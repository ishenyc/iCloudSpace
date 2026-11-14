package intake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	messageMail "github.com/emersion/go-message/mail"
	"icloudspace/internal/blobstore"
	"icloudspace/internal/content"
	upstream "icloudspace/internal/provider/imap"
	"icloudspace/internal/sourceguard"
)

type Pipeline struct {
	Registry   *sourceguard.Registry
	Repository *Repository
	Files      *blobstore.Store
	Acquire    Acquire
	Now        func() time.Time
	budgets    atomic.Pointer[content.Limits]
}

const (
	DefaultIncomingMessageBytes int64 = 100 << 20
	DefaultBodyBytes            int64 = 512 << 10
)

// ConfigureLimits supplies use-case budgets, independently of historical raw
// reads. A Run captures one immutable pair, including if configuration changes
// while that run is streaming. The composition root normally calls this once.
func (p *Pipeline) ConfigureLimits(incomingMessageBytes, bodyBytes int64) error {
	if p == nil || incomingMessageBytes <= 0 || bodyBytes <= 0 {
		return ErrInvalid
	}
	budget := limits()
	budget.MessageBytes, budget.BodyBytes = incomingMessageBytes, bodyBytes
	p.budgets.Store(&budget)
	return nil
}

func (p *Pipeline) parseLimits() content.Limits {
	if p != nil {
		if budget := p.budgets.Load(); budget != nil {
			return *budget
		}
	}
	return limits()
}

func New(registry *sourceguard.Registry, repository *Repository, files *blobstore.Store, pool *upstream.Pool) *Pipeline {
	return &Pipeline{Registry: registry, Repository: repository, Files: files, Now: time.Now,
		Acquire: func(ctx context.Context, e upstream.Endpoint, s upstream.Scope, m string) (ReadLease, error) {
			return pool.Acquire(ctx, e, s, m)
		}}
}

func limits() content.Limits {
	return content.Limits{MessageBytes: DefaultIncomingMessageBytes, HeaderBytes: upstream.MaxHeaderBytes, BodyBytes: DefaultBodyBytes,
		AttachmentBytes: 10 << 20, Parts: 128, Depth: 16, Addresses: 256, Attachments: 32}
}

func (p *Pipeline) Run(ctx context.Context, input InputSnapshot) (result Result, err error) {
	s := input.Snapshot
	if p == nil || p.Registry == nil || p.Repository == nil || p.Files == nil || p.Acquire == nil || !input.Gate.ValidFor(p.Registry, s.Source.ID) || !s.Source.Enabled || s.Mailbox == "" || len(s.Pending) > MaxSegment {
		return result, ErrInvalid
	}
	if input.Endpoint.Host != s.Source.Host || input.Endpoint.Port != s.Source.Port || input.Endpoint.Username != s.Source.Username {
		return result, ErrInvalid
	}
	budget := p.parseLimits()
	headerBudget := budget
	// IncomingMessageBytes decides whether to fetch a whole original. The
	// independent bounded Headers path must still establish complete ownership
	// even when the incoming budget is smaller than a valid message's header.
	headerBudget.MessageBytes = max(budget.MessageBytes, budget.HeaderBytes)
	if err = p.Repository.CheckPending(ctx, input.Gate, s.Source.ID); err != nil {
		var pending *PendingError
		if errors.As(err, &pending) {
			result.BatchKey = pending.BatchKey
		}
		return result, err
	}
	l, err := p.Acquire(ctx, input.Endpoint, upstream.Scope{SourceID: s.Source.ID, SourceGeneration: s.Source.Generation, CredentialGeneration: s.Source.CredentialGeneration}, s.Mailbox)
	if err != nil {
		return result, err
	}
	defer l.Release()
	streamRaw := l.StreamRawBatch
	if bounded, ok := l.(interface {
		StreamRawBatchWithLimit(context.Context, uint32, []uint32, int64, func(uint32, io.Reader) error) error
	}); ok {
		streamRaw = func(ctx context.Context, uidv uint32, uids []uint32, consume func(uint32, io.Reader) error) error {
			return bounded.StreamRawBatchWithLimit(ctx, uidv, uids, budget.MessageBytes, consume)
		}
	} else if budget.MessageBytes > upstream.MaxMessageBytes {
		// A legacy/fake read port cannot promise a larger literal budget.
		// Reject before preparing a batch or creating any archive identity.
		return result, ErrInvalid
	}
	selected := l.Snapshot()
	if selected.UIDValidity == 0 || selected.UIDNext == 0 {
		return result, ErrInvalid
	}
	upper := selected.UIDNext - 1
	if input.CapturedUpper != 0 {
		if input.CapturedUpper > upper {
			return result, ErrStale
		}
		upper = input.CapturedUpper
	}
	if s.Backfill == nil && s.Cursor.Exists && s.Cursor.UIDValidity == selected.UIDValidity && s.Cursor.Observed > s.Cursor.Committed {
		if s.Cursor.Observed > selected.UIDNext-1 || input.CapturedUpper != 0 && input.CapturedUpper != s.Cursor.Observed {
			return result, ErrStale
		}
		upper = s.Cursor.Observed
	}
	after := s.Cursor.Committed
	if !s.Cursor.Exists || s.Cursor.UIDValidity != selected.UIDValidity {
		after = 0
		if upper > RecentWindow {
			after = upper - RecentWindow
		}
	}
	if s.Backfill != nil {
		b := s.Backfill
		if b.UIDValidity != selected.UIDValidity || b.Upper > upper || (b.State != "pending" && b.State != "scanning") {
			return result, ErrStale
		}
		after, upper = b.Committed, b.Upper
	}
	if after > upper {
		return result, ErrStale
	}
	page, err := l.Discover(ctx, upstream.Discovery{UIDValidity: selected.UIDValidity, After: after, Through: upper, Limit: upstream.MaxCandidates})
	if err != nil {
		return result, err
	}
	uids := page.UIDs[:min(len(page.UIDs), MaxSegment)]
	var metadata []upstream.Metadata
	if len(uids) > 0 {
		metadata, err = l.Metadata(ctx, selected.UIDValidity, uids)
		if err != nil {
			return result, err
		}
	}
	byUID := make(map[uint32]upstream.Metadata, len(metadata))
	for _, m := range metadata {
		byUID[m.UID] = m
	}
	// A single large message may exceed the normal segment target. Oversized
	// metadata-only messages do not consume a raw-byte allowance.
	var rawBytes int64
	take := len(uids)
	for i, uid := range uids {
		m, ok := byUID[uid]
		if !ok || m.Size > budget.MessageBytes {
			continue
		}
		if rawBytes > 0 && m.Size > TargetBytes-rawBytes {
			take = i
			break
		}
		rawBytes += m.Size
	}
	uids = uids[:take]
	for _, uid := range uids {
		if m, ok := byUID[uid]; ok {
			if _, e := requiredInstant(m.InternalDate); e != nil {
				return result, e
			}
		}
	}
	through := page.ScannedThrough
	if len(uids) < len(page.UIDs) {
		through = page.UIDs[len(uids)] - 1
	}
	key, err := token()
	if err != nil {
		return result, err
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	pl := plan{BatchKey: key, Snapshot: s, UIDValidity: selected.UIDValidity, Upper: upper, After: after, Through: through, UIDs: uids, CreatedAt: now().UnixNano()}
	result.BatchKey = key
	result.Through = through
	result.CapturedUpper = upper
	result.Complete = through == upper
	pl.Invalidations, err = refreshPending(ctx, l, s, selected.UIDValidity)
	if err != nil {
		return result, err
	}
	if s.Backfill == nil && s.Cursor.Exists && s.Cursor.UIDValidity == selected.UIDValidity && through == s.Cursor.Committed && len(uids) == 0 && len(pl.Invalidations) == 0 {
		result.BatchKey = ""
		if len(s.Pending) > 0 {
			result.PendingAfter = s.Pending[len(s.Pending)-1].AddressID
		}
		return result, nil
	}
	existing, err := p.Repository.loadExisting(ctx, s, selected.UIDValidity, uids)
	if err != nil {
		return result, err
	}
	var existingKeys []string
	for _, uid := range uids {
		d := existing[uid]
		if d.ObjectKey != "" && d.ObjectState != "available" {
			existingKeys = append(existingKeys, d.ObjectKey)
		}
	}
	generation, err := p.Repository.nextGenerations(ctx, s.Source.ID, existingKeys)
	if err != nil {
		return result, err
	}
	for _, uid := range uids {
		m, ok := byUID[uid]
		if !ok || m.Size > budget.MessageBytes {
			continue
		}
		d := existing[uid]
		if d.ExistingID != 0 && (d.ObjectState == "available" || d.ObjectKey == "" && d.State == "over_budget") {
			continue
		}
		object := d.ObjectKey
		if object == "" {
			object, err = token()
			if err != nil {
				return result, err
			}
		}
		next := int64(1)
		if d.ObjectKey != "" {
			next = generation[object]
			if next <= d.ObjectGeneration {
				return result, ErrStale
			}
		}
		pl.Claims = append(pl.Claims, claim{UID: uid, Identity: blobstore.Identity{ObjectKey: object, OwnerKey: key, Generation: next}, PreviousGeneration: d.ObjectGeneration})
	}
	if err = p.Repository.PrepareBatch(ctx, input.Gate, pl); err != nil {
		return result, err
	}
	checkpointStarted := false
	defer func() {
		if err != nil && !checkpointStarted {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			_ = p.Repository.AbandonBatch(cleanup, input.Gate, key)
		}
	}()
	directoryAliases := make([]content.Alias, 0, len(s.Aliases))
	for _, a := range s.Aliases {
		directoryAliases = append(directoryAliases, content.Alias{ID: strconv.FormatInt(a.ID, 10), Address: a.Email, Enabled: a.Enabled && !a.Deleted && a.Lifecycle == "confirmed"})
	}
	directory := content.NewDirectory(directoryAliases)
	claims := make(map[uint32]claim)
	for _, c := range pl.Claims {
		claims[c.UID] = c
	}
	var headerUIDs []uint32
	for _, uid := range uids {
		if m, ok := byUID[uid]; ok && (m.Size > budget.MessageBytes && existing[uid].ExistingID == 0 || existing[uid].ExistingID != 0 && !existing[uid].HeaderComplete && claims[uid].UID == 0) {
			headerUIDs = append(headerUIDs, uid)
		}
	}
	headers := make(map[uint32]upstream.Header)
	if len(headerUIDs) > 0 {
		hs, e := l.Headers(ctx, selected.UIDValidity, headerUIDs)
		if e != nil {
			return result, e
		}
		for _, h := range hs {
			headers[h.UID] = h
		}
	}
	cp := checkpoint{Plan: pl}
	rawDrafts := make(map[uint32]draft, len(pl.Claims))
	var rawUIDs []uint32
	for _, c := range pl.Claims {
		rawUIDs = append(rawUIDs, c.UID)
	}
	if len(rawUIDs) > 0 {
		err = streamRaw(ctx, selected.UIDValidity, rawUIDs, func(uid uint32, raw io.Reader) error {
			c, ok := claims[uid]
			if !ok {
				return ErrInvalid
			}
			meta := byUID[uid]
			r, parsed, parseErr, e := stageParseWithLimits(ctx, p.Files, c.Identity, raw, budget)
			if e != nil {
				return e
			}
			if r.ByteSize != meta.Size {
				return ErrSourceChanged
			}
			old := existing[uid]
			d, e := interpret(uid, meta, parsed, parseErr)
			if e != nil {
				return e
			}
			d.ExistingID = old.ExistingID
			d.ObjectGeneration = old.ObjectGeneration
			d.ObjectState = old.ObjectState
			d.ExpectedSize = old.ExpectedSize
			d.ExpectedSHA = old.ExpectedSHA
			d.ObjectKey = r.Identity.ObjectKey
			d.Receipt = &r
			if ban, ok := content.DetectRegistrationBan(parsed, sourceRoute(s), directory, 4<<20); ok {
				if id, e := strconv.ParseInt(ban.AddressID, 10, 64); e == nil && id > 0 {
					d.Ban = &banFact{AddressID: id, Detail: ban.Summary, DetectedAt: now().UnixNano()}
				}
			}
			rawDrafts[uid] = d
			return nil
		})
		if err != nil {
			var missing *upstream.MissingError
			if !errors.As(err, &missing) {
				return result, err
			}
			err = nil
		}
	}
	for _, uid := range uids {
		meta, ok := byUID[uid]
		if !ok {
			continue
		}
		d := existing[uid]
		if d.ExistingID != 0 && claims[uid].UID == 0 {
			d.Seen = seen(meta.Flags)
			if h, ok := headers[uid]; ok {
				m, e := content.Parse(bytes.NewReader(h.RawHeader), headerBudget)
				d.Header = h.RawHeader
				d.HeaderComplete = h.Complete && !h.Truncated && headerComplete(m)
				if m != nil {
					d.Evidence = &m.Recipients
					hd, rangeErr := interpret(uid, meta, m, e)
					if rangeErr != nil {
						return result, rangeErr
					}
					d.Recipients = hd.Recipients
					d.To = hd.To
					d.CC = hd.CC
				}
			}
			attribute(&d, directory, s)
			cp.Messages = append(cp.Messages, d)
			continue
		}
		var parsed *content.Message
		var parseErr error
		if meta.Size > budget.MessageBytes {
			h, exists := headers[uid]
			if !exists {
				continue
			}
			parsed, parseErr = content.Parse(bytes.NewReader(h.RawHeader), headerBudget)
			if parsed == nil {
				parsed = &content.Message{RawHeader: h.RawHeader}
			}
			parsed.Complete = false
			parsed.BodyComplete = false
			d, err = interpret(uid, meta, parsed, parseErr)
			if err != nil {
				return result, err
			}
			d.State = "over_budget"
			d.HeaderComplete = h.Complete && !h.Truncated && headerComplete(parsed)
		} else {
			var exists bool
			d, exists = rawDrafts[uid]
			if !exists {
				continue
			}
		}
		attribute(&d, directory, s)
		if d.Ban != nil {
			linked := false
			for _, id := range d.Links {
				linked = linked || id == d.Ban.AddressID
			}
			if !linked {
				d.Ban = nil
			}
		}
		d.Evidence = nil
		delete(rawDrafts, uid)
		cp.Messages = append(cp.Messages, d)
	}
	if err = l.ValidateSelection(ctx, selected.UIDValidity); err != nil {
		return result, err
	}
	for i := range cp.Messages {
		d := &cp.Messages[i]
		if d.Receipt != nil {
			if err = p.Files.Publish(ctx, *d.Receipt); err != nil {
				return result, err
			}
			d.PublishedAt = now().UnixNano()
		}
	}
	checkpointStarted = true
	result, err = p.Repository.CommitBatch(ctx, input.Gate, cp)
	result.BatchKey = key
	result.Through = through
	result.CapturedUpper = upper
	result.Complete = through == upper
	if len(s.Pending) > 0 {
		result.PendingAfter = s.Pending[len(s.Pending)-1].AddressID
	}
	return result, err
}

func seen(flags []string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, `\Seen`) {
			return true
		}
	}
	return false
}

func refreshPending(ctx context.Context, l ReadLease, s Snapshot, uidv uint32) ([]Pending, error) {
	var invalid []Pending
	unique := make(map[uint32]bool)
	var ids []uint32
	for _, v := range s.Pending {
		if v.Generation != s.Source.Generation || v.UIDValidity != uidv {
			invalid = append(invalid, v)
			continue
		}
		if !unique[v.UID] {
			unique[v.UID] = true
			ids = append(ids, v.UID)
		}
	}
	if len(ids) == 0 {
		return invalid, nil
	}
	rows, err := l.Metadata(ctx, uidv, ids)
	if err != nil {
		return nil, err
	}
	live := make(map[uint32]bool)
	for _, m := range rows {
		live[m.UID] = !seen(m.Flags)
	}
	for _, v := range s.Pending {
		if v.Generation == s.Source.Generation && v.UIDValidity == uidv && !live[v.UID] {
			invalid = append(invalid, v)
		}
	}
	return invalid, nil
}

type parsedResult struct {
	message *content.Message
	err     error
}

// The parser is joined even on a failed stage. Once Parse stops, its goroutine
// drains the pipe so an interpretation budget cannot truncate archived MIME.
func stageParse(ctx context.Context, files *blobstore.Store, id blobstore.Identity, raw io.Reader) (blobstore.Receipt, *content.Message, error, error) {
	return stageParseWithLimits(ctx, files, id, raw, limits())
}

func stageParseWithLimits(ctx context.Context, files *blobstore.Store, id blobstore.Identity, raw io.Reader, budget content.Limits) (blobstore.Receipt, *content.Message, error, error) {
	reader, writer := io.Pipe()
	done := make(chan parsedResult, 1)
	go func() {
		m, e := content.Parse(reader, budget)
		_, _ = io.Copy(io.Discard, reader)
		_ = reader.Close()
		done <- parsedResult{m, e}
	}()
	tee := io.TeeReader(raw, writer)
	r, stageErr := files.Stage(ctx, id, tee)
	if stageErr == nil && r.Reused {
		// Reused means Stage did not consume this literal. Verify the current
		// upstream bytes; only its subsequent tagged OK confirms this attempt.
		h := sha256.New()
		var n int64
		n, stageErr = io.Copy(h, tee)
		if stageErr == nil && (n != r.ByteSize || hex.EncodeToString(h.Sum(nil)) != r.SHA256) {
			stageErr = ErrSourceChanged
		}
	}
	_ = writer.CloseWithError(stageErr)
	parsed := <-done
	return r, parsed.message, parsed.err, stageErr
}

func headerComplete(m *content.Message) bool {
	return m != nil && m.HeaderComplete
}

func interpret(uid uint32, meta upstream.Metadata, m *content.Message, parseErr error) (draft, error) {
	received, err := requiredInstant(meta.InternalDate)
	if err != nil {
		return draft{}, err
	}
	d := draft{UID: uid, Size: meta.Size, ReceivedAt: received, Seen: seen(meta.Flags), State: "malformed"}
	if m == nil {
		return d, nil
	}
	d.Header = m.RawHeader
	d.Evidence = &m.Recipients
	d.HeaderComplete = headerComplete(m)
	d.MessageID = m.MessageID
	d.MessageID = pgText(d.MessageID)
	d.Subject = pgText(m.Subject)
	for _, a := range m.From {
		d.From = append(d.From, mailbox{Name: pgText(a.Name), Address: pgText(a.Address)})
	}
	d.SentAt = instant(m.Date)
	if d.SentAt == nil {
		if !m.Date.IsZero() {
			d.TimestampIssue = "header_date_unavailable"
		}
		for _, h := range m.Headers {
			if strings.EqualFold(h.Name, "Date") {
				d.TimestampIssue = "header_date_unavailable"
				break
			}
		}
	}
	d.Text = pgText(m.Text)
	d.BodyComplete = m.BodyComplete && parseErr == nil
	d.HTML, _ = content.RenderReceived(m, 4<<20)
	d.HTML = pgText(d.HTML)
	if parseErr == nil {
		d.State = "complete"
	}
	var budget *content.BudgetError
	if errors.As(parseErr, &budget) || m.Truncated {
		d.State = "metadata_only"
	}
	for i := range m.Attachments {
		a := &m.Attachments[i]
		d.Attachments = append(d.Attachments, attachment{Part: a.Part, Filename: pgText(a.Filename), MediaType: pgText(a.MediaType), ContentID: pgText(a.ContentID), Disposition: pgText(a.Disposition), Inline: a.Inline, Size: a.Size, Complete: a.Complete})
		a.Bytes = nil
	}
	ordinal := make(map[string]int)
	addressesLeft := limits().Addresses
	limited := false
	for _, h := range m.Headers {
		role := ""
		switch strings.ToLower(h.Name) {
		case "to":
			role = "to"
		case "cc":
			role = "cc"
		case "bcc":
			role = "bcc"
		}
		if role == "" {
			continue
		}
		addresses, e := messageMail.ParseAddressList(h.Value)
		if e != nil {
			continue
		}
		if len(addresses) > addressesLeft {
			addresses = addresses[:addressesLeft]
			limited = true
		}
		for _, a := range addresses {
			addressesLeft--
			d.Recipients = append(d.Recipients, recipient{Role: role, Ordinal: ordinal[role], Email: pgText(strings.ToLower(a.Address)), Name: pgText(a.Name), Evidence: "display"})
			ordinal[role]++
			if role == "to" {
				d.To = append(d.To, mailbox{Name: pgText(a.Name), Address: pgText(a.Address)})
			}
			if role == "cc" {
				d.CC = append(d.CC, mailbox{Name: pgText(a.Name), Address: pgText(a.Address)})
			}
		}
	}
	for _, h := range m.Recipients.Strong {
		role := "envelope_to"
		if h.Tier == 3 {
			role = "delivered_to"
		}
		for _, a := range h.Addresses {
			if addressesLeft == 0 {
				limited = true
				break
			}
			addressesLeft--
			d.Recipients = append(d.Recipients, recipient{Role: role, Ordinal: ordinal[role], Email: pgText(a), Evidence: "strong"})
			ordinal[role]++
		}
	}
	if limited {
		d.State = "metadata_only"
	}
	if d.BodyComplete {
		candidates, e := content.FindCodes(m.Subject, m.Text, m.HTML, 64, 4<<20)
		if e == nil {
			seenCodes := make(map[string]bool)
			for _, c := range candidates {
				if !seenCodes[c.Code] {
					d.Codes = append(d.Codes, c.Code)
					seenCodes[c.Code] = true
				}
			}
			if c, ok := content.SelectCode(candidates, 6); ok {
				d.Code = &c.Code
			}
		}
	}
	return d, nil
}

// PostgreSQL text/jsonb cannot represent U+0000. This changes only the parsed
// projection; the staged MIME and binary raw_header retain the original octets.
func pgText(s string) string { return strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", "") }

func attribute(d *draft, directory *content.Directory, s Snapshot) {
	d.Links = nil
	if !d.HeaderComplete {
		return
	}
	// Header-only interpretation does not retain or copy a raw body.
	evidence := d.Evidence
	if evidence == nil {
		// A header-only multipart replay has no body boundary. Its body parse
		// error does not invalidate independently complete recipient headers.
		m, _ := content.Parse(bytes.NewReader(d.Header), limits())
		if m == nil || !headerComplete(m) {
			return
		}
		evidence = &m.Recipients
	}
	a := directory.Attribute(*evidence, sourceRoute(s), s.Source.AllowWeak)
	if !a.Determinate {
		return
	}
	for _, match := range a.Matches {
		id, e := strconv.ParseInt(match.ID, 10, 64)
		if e == nil && (s.Backfill == nil || s.Backfill.AddressID == id) {
			d.Links = append(d.Links, id)
		}
	}
}

func sourceRoute(s Snapshot) content.SourceRoute {
	kind := content.SourceCustom
	switch s.Source.Kind {
	case "apple_direct":
		kind = content.SourceDirect
	case "apple_forwarded":
		kind = content.SourceForwarded
	}
	return content.SourceRoute{Kind: kind, PrimaryAddress: s.Source.Namespace, IMAPUsername: s.Source.Username}
}
