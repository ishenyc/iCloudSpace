package mailview

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/blobstore"
	"icloudspace/internal/content"
)

type BodyError struct{ State string }

func (e *BodyError) Error() string   { return "mailview: original body unavailable" }
func (e *BodyError) Unwrap() error   { return ErrUnavailable }
func unavailable(state string) error { return &BodyError{State: state} }

type memoryBody struct{ *bytes.Reader }

func (*memoryBody) Close() error { return nil }

// Readers remain bound to their originating live lease after the opening
// method returns. The caller still owns scope lifetime through response IO;
// a closed or foreign lease cannot be reused to keep reading an escaped fd.
type guardedBody struct {
	inner BodyReader
	s     *Service
	lease *addressauth.Lease
}

func (g *guardedBody) Read(p []byte) (int, error) {
	if !g.lease.ValidFor(g.s.authority) {
		return 0, ErrDenied
	}
	return g.inner.Read(p)
}
func (g *guardedBody) ReadAt(p []byte, off int64) (int, error) {
	if !g.lease.ValidFor(g.s.authority) {
		return 0, ErrDenied
	}
	return g.inner.ReadAt(p, off)
}
func (g *guardedBody) Seek(off int64, whence int) (int64, error) {
	if !g.lease.ValidFor(g.s.authority) {
		return 0, ErrDenied
	}
	return g.inner.Seek(off, whence)
}
func (g *guardedBody) Close() error { return g.inner.Close() }
func (s *Service) protect(lease *addressauth.Lease, r *Raw) *Raw {
	r.Reader = &guardedBody{inner: r.Reader, s: s, lease: lease}
	return r
}

type guardedDownload struct {
	inner io.ReadCloser
	s     *Service
	lease *addressauth.Lease
}

func (g *guardedDownload) Read(p []byte) (int, error) {
	if !g.lease.ValidFor(g.s.authority) {
		return 0, ErrDenied
	}
	return g.inner.Read(p)
}
func (g *guardedDownload) Close() error { return g.inner.Close() }

func (s *Service) entry(ctx context.Context, id addressauth.Identity, uid uint32) (Metadata, error) {
	if uid == 0 {
		return Metadata{}, ErrInvalid
	}
	m, e := s.scanMessage(s.db.QueryRowContext(ctx, `SELECT `+metadataColumns+entryFrom+`WHERE e.source_id=$1 AND e.address_id=$2 AND e.local_uid=$5 AND m.source_generation=$6`, id.SourceID, id.AddressID, s.options.Limits.BodyBytes, descriptorBudget, uid, id.SourceGeneration), false)
	return m.Metadata, e
}
func (s *Service) openObject(ctx context.Context, id addressauth.Identity, message int64, uid uint32, ref *SnapshotRef) (*Raw, error) {
	var object, storageRef, owner, receipt, staging, state sql.NullString
	var version, size, generation sql.NullInt64
	var digest []byte
	query := `SELECT o.object_key,o.manifest_version,o.byte_size,o.sha256,o.storage_ref,o.state,o.publication_generation,p.owner_key,p.receipt_key,p.staging_ref FROM space.source_messages m JOIN space.mail_sources current_source ON current_source.id=m.source_id AND current_source.source_generation=m.source_generation LEFT JOIN space.content_objects o ON o.source_id=m.source_id AND o.object_key=m.object_key LEFT JOIN space.content_publications p ON p.source_id=o.source_id AND p.object_key=o.object_key AND p.publication_generation=o.publication_generation AND p.state IN ('published','sql_unknown','committed') WHERE m.source_id=$1 AND m.id=$2 AND `
	args := []any{id.SourceID, message, id.AddressID}
	if ref == nil {
		query += `EXISTS(SELECT 1 FROM space.mailbox_entries e WHERE e.source_id=m.source_id AND e.address_id=$3 AND e.message_id=m.id AND e.local_uid=$4)`
		args = append(args, uid)
	} else {
		query += `EXISTS(SELECT 1 FROM space.address_snapshots a WHERE a.source_id=m.source_id AND a.address_id=$3 AND a.message_id=m.id AND a.selected_at=$4 AND coalesce(a.view_key,'')=$5 AND a.view_scope_address_id=$6)`
		args = append(args, ref.SelectedAt, ref.ViewKey, ref.ViewScopeAddressID)
	}
	args = append(args, id.SourceGeneration)
	query += ` AND m.source_generation=$` + strconv.Itoa(len(args))
	e := s.db.QueryRowContext(ctx, query, args...).Scan(&object, &version, &size, &digest, &storageRef, &state, &generation, &owner, &receipt, &staging)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, storage(ctx)
	}
	if !object.Valid {
		return nil, unavailable("metadata_only")
	}
	if state.String != "available" {
		return nil, unavailable(state.String)
	}
	if !owner.Valid || !receipt.Valid || !staging.Valid || !version.Valid || !size.Valid || !generation.Valid || len(digest) != 32 {
		return nil, unavailable("corrupt")
	}
	if size.Int64 > s.options.Limits.MessageBytes {
		return nil, unavailable("over_budget")
	}
	r := blobstore.Receipt{Version: int(version.Int64), Identity: blobstore.Identity{ObjectKey: object.String, Generation: generation.Int64, OwnerKey: owner.String}, ReceiptKey: receipt.String, StagingRef: staging.String, StorageRef: storageRef.String, ByteSize: size.Int64, SHA256: hex.EncodeToString(digest)}
	file, e := s.blobs.OpenVerified(ctx, r)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(e, blobstore.ErrClosed) {
			return nil, ErrStorage
		}
		return nil, unavailable("corrupt")
	}
	return &Raw{Reader: file, ByteSize: r.ByteSize, Original: true, State: "available"}, nil
}

// OpenRaw never substitutes a reconstruction for an original. The returned
// reader is the same fd that passed blobstore size/SHA/ordinary-file checks.
// The caller closes it and continues to hold its Authority lease through IO.
func (s *Service) OpenRaw(ctx context.Context, lease *addressauth.Lease, uid uint32) (*Raw, error) {
	id, e := s.allow(lease, addressauth.RawRead)
	if e != nil {
		return nil, e
	}
	m, e := s.entry(ctx, id, uid)
	if e != nil {
		return nil, e
	}
	if e = s.observe(ctx, id); e != nil {
		return nil, e
	}
	raw, e := s.openObject(ctx, id, m.MessageID, uid, nil)
	if e != nil {
		return nil, e
	}
	return s.protect(lease, raw), nil
}
func (s *Service) OpenSnapshotRaw(ctx context.Context, lease *addressauth.Lease, ref SnapshotRef) (*Raw, error) {
	id, e := s.allow(lease, addressauth.RawRead)
	if e != nil {
		return nil, e
	}
	if ref.MessageID < 1 || ref.LocalUIDValidity != id.UIDValidity {
		return nil, ErrInvalid
	}
	if e = s.observe(ctx, id); e != nil {
		return nil, e
	}
	raw, e := s.openObject(ctx, id, ref.MessageID, 0, &ref)
	if e != nil {
		return nil, e
	}
	return s.protect(lease, raw), nil
}
func (s *Service) RawCandidates(ctx context.Context, lease *addressauth.Lease, page Page) (MessagePage, error) {
	id, e := s.allow(lease, addressauth.RawRead)
	if e != nil {
		return MessagePage{}, e
	}
	if e = s.observe(ctx, id); e != nil {
		return MessagePage{}, e
	}
	return s.list(ctx, id, page)
}

// LatestRaw skips missing, evicted and corrupt originals, retaining bounded
// metadata pages and one verified fd. It does not omit any IMAP entry/UID.
func (s *Service) LatestRaw(ctx context.Context, lease *addressauth.Lease) (Metadata, *Raw, error) {
	id, e := s.allow(lease, addressauth.RawRead)
	if e != nil {
		return Metadata{}, nil, e
	}
	if e = s.observe(ctx, id); e != nil {
		return Metadata{}, nil, e
	}
	page := Page{Limit: 32}
	for {
		if ctx.Err() != nil {
			return Metadata{}, nil, ctx.Err()
		}
		result, e := s.list(ctx, id, page)
		if e != nil {
			return Metadata{}, nil, e
		}
		for _, m := range result.Items {
			if _, e = s.allow(lease, addressauth.RawRead); e != nil {
				return Metadata{}, nil, e
			}
			raw, e := s.openObject(ctx, id, m.MessageID, m.UID, nil)
			if e == nil {
				return m, s.protect(lease, raw), nil
			}
			if !errors.Is(e, ErrUnavailable) && !errors.Is(e, ErrNotFound) {
				return Metadata{}, nil, e
			}
		}
		if !result.More {
			return Metadata{}, nil, ErrNotFound
		}
		page.BeforeTime = result.NextTime
		page.BeforeID = result.NextID
	}
}

// IMAPRaw preserves the entry and emits explicit standards-shaped placeholder
// MIME for unavailable originals. SIZE is always ByteSize of this exact reader.
func (s *Service) IMAPRaw(ctx context.Context, lease *addressauth.Lease, uid uint32) (*Raw, error) {
	id, e := s.allow(lease, addressauth.IMAPLogin)
	if e != nil {
		return nil, e
	}
	m, e := s.entry(ctx, id, uid)
	if e != nil {
		return nil, e
	}
	raw, e := s.openObject(ctx, id, m.MessageID, uid, nil)
	if e == nil {
		return s.protect(lease, raw), nil
	}
	var unavailableBody *BodyError
	if !errors.As(e, &unavailableBody) {
		return nil, e
	}
	state := unavailableBody.State
	if state == "metadata_only" && m.ContentState == "over_budget" {
		state = "over_budget"
	}
	body := placeholder(id, m, state)
	return s.protect(lease, &Raw{Reader: &memoryBody{bytes.NewReader(body)}, ByteSize: int64(len(body)), Original: false, State: state}), nil
}
func headerText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 127 {
			return ' '
		}
		return r
	}, s)
}
func boundedHeader(s string, limit int) string {
	s = headerText(s)
	if len(s) > limit {
		return strings.ToValidUTF8(s[:limit-3], "") + "..."
	}
	return s
}
func placeholder(id addressauth.Identity, m Metadata, state string) []byte {
	switch state {
	case "metadata_only", "evicted", "missing", "corrupt", "staged", "over_budget":
	default:
		state = "corrupt"
	}
	from := "archive-unavailable@invalid"
	if len(m.From) > 0 && len(m.From[0].Address) <= 320 {
		if parsed, e := mail.ParseAddress(m.From[0].Address); e == nil {
			parsed.Name = boundedHeader(m.From[0].Name, 128)
			from = parsed.String()
		}
	}
	to := "undisclosed-recipients:;"
	if parsed, e := mail.ParseAddress(id.Email); e == nil && len(id.Email) <= 320 {
		to = parsed.String()
	}
	date := m.ReceivedAt
	if m.SentAt != nil {
		date = *m.SentAt
	}
	var out strings.Builder
	fmt.Fprintf(&out, "From: %s\r\nTo: %s\r\nDate: %s\r\nSubject: %s\r\nMessage-ID: <unavailable-%d-%d@invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\nX-Space-Original-Available: no\r\nX-Space-Body-State: %s\r\n\r\nThe original message body is unavailable (%s).\r\nThis is an explanatory placeholder; message identity and metadata are retained.\r\n", from, to, time.Unix(0, date).UTC().Format(time.RFC1123Z), mime.QEncoding.Encode("utf-8", boundedHeader(m.Subject, 512)), id.AddressID, m.MessageID, state, state)
	return []byte(out.String())
}
func validPart(part string) bool {
	if part == "root" {
		return true
	}
	if len(part) < 1 || len(part) > 128 {
		return false
	}
	for _, segment := range strings.Split(part, ".") {
		if segment == "" || segment[0] == '0' {
			return false
		}
		for _, c := range segment {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
func (s *Service) Attachment(ctx context.Context, lease *addressauth.Lease, uid uint32, part string) (*Download, error) {
	if !validPart(part) {
		return nil, ErrInvalid
	}
	raw, e := s.OpenRaw(ctx, lease, uid)
	if e != nil {
		return nil, e
	}
	defer raw.Close()
	parsed, e := content.Parse(raw.Reader, s.options.Limits)
	if parsed == nil {
		return nil, ErrUnavailable
	}
	for _, a := range parsed.Attachments {
		if a.Part == part || (part == "root" && a.Part == "") {
			if !a.Complete {
				return nil, ErrBudget
			}
			return &Download{Reader: &guardedDownload{inner: io.NopCloser(bytes.NewReader(a.Bytes)), s: s, lease: lease}, Filename: a.Filename, MediaType: a.MediaType, ContentID: a.ContentID, ByteSize: a.Size}, nil
		}
	}
	if e != nil {
		return nil, ErrBudget
	}
	return nil, ErrNotFound
}
func (s *Service) RenderRaw(ctx context.Context, lease *addressauth.Lease, uid uint32) (string, error) {
	raw, e := s.OpenRaw(ctx, lease, uid)
	if e != nil {
		return "", e
	}
	defer raw.Close()
	limits := s.options.Limits
	limits.AttachmentBytes = 1
	parsed, e := content.Parse(raw.Reader, limits)
	if parsed == nil {
		return "", ErrUnavailable
	}
	html, e := content.RenderReceived(parsed, 2*limits.BodyBytes+4096)
	if e != nil {
		return "", ErrBudget
	}
	if !parsed.BodyComplete {
		html = `<p role="status">The displayed body is incomplete. The verified original remains available.</p>` + html
	}
	return html, nil
}
