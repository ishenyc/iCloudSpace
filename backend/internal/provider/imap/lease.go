package imap

import (
	"context"
	"errors"
	"io"
	"sort"
	"sync"

	protocol "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

type Lease struct {
	mu       sync.Mutex
	pool     *Pool
	s        *session
	ctx      context.Context
	stop     func()
	mailbox  string
	snapshot Snapshot
	released bool
}

func (l *Lease) Snapshot() Snapshot { return l.snapshot }
func (l *Lease) Discard() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.released {
		l.s.discard()
	}
}

// Release is idempotent and joins the lease watcher before exposing the session
// to another Acquire. In-flight methods finish before it can retain the session.
func (l *Lease) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	l.stop()
	if l.ctx.Err() != nil {
		l.s.discard()
	}
	l.pool.retain(l.s)
}

// run is called only while this lease is exclusively owned. A command watcher
// is always joined before another operation or Release can run.
func (l *Lease) run(ctx context.Context, stage string, fn func() error) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := l.ctx.Err(); err != nil {
		l.s.discard()
		return diagnostic(stage, err)
	}
	if err := ctx.Err(); err != nil {
		l.s.discard()
		return diagnostic(stage, err)
	}
	if l.released || l.s.bad.Load() {
		return ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, l.pool.cfg.CommandTimeout)
	join := watch(bounded, l.s)
	completed := false
	defer func() {
		// A caller callback may panic. Its abandoned command must never leave
		// a live watcher behind or return its session to the idle pool.
		if !completed {
			l.s.discard()
			join()
			cancel()
		}
	}()
	err := fn()
	join()
	if l.s.bad.Load() {
		// An unsolicited literal has its own controlled reader. It must finish
		// releasing the decoder before this failed command returns to its owner.
		_ = l.s.client.Close()
	}
	if bounded.Err() != nil {
		err = bounded.Err()
	} else if l.ctx.Err() != nil {
		err = l.ctx.Err()
	} else if fault := l.s.fault.Load(); fault != nil {
		err = fault.err
	}
	cancel()
	completed = true
	if err == nil && stage != "greeting" && stage != "login" && stage != "noop" && stage != "examine" {
		if l.s.client.State() != protocol.ConnStateSelected {
			err = ErrIncomplete
		}
	}
	if err != nil {
		var missing *MissingError
		if !errors.As(err, &missing) {
			l.s.discard()
		}
		return diagnostic(stage, err)
	}
	return nil
}

func (l *Lease) sameGeneration(uidValidity uint32) error {
	if uidValidity == 0 || uidValidity != l.snapshot.UIDValidity {
		return ErrGenerationChanged
	}
	selected := l.s.client.Mailbox()
	if l.s.client.State() != protocol.ConnStateSelected || selected == nil || selected.Name != l.mailbox {
		return ErrIncomplete
	}
	return nil
}

// ValidateSelection performs one explicit generation fence for a whole batch.
// The caller can use it before committing a checkpoint. RFC 9051 keeps UIDs
// stable during a selection; individual reads do not each issue extra STATUS.
// beta8 does not expose unsolicited UIDVALIDITY outside a SELECT response.
func (l *Lease) ValidateSelection(ctx context.Context, uidValidity uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.run(ctx, "validate", func() error {
		if err := l.sameGeneration(uidValidity); err != nil {
			return err
		}
		data, err := l.s.client.Status(l.mailbox, &protocol.StatusOptions{UIDValidity: true}).Wait()
		if err != nil {
			return err
		}
		if data.UIDValidity != uidValidity {
			return ErrGenerationChanged
		}
		return nil
	})
}

func (l *Lease) Discover(ctx context.Context, request Discovery) (DiscoveryPage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	page := DiscoveryPage{ScannedThrough: request.After}
	if request.Limit == 0 {
		request.Limit = MaxCandidates
	}
	if request.MaxCommands == 0 {
		request.MaxCommands = MaxDiscoveryCommands
	}
	if request.Limit < 1 || request.Limit > MaxCandidates || request.MaxCommands < 1 || request.MaxCommands > MaxDiscoveryCommands || request.Through >= l.snapshot.UIDNext || request.After > request.Through {
		return page, ErrInvalid
	}
	err := l.run(ctx, "discover", func() error {
		if err := l.sameGeneration(request.UIDValidity); err != nil {
			return err
		}
		commands := 0
		for page.ScannedThrough < request.Through && len(page.UIDs) < request.Limit && commands < request.MaxCommands {
			start := page.ScannedThrough + 1
			// MIN returns one scalar, avoiding a mailbox-wide UID vector.
			if l.s.client.Caps().Has(protocol.CapESearch) && commands+1 < request.MaxCommands {
				data, err := l.s.client.UIDSearch(&protocol.SearchCriteria{UID: []protocol.UIDSet{{{Start: protocol.UID(start), Stop: protocol.UID(request.Through)}}}}, &protocol.SearchOptions{ReturnMin: true}).Wait()
				commands++
				if err != nil {
					return err
				}
				if data.Min == 0 {
					page.ScannedThrough = request.Through
					break
				}
				if data.Min < start || data.Min > request.Through {
					return ErrIncomplete
				}
				start = data.Min
				page.ScannedThrough = start - 1
			}
			width := uint64(request.Limit - len(page.UIDs))
			end := uint32(min(uint64(request.Through), uint64(start)+width-1))
			data, err := l.s.client.UIDSearch(&protocol.SearchCriteria{UID: []protocol.UIDSet{{{Start: protocol.UID(start), Stop: protocol.UID(end)}}}}, nil).Wait()
			commands++
			if err != nil {
				return err
			}
			set, ok := data.All.(protocol.UIDSet)
			if !ok || set.Dynamic() {
				return ErrIncomplete
			}
			// Validate compressed ranges before expansion, including server bugs.
			var count uint64
			for _, r := range set {
				if uint32(r.Start) < start || uint32(r.Stop) > end || r.Stop < r.Start {
					return ErrIncomplete
				}
				count += uint64(r.Stop) - uint64(r.Start) + 1
				if count > width {
					return ErrIncomplete
				}
			}
			uids, ok := set.Nums()
			if !ok || len(uids) > int(width) {
				return ErrIncomplete
			}
			for _, uid := range uids {
				page.UIDs = append(page.UIDs, uint32(uid))
			}
			page.ScannedThrough = end
		}
		sort.Slice(page.UIDs, func(i, j int) bool { return page.UIDs[i] < page.UIDs[j] })
		page.Complete = page.ScannedThrough == request.Through
		return nil
	})
	if err != nil {
		return DiscoveryPage{}, err
	}
	return page, nil
}

// Metadata omits disappeared UIDs. Missing rows are expected after EXPUNGE and
// do not authorize the caller to delete already archived content.
func (l *Lease) Metadata(ctx context.Context, uidValidity uint32, uids []uint32) ([]Metadata, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(uids) == 0 || len(uids) > MaxMetadataBatch {
		return nil, ErrInvalid
	}
	set := protocol.UIDSet(nil)
	wanted := make(map[uint32]bool, len(uids))
	for _, uid := range uids {
		if uid == 0 || uid >= l.snapshot.UIDNext || wanted[uid] {
			return nil, ErrInvalid
		}
		wanted[uid] = true
		set.AddNum(protocol.UID(uid))
	}
	var result []Metadata
	err := l.run(ctx, "metadata", func() error {
		if err := l.sameGeneration(uidValidity); err != nil {
			return err
		}
		cmd := l.s.client.Fetch(set, &protocol.FetchOptions{UID: true, Flags: true, InternalDate: true, RFC822Size: true})
		var parseErr error
		for msg := cmd.Next(); msg != nil; msg = cmd.Next() {
			m := Metadata{}
			sizeSeen, dateSeen, flagsSeen := false, false, false
			for item := msg.Next(); item != nil; item = msg.Next() {
				switch item := item.(type) {
				case imapclient.FetchItemDataUID:
					m.UID = uint32(item.UID)
				case imapclient.FetchItemDataRFC822Size:
					m.Size = item.Size
					sizeSeen = true
				case imapclient.FetchItemDataInternalDate:
					m.InternalDate = item.Time
					dateSeen = true
				case imapclient.FetchItemDataFlags:
					for _, f := range item.Flags {
						m.Flags = append(m.Flags, string(f))
					}
					flagsSeen = true
				case imapclient.FetchItemDataBodySection, imapclient.FetchItemDataBinarySection:
					parseErr = ErrIncomplete
					l.s.discard()
				}
			}
			if !wanted[m.UID] || !sizeSeen || !dateSeen || !flagsSeen || m.Size < 0 {
				parseErr = ErrIncomplete
			} else {
				delete(wanted, m.UID)
				result = append(result, m)
			}
		}
		if err := cmd.Close(); err != nil {
			return err
		}
		if parseErr != nil {
			return parseErr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UID < result[j].UID })
	return result, nil
}

// StreamRaw passes a literal without buffering it. The callback must consume it
// synchronously and retain no reader. Published output must await this method's
// nil error, which includes tagged completion in the captured selection epoch.
func (l *Lease) StreamRaw(ctx context.Context, uidValidity, uid uint32, consume func(io.Reader) error) error {
	if consume == nil {
		return ErrInvalid
	}
	return l.StreamRawBatch(ctx, uidValidity, []uint32{uid}, func(_ uint32, r io.Reader) error { return consume(r) })
}

// StreamRawBatch uses one FETCH and invokes consume once per UID, in wire order.
// The caller chooses its segment byte target from Metadata; only the number of
// UIDs and each literal have provider limits. A normal large single message is
// not rejected merely because it exceeds a segment's usual 16 MiB target.
func (l *Lease) StreamRawBatch(ctx context.Context, uidValidity uint32, uids []uint32, consume func(uint32, io.Reader) error) error {
	return l.StreamRawBatchWithLimit(ctx, uidValidity, uids, MaxMessageBytes, consume)
}

// StreamRawBatchWithLimit applies an explicit incoming-message budget to every
// literal before calling consume. It does not change the default raw-reader
// limit or retain a per-pool setting that could affect another use case.
func (l *Lease) StreamRawBatchWithLimit(ctx context.Context, uidValidity uint32, uids []uint32, messageBytes int64, consume func(uint32, io.Reader) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if messageBytes <= 0 || consume == nil || len(uids) == 0 || len(uids) > MaxMetadataBatch {
		return ErrInvalid
	}
	requested := make(map[uint32]bool, len(uids))
	for _, uid := range uids {
		if uid == 0 || uid >= l.snapshot.UIDNext || requested[uid] {
			return ErrInvalid
		}
		requested[uid] = true
	}
	return l.run(ctx, "body", func() error {
		if err := l.sameGeneration(uidValidity); err != nil {
			return err
		}
		section := &protocol.FetchItemBodySection{Peek: true}
		return l.fetchLiterals(ctx, uids, section, messageBytes, func(uid uint32, r io.Reader, _ int64) error { return consume(uid, r) })
	})
}
