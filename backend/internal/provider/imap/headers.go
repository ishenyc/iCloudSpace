package imap

import (
	"context"
	"errors"
	"io"
	"sort"

	protocol "github.com/emersion/go-imap/v2"
)

// Headers is an on-demand metadata path for messages whose full raw body is not
// fetched, including oversized messages. It requests at most 64 KiB plus one
// sentinel octet per UID in one FETCH; no envelope strings or MIME are decoded.
// The sentinel establishes truncation without guessing from a full 64 KiB page.
// Disappeared UIDs are omitted, as with Metadata.
func (l *Lease) Headers(ctx context.Context, uidValidity uint32, uids []uint32) ([]Header, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(uids) == 0 || len(uids) > MaxMetadataBatch {
		return nil, ErrInvalid
	}
	wanted := make(map[uint32]bool, len(uids))
	for _, uid := range uids {
		if uid == 0 || uid >= l.snapshot.UIDNext || wanted[uid] {
			return nil, ErrInvalid
		}
		wanted[uid] = true
	}
	var result []Header
	err := l.run(ctx, "headers", func() error {
		if err := l.sameGeneration(uidValidity); err != nil {
			return err
		}
		section := &protocol.FetchItemBodySection{Specifier: protocol.PartSpecifierHeader, Peek: true, Partial: &protocol.SectionPartial{Offset: 0, Size: MaxHeaderBytes + 1}}
		err := l.fetchLiterals(ctx, uids, section, MaxHeaderBytes+1, func(uid uint32, r io.Reader, size int64) error {
			buffer := make([]byte, int(size))
			if _, err := io.ReadFull(r, buffer); err != nil {
				return ErrIncomplete
			}
			retained := min(len(buffer), MaxHeaderBytes)
			result = append(result, Header{UID: uid, RawHeader: buffer[:retained:retained], Truncated: len(buffer) > MaxHeaderBytes})
			return nil
		})
		var missing *MissingError
		if err != nil && !errors.As(err, &missing) {
			return err
		}
		for i := range result {
			result[i].Complete = !result[i].Truncated
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UID < result[j].UID })
	return result, nil
}
