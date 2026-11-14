package imap

import (
	"context"
	"sort"
	"strings"

	protocol "github.com/emersion/go-imap/v2"
)

// SearchHeader locates at most four current-mailbox candidates. IMAP HEADER is
// a substring search; the caller must verify complete fetched headers before
// treating a result as its nonce or Message-ID. No body or Seen state is read.
func (l *Lease) SearchHeader(ctx context.Context, uidValidity uint32, name, value string, limit int) ([]uint32, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if strings.EqualFold(name, "Subject") {
		name = "Subject"
	} else if strings.EqualFold(name, "Message-ID") {
		name = "Message-ID"
	} else {
		return nil, ErrInvalid
	}
	if limit < 1 || limit > 4 || value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
		return nil, ErrInvalid
	}
	var result []uint32
	err := l.run(ctx, "search", func() error {
		if err := l.sameGeneration(uidValidity); err != nil {
			return err
		}
		if l.snapshot.UIDNext == 1 {
			return nil
		}
		upper := l.snapshot.UIDNext - 1
		data, err := l.s.client.UIDSearch(&protocol.SearchCriteria{
			UID:    []protocol.UIDSet{{{Start: 1, Stop: protocol.UID(upper)}}},
			Header: []protocol.SearchCriteriaHeaderField{{Key: name, Value: value}},
		}, &protocol.SearchOptions{ReturnAll: true}).Wait()
		if err != nil {
			return err
		}
		// RFC 4731 requires omitting ALL for an empty ESEARCH result. The
		// SDK represents that as nil, unlike legacy SEARCH's typed empty set.
		// A positive result without the requested ALL set is still incomplete.
		if data.All == nil {
			if data.Count != 0 || data.Min != 0 || data.Max != 0 {
				return ErrIncomplete
			}
			result = []uint32{}
			return nil
		}
		set, ok := data.All.(protocol.UIDSet)
		if !ok || set.Dynamic() {
			return ErrIncomplete
		}
		var count uint64
		for _, r := range set {
			if r.Start < 1 || r.Stop < r.Start || uint32(r.Stop) > upper {
				return ErrIncomplete
			}
			count += uint64(r.Stop) - uint64(r.Start) + 1
			if count > uint64(limit) {
				return ErrTooLarge
			}
		}
		// Expansion is permitted only after the compressed representation has
		// been checked. A huge or dynamic range never allocates a UID vector.
		uids, ok := set.Nums()
		if !ok {
			return ErrIncomplete
		}
		result = make([]uint32, len(uids))
		for i, uid := range uids {
			result[i] = uint32(uid)
		}
		sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
		for i := 1; i < len(result); i++ {
			if result[i] == result[i-1] {
				return ErrIncomplete
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
