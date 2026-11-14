// Package sourceguard serializes business operations on one mail source.
// The composition root creates one Registry and shares it with every source
// owner. Worker admission and network-session caching remain separate owners.
package sourceguard

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var ErrInvalid = errors.New("sourceguard: positive source identity and registry are required")

type cell struct {
	token chan struct{}
	refs  int
}

type Registry struct {
	mu      sync.Mutex
	entries map[int64]*cell
}

func New() *Registry { return &Registry{entries: make(map[int64]*cell)} }

type Lease struct {
	registry *Registry
	entry    *cell
	sourceID int64
	active   atomic.Bool
}

func (r *Registry) Acquire(ctx context.Context, sourceID int64) (*Lease, error) {
	if r == nil || sourceID < 1 {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.entries == nil {
		r.entries = make(map[int64]*cell)
	}
	entry := r.entries[sourceID]
	if entry == nil {
		entry = &cell{token: make(chan struct{}, 1)}
		entry.token <- struct{}{}
		r.entries[sourceID] = entry
	}
	entry.refs++
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		r.drop(sourceID, entry)
		return nil, ctx.Err()
	case <-entry.token:
	}
	if err := ctx.Err(); err != nil {
		entry.token <- struct{}{}
		r.drop(sourceID, entry)
		return nil, err
	}
	lease := &Lease{registry: r, entry: entry, sourceID: sourceID}
	lease.active.Store(true)
	return lease, nil
}

func (l *Lease) SourceID() int64 {
	if l == nil {
		return 0
	}
	return l.sourceID
}

func (l *Lease) ValidFor(registry *Registry, sourceID int64) bool {
	return l != nil && l.registry == registry && l.sourceID == sourceID && l.active.Load()
}

// Cancellation does not release the business lock behind an in-flight IO.
// The owner finishes/cancels that IO, resolves uncertain state, then closes its
// lease. A canceled waiter, in contrast, never receives ownership.
func (l *Lease) Close() error {
	if l != nil && l.active.CompareAndSwap(true, false) {
		l.entry.token <- struct{}{}
		l.registry.drop(l.sourceID, l.entry)
	}
	return nil
}

func (r *Registry) drop(sourceID int64, entry *cell) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry.refs--
	if entry.refs == 0 && r.entries[sourceID] == entry {
		delete(r.entries, sourceID)
	}
}
