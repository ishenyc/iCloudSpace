package rounds

import (
	"context"
	"sync/atomic"

	"icloudspace/internal/sourceguard"
)

// Slots is shared with independent Seen writers. Idle provider sessions never
// hold a permit. No slot can be acquired without the same root source registry.
type Slots struct {
	registry *sourceguard.Registry
	tokens   chan struct{}
	active   atomic.Int64
}
type Permit struct {
	slots  *Slots
	gate   *sourceguard.Lease
	active atomic.Bool
}

func NewSlots(registry *sourceguard.Registry, capacity int) (*Slots, error) {
	if registry == nil || capacity < 1 {
		return nil, ErrInvalid
	}
	s := &Slots{registry: registry, tokens: make(chan struct{}, capacity)}
	for i := 0; i < capacity; i++ {
		s.tokens <- struct{}{}
	}
	return s, nil
}
func (s *Slots) Acquire(ctx context.Context, gate *sourceguard.Lease) (*Permit, error) {
	if s == nil || gate == nil || !gate.ValidFor(s.registry, gate.SourceID()) {
		return nil, ErrInvalid
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.tokens:
	}
	if err := ctx.Err(); err != nil {
		s.tokens <- struct{}{}
		return nil, err
	}
	if !gate.ValidFor(s.registry, gate.SourceID()) {
		s.tokens <- struct{}{}
		return nil, ErrStale
	}
	p := &Permit{slots: s, gate: gate}
	p.active.Store(true)
	s.active.Add(1)
	return p, nil
}
func (p *Permit) ValidFor(gate *sourceguard.Lease) bool {
	return p != nil && p.gate == gate && p.active.Load() && gate.ValidFor(p.slots.registry, gate.SourceID())
}

// Owns also checks the specific global budget, not merely its source registry.
func (s *Slots) Owns(permit *Permit, gate *sourceguard.Lease) bool {
	return s != nil && permit != nil && permit.slots == s && permit.ValidFor(gate)
}
func (p *Permit) Close() error {
	if p != nil && p.active.CompareAndSwap(true, false) {
		p.slots.active.Add(-1)
		p.slots.tokens <- struct{}{}
	}
	return nil
}
func (s *Slots) Active() int   { return int(s.active.Load()) }
func (s *Slots) Capacity() int { return cap(s.tokens) }
