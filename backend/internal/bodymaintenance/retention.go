package bodymaintenance

import (
	"context"
	"errors"
)

const eligibleFIFO = `o.state='available' AND p.state='committed' AND NOT EXISTS(SELECT 1 FROM space.content_publications pending WHERE pending.object_key=o.object_key AND pending.state IN ('staged','published','sql_unknown')) AND NOT EXISTS(
 SELECT 1 FROM space.intake_batches b WHERE b.state='prepared' AND b.source_id=o.source_id)`

func (s *Service) evictPage(ctx context.Context, result *Result) error {
	// Recovery and verification never add available bytes. If intake crosses
	// capacity concurrently after Before, After reports it for the next tick;
	// ordinary under-capacity ticks need no global write lock.
	if !result.Before.OverCapacity {
		return nil
	}
	refs, e := fifoPage(ctx, s.db, s.options.BatchSize)
	if e != nil {
		return e
	}
	if len(refs) == 0 {
		result.Protected++
		return nil
	}
	closeGuards, e := s.pageGuards(ctx, refs)
	if errors.Is(e, ErrBusy) {
		result.Protected++
		return nil
	}
	if e != nil {
		return e
	}
	marked, recovered, e := s.markEvicted(ctx, refs)
	closeGuards()
	if errors.Is(e, ErrBusy) || errors.Is(e, ErrStale) || errors.Is(e, ErrProtected) {
		result.Protected++
		return nil
	}
	if e != nil {
		return e
	}
	result.Evicted += len(marked)
	if recovered {
		result.Recovered += len(marked)
	}
	collected, e := s.collectPage(ctx, marked)
	result.Collected += collected.Collected
	result.Unresolved += collected.Unresolved + collected.Protected
	return e
}
func (s *Service) evict(ctx context.Context, ref Reference) (evicted, collected, recovered bool, err error) {
	if !validReference(ref) {
		return false, false, false, ErrEvidence
	}
	guard, e := s.guards.Acquire(ctx, ref.SourceID)
	if e != nil {
		return false, false, false, e
	}
	defer guard.Close()
	marked, recovered, e := s.markEvicted(ctx, []Reference{ref})
	if e != nil {
		return false, false, recovered, e
	}
	if len(marked) == 0 {
		return false, false, recovered, nil
	}
	evicted = true
	collected, e = s.collectHeld(ctx, ref)
	if errors.Is(e, ErrEvidence) {
		return true, false, recovered, nil
	}
	return evicted, collected, recovered, e
}
