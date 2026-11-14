package creationengine

import (
	"context"
	"errors"
	"sync"
	"time"
)

func (e *Engine) notify() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Run has one discovery ticker and a fixed worker group, irrespective of the
// number of sources. Completion wakes discovery; each source occupies one job.
func (e *Engine) Run(ctx context.Context) error {
	if e == nil {
		return ErrInvalid
	}
	if !e.running.CompareAndSwap(false, true) {
		return ErrConflict
	}
	defer e.running.Store(false)
	if err := e.Recover(ctx); err != nil {
		return err
	}
	jobs := make(chan int64, e.options.Workers*2)
	var workers sync.WaitGroup
	for i := 0; i < e.options.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for id := range jobs {
				_, err := e.Step(ctx, id)
				if err != nil && !errors.Is(err, ErrNotDue) && !errors.Is(err, ErrUnresolved) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					e.options.Logger.Warn("Automatic creation attempt did not finish", "component", "creation", "source_id", id, "phase", "creation_worker", "outcome", "failed", "error_code", "creation_worker_failed")
				}
				e.mu.Lock()
				delete(e.active, id)
				e.mu.Unlock()
				e.notify()
			}
		}()
	}
	defer func() { close(jobs); workers.Wait() }()
	ticker := time.NewTicker(e.options.PollInterval)
	defer ticker.Stop()
	for {
		if err := e.dispatch(ctx, jobs); err != nil && !errors.Is(err, context.Canceled) {
			e.options.Logger.Warn("Automatic creation discovery failed", "component", "creation", "phase", "creation_discovery", "outcome", "failed", "error_code", "creation_discovery_failed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-e.wake:
		}
	}
}
func (e *Engine) dispatch(ctx context.Context, jobs chan<- int64) error {
	now := e.options.Clock()
	cutoff, err := add(now, -int64(RoundDuration))
	if err != nil {
		return err
	}
	latest, err := add(now, -int64(MinimumInterval))
	if err != nil {
		return err
	}
	e.mu.Lock()
	after := e.after
	e.mu.Unlock()
	rows, err := e.db.QueryContext(ctx, `SELECT p.source_id FROM space.creation_policies p JOIN space.mail_sources m ON m.id=p.source_id
 WHERE p.enabled AND m.enabled AND (p.cooldown_until IS NULL OR p.cooldown_until<=$1)
 AND (p.last_attempted_at IS NULL OR p.last_attempted_at<=$2)
 AND EXISTS(SELECT 1 FROM space.installation WHERE singleton AND installation_id=$6 AND writes_enabled)
 AND NOT EXISTS(SELECT 1 FROM space.creation_claims c WHERE c.source_id=p.source_id)
 AND NOT EXISTS(SELECT 1 FROM space.creation_attempts a WHERE a.source_id=p.source_id AND a.state IN ('claimed','unknown'))
 AND NOT EXISTS(SELECT 1 FROM space.creation_slots s WHERE s.source_id=p.source_id AND s.state IN ('claimed','unknown'))
 AND (SELECT count(*) FROM space.creation_attempts a WHERE a.source_id=p.source_id AND a.claimed_at>$3)<5
 AND (EXISTS(SELECT 1 FROM space.creation_slots s WHERE s.source_id=p.source_id AND s.state='scheduled' AND s.scheduled_for<=$1)
 OR NOT EXISTS(SELECT 1 FROM space.creation_slots s WHERE s.source_id=p.source_id AND s.state='scheduled'))
 ORDER BY (p.source_id>$4) DESC,p.source_id LIMIT $5`, now, latest, cutoff, after, e.options.Workers*4, e.installation)
	if err != nil {
		return storage(ctx)
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) != nil {
			rows.Close()
			return storage(ctx)
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storage(ctx)
	}
	for _, id := range ids {
		e.mu.Lock()
		if e.active[id] {
			e.mu.Unlock()
			continue
		}
		e.active[id] = true
		e.mu.Unlock()
		select {
		case jobs <- id:
			e.mu.Lock()
			e.after = id
			e.mu.Unlock()
		case <-ctx.Done():
			e.mu.Lock()
			delete(e.active, id)
			e.mu.Unlock()
			return ctx.Err()
		default:
			e.mu.Lock()
			delete(e.active, id)
			e.mu.Unlock()
			return nil
		}
	}
	return nil
}
