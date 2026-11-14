package localcleanup

import (
	"context"
	"errors"
	"time"
)

func (s *Service) Step(ctx context.Context) (Progress, error) {
	var result Progress
	if s == nil {
		return result, ErrInvalid
	}
	if !s.worker.CompareAndSwap(false, true) {
		return result, ErrBusy
	}
	defer s.worker.Store(false)
	rows, e := s.db.QueryContext(ctx, `SELECT `+objectColumns+` FROM space.local_cleanup_objects WHERE state IN ('ready','protected','needs_review') ORDER BY updated_at,operation_key,object_key,publication_generation LIMIT $1`, s.options.BatchSize)
	if e != nil {
		return result, storage(ctx)
	}
	var page []object
	for rows.Next() {
		o, e := scanObject(rows)
		if e != nil {
			rows.Close()
			return result, storage(ctx)
		}
		page = append(page, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, storage(ctx)
	}
	for _, o := range page {
		state, e := s.process(ctx, o)
		if errors.Is(e, ErrEvidence) {
			state = "needs_review"
			e = s.record(ctx, o, state, "sql_evidence_mismatch")
		}
		if e != nil {
			return result, e
		}
		result.Visited++
		switch state {
		case "collected":
			result.Collected++
		case "absent":
			result.Absent++
		case "shared":
			result.Shared++
		case "protected":
			result.Protected++
		case "needs_review":
			result.NeedsReview++
		}
	}
	if e = s.finishPage(ctx); e != nil {
		return result, e
	}
	return result, nil
}
func (s *Service) finishPage(ctx context.Context) error {
	rows, e := s.db.QueryContext(ctx, `SELECT operation_key,source_id,kind FROM space.local_cleanup_operations WHERE state<>'complete' ORDER BY updated_at,operation_key LIMIT $1`, s.options.BatchSize)
	if e != nil {
		return storage(ctx)
	}
	type operation struct {
		key, kind string
		source    int64
	}
	var page []operation
	for rows.Next() {
		var op operation
		if rows.Scan(&op.key, &op.source, &op.kind) != nil {
			rows.Close()
			return storage(ctx)
		}
		page = append(page, op)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return storage(ctx)
	}
	for _, op := range page {
		g, e := s.guards.Acquire(ctx, op.source)
		if e != nil {
			return e
		}
		e = s.finishHeld(ctx, op.key, op.kind, op.source)
		g.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) finishHeld(ctx context.Context, key, kind string, source int64) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return storage(ctx)
	}
	defer tx.Rollback()
	var id int64
	if tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, source).Scan(&id) != nil {
		return ErrEvidence
	}
	if e = s.writable(ctx, tx); e != nil {
		return e
	}
	// No renewed secret reads are allowed for retired sources. Remaining
	// reconciliation secrets are erased after their last unknown owner resolves.
	if kind == "source_delete" {
		if e = s.scrubSourceSecrets(ctx, tx, source); e != nil {
			return e
		}
	}
	now := s.options.Clock()
	_, e = tx.ExecContext(ctx, `UPDATE space.local_cleanup_operations c SET state=CASE WHEN NOT inventory_complete OR EXISTS(SELECT 1 FROM space.local_cleanup_objects o WHERE o.operation_key=c.operation_key AND state IN ('protected','needs_review')) OR (kind='source_delete' AND EXISTS(SELECT 1 FROM space.mail_sources s WHERE s.id=c.source_id AND s.credentials_envelope IS NOT NULL)) THEN 'blocked' WHEN EXISTS(SELECT 1 FROM space.local_cleanup_objects o WHERE o.operation_key=c.operation_key AND state='ready') THEN 'cleaning' ELSE 'complete' END,
 completed_at=CASE WHEN inventory_complete AND NOT EXISTS(SELECT 1 FROM space.local_cleanup_objects o WHERE o.operation_key=c.operation_key AND state IN ('ready','protected','needs_review')) AND NOT (kind='source_delete' AND EXISTS(SELECT 1 FROM space.mail_sources s WHERE s.id=c.source_id AND s.credentials_envelope IS NOT NULL)) THEN $2::bigint ELSE NULL END,updated_at=greatest(updated_at+1,$2::bigint) WHERE operation_key=$1`, key, now)
	if e != nil {
		return sqlFailure(ctx, e, "operation-finish")
	}
	if e = s.commit(tx); e != nil {
		return ErrUnknown
	}
	return nil
}

// Run joins the current bounded Step on cancellation. It owns no producer or
// remote connection; the composition root joins this one worker at shutdown.
func (s *Service) Run(ctx context.Context) error {
	if s == nil {
		return ErrInvalid
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrBusy
	}
	defer s.running.Store(false)
	ticker := time.NewTicker(s.options.Interval)
	defer ticker.Stop()
	for {
		if _, e := s.Step(ctx); e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
