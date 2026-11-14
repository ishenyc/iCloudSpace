package creationengine

import (
	"context"
	"database/sql"
	"errors"
)

type sourceState struct {
	revision           int64
	kind               string
	enabled, principal bool
}

func readSource(ctx context.Context, tx *sql.Tx, id int64) (sourceState, error) {
	var source sourceState
	err := tx.QueryRowContext(ctx, `SELECT revision,kind,enabled,EXISTS(SELECT 1 FROM space.apple_principals p WHERE p.source_id=s.id AND p.dsid IS NOT NULL AND p.dsid<>'') FROM space.mail_sources s WHERE id=$1 FOR UPDATE`, id).Scan(&source.revision, &source.kind, &source.enabled, &source.principal)
	if errors.Is(err, sql.ErrNoRows) {
		return source, ErrNotFound
	}
	if err != nil {
		return source, storage(ctx)
	}
	return source, nil
}
func eligible(source sourceState) bool {
	return source.enabled && source.kind != "custom" && source.principal
}
func unresolved(ctx context.Context, q queryer, source int64) (bool, error) {
	var pending bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.creation_claims WHERE source_id=$1)
 OR EXISTS(SELECT 1 FROM space.creation_attempts WHERE source_id=$1 AND state IN ('claimed','unknown'))
 OR EXISTS(SELECT 1 FROM space.creation_slots WHERE source_id=$1 AND state IN ('claimed','unknown'))`, source).Scan(&pending)
	if err != nil {
		return false, storage(ctx)
	}
	return pending, nil
}

// Get is a stable metadata read. Migrated finite slots and original attempt
// owners are returned as stored, without converting them into a repeat interval.
func (e *Engine) Get(ctx context.Context, source int64) (Policy, error) {
	if e == nil || source < 1 {
		return Policy{}, ErrInvalid
	}
	tx, err := e.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Policy{}, storage(ctx)
	}
	defer tx.Rollback()
	p, err := readPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM space.creation_policies WHERE source_id=$1`, source))
	if err != nil {
		return p, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT source_id,policy_revision,scheduled_for,state FROM space.creation_slots WHERE source_id=$1 AND state IN ('scheduled','claimed','unknown') ORDER BY scheduled_for,policy_revision`, source)
	if err != nil {
		return p, storage(ctx)
	}
	p.Slots = []Slot{}
	for rows.Next() {
		var slot Slot
		if err = rows.Scan(&slot.SourceID, &slot.PolicyRevision, &slot.ScheduledFor, &slot.State); err != nil {
			rows.Close()
			return p, storage(ctx)
		}
		p.Slots = append(p.Slots, slot)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, storage(ctx)
	}
	a, err := readAttempt(tx.QueryRowContext(ctx, `SELECT `+attemptColumns+` FROM space.creation_attempts a WHERE a.source_id=$1 AND (a.state IN ('claimed','unknown') OR EXISTS(SELECT 1 FROM space.creation_claims c WHERE c.source_id=$1 AND c.attempt_id=a.id)) ORDER BY a.id LIMIT 1`, source))
	if err == nil {
		p.PendingAttempt = &a
	} else if !errors.Is(err, ErrNotFound) {
		return p, err
	}
	if err = tx.Commit(); err != nil {
		return p, storage(ctx)
	}
	return p, nil
}

func (e *Engine) Set(ctx context.Context, source, expectedRevision int64, settings Settings) (Policy, error) {
	if settings.MaximumAddresses < 0 || settings.AttemptsPerRound < 1 || settings.AttemptsPerRound > MaximumAttempts {
		return Policy{}, ErrInvalid
	}
	return e.change(ctx, source, expectedRevision, &settings, nil)
}
func (e *Engine) Enable(ctx context.Context, source, expectedRevision int64) (Policy, error) {
	enabled := true
	return e.change(ctx, source, expectedRevision, nil, &enabled)
}
func (e *Engine) Disable(ctx context.Context, source, expectedRevision int64) (Policy, error) {
	enabled := false
	return e.change(ctx, source, expectedRevision, nil, &enabled)
}

func (e *Engine) change(ctx context.Context, id, expected int64, settings *Settings, toggle *bool) (Policy, error) {
	if e == nil || id < 1 || expected < 0 {
		return Policy{}, ErrInvalid
	}
	ctx, close, err := e.enter(ctx, id)
	if err != nil {
		return Policy{}, err
	}
	defer close()
	tx, err := e.begin(ctx)
	if err != nil {
		return Policy{}, err
	}
	defer tx.Rollback()
	source, err := readSource(ctx, tx, id)
	if err != nil {
		return Policy{}, err
	}
	p, err := readPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM space.creation_policies WHERE source_id=$1 FOR UPDATE`, id))
	if errors.Is(err, ErrNotFound) {
		p = Policy{SourceID: id, ScheduleKind: "scheduled", AttemptsPerRound: MaximumAttempts, CreatedAt: e.options.Clock()}
	} else if err != nil {
		return p, err
	}
	if p.Revision != expected {
		return p, ErrConflict
	}
	revision, err := nextRevision(p.Revision)
	if err != nil {
		return p, err
	}
	if settings != nil {
		p.MaximumAddresses = settings.MaximumAddresses
		p.AttemptsPerRound = settings.AttemptsPerRound
		p.ScheduleKind = "scheduled"
		p.IntervalMilliseconds = nil
	}
	if toggle != nil {
		p.Enabled = *toggle
	}
	if p.Enabled && (!eligible(source) || p.ScheduleKind != "scheduled" || p.AttemptsPerRound < 1 || p.AttemptsPerRound > MaximumAttempts) {
		return p, ErrIneligible
	}
	blocked, err := unresolved(ctx, tx, id)
	if err != nil {
		return p, err
	}
	if p.Enabled && blocked {
		return p, ErrUnresolved
	}
	now := e.options.Clock()
	var slots []int64
	if !p.Enabled || settings != nil {
		if err = cancelScheduled(ctx, tx, id, now); err != nil {
			return p, err
		}
	} else {
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM space.creation_slots WHERE source_id=$1 AND state='scheduled'`, id).Scan(&n); err != nil {
			return p, storage(ctx)
		}
		if n > 0 {
			slots = []int64{}
		}
	}
	if p.Enabled && slots == nil {
		first, err := add(now, int64(MinimumInterval))
		if err != nil {
			return p, err
		}
		if p.CooldownUntil != nil && *p.CooldownUntil > first {
			first = *p.CooldownUntil
		}
		slots, err = e.plan(first, p.AttemptsPerRound)
		if err != nil {
			return p, err
		}
	}
	paused := p.PausedReason
	if p.Enabled {
		paused = ""
	} else if !blocked {
		paused = "disabled"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO space.creation_policies(source_id,enabled,revision,schedule_kind,interval_milliseconds,maximum_addresses,attempts_per_round,cooldown_until,paused_reason,last_attempted_at,last_confirmed_at,last_address,last_error_detail,created_at,updated_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
 ON CONFLICT(source_id) DO UPDATE SET enabled=EXCLUDED.enabled,revision=EXCLUDED.revision,schedule_kind=EXCLUDED.schedule_kind,interval_milliseconds=EXCLUDED.interval_milliseconds,maximum_addresses=EXCLUDED.maximum_addresses,attempts_per_round=EXCLUDED.attempts_per_round,paused_reason=EXCLUDED.paused_reason,updated_at=greatest(space.creation_policies.updated_at+1,EXCLUDED.updated_at)`, id, p.Enabled, revision, p.ScheduleKind, p.IntervalMilliseconds, p.MaximumAddresses, p.AttemptsPerRound, p.CooldownUntil, paused, p.LastAttemptedAt, p.LastConfirmedAt, p.LastAddress, p.LastErrorDetail, p.CreatedAt, now)
	if err != nil {
		return p, storage(ctx)
	}
	if len(slots) > 0 {
		if err = insertPlan(ctx, tx, id, revision, slots, now); err != nil {
			return p, err
		}
	}
	if err = audit(ctx, tx, id, "", "creation_policy_changed", "success", now); err != nil {
		return p, storage(ctx)
	}
	if err = commit(tx); err != nil {
		return p, err
	}
	e.notify()
	return e.Get(ctx, id)
}
func cancelScheduled(ctx context.Context, tx *sql.Tx, source, at int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE space.creation_slots SET state='cancelled' WHERE source_id=$1 AND state='scheduled'`, source); err != nil {
		return storage(ctx)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE space.creation_attempts SET state='cancelled',finished_at=$2 WHERE source_id=$1 AND state='scheduled'`, source, at); err != nil {
		return storage(ctx)
	}
	return nil
}
func insertPlan(ctx context.Context, tx *sql.Tx, source, revision int64, slots []int64, at int64) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO space.creation_slots(source_id,policy_revision,scheduled_for,state) SELECT $1,$2,value,'scheduled' FROM unnest($3::bigint[]) AS value`, source, revision, slots); err != nil {
		return storage(ctx)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO space.creation_attempts(source_id,policy_revision,scheduled_for,ordinal,state,error_code,created_at) SELECT $1,$2,value,0,'scheduled','',$4 FROM unnest($3::bigint[]) AS value`, source, revision, slots, at); err != nil {
		return storage(ctx)
	}
	return nil
}
