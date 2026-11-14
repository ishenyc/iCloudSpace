package creationengine

import (
	"context"
	"database/sql"
	"errors"
)

func (e *Engine) claim(ctx context.Context, id int64) (Attempt, int64, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Attempt{}, 0, err
	}
	defer tx.Rollback()
	source, err := readSource(ctx, tx, id)
	if err != nil {
		return Attempt{}, 0, err
	}
	p, err := readPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM space.creation_policies WHERE source_id=$1 FOR UPDATE`, id))
	if err != nil {
		return Attempt{}, 0, err
	}
	if !p.Enabled {
		return Attempt{}, 0, ErrNotDue
	}
	blocked, err := unresolved(ctx, tx, id)
	if err != nil {
		return Attempt{}, 0, err
	}
	if blocked {
		return Attempt{}, 0, ErrUnresolved
	}
	if !eligible(source) || p.ScheduleKind != "scheduled" || p.AttemptsPerRound < 1 || p.AttemptsPerRound > MaximumAttempts {
		return Attempt{}, 0, ErrIneligible
	}
	now := e.options.Clock()
	if p.CooldownUntil != nil && *p.CooldownUntil > now {
		return Attempt{}, 0, ErrNotDue
	}
	if p.LastAttemptedAt != nil {
		next, err := add(*p.LastAttemptedAt, int64(MinimumInterval))
		if err != nil {
			return Attempt{}, 0, err
		}
		if next > now {
			return Attempt{}, 0, ErrNotDue
		}
	}
	cutoff, err := add(now, -int64(RoundDuration))
	if err != nil {
		return Attempt{}, 0, err
	}
	var recent int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM space.creation_attempts WHERE source_id=$1 AND claimed_at>$2`, id, cutoff).Scan(&recent); err != nil {
		return Attempt{}, 0, storage(ctx)
	}
	if recent >= MaximumAttempts {
		return Attempt{}, 0, ErrNotDue
	}
	if p.MaximumAddresses > 0 {
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM space.private_addresses WHERE source_id=$1 AND enabled AND deleted_at IS NULL`, id).Scan(&n); err != nil {
			return Attempt{}, 0, storage(ctx)
		}
		if n >= p.MaximumAddresses {
			return Attempt{}, 0, ErrCapacity
		}
	}
	var slot Slot
	err = tx.QueryRowContext(ctx, `SELECT source_id,policy_revision,scheduled_for,state FROM space.creation_slots WHERE source_id=$1 AND state='scheduled' ORDER BY scheduled_for,policy_revision LIMIT 1 FOR UPDATE`, id).Scan(&slot.SourceID, &slot.PolicyRevision, &slot.ScheduledFor, &slot.State)
	if errors.Is(err, sql.ErrNoRows) {
		if err = e.replan(ctx, tx, p, now, now, "creation_round_planned"); err != nil {
			return Attempt{}, 0, err
		}
		if err = commit(tx); err != nil {
			return Attempt{}, 0, err
		}
		return Attempt{}, 0, ErrNotDue
	}
	if err != nil {
		return Attempt{}, 0, storage(ctx)
	}
	if slot.ScheduledFor > now {
		return Attempt{}, 0, ErrNotDue
	}
	expires, err := add(slot.ScheduledFor, int64(e.options.OverdueGrace))
	if err != nil {
		return Attempt{}, 0, err
	}
	if expires < now {
		first, err := add(now, int64(MinimumInterval))
		if err != nil {
			return Attempt{}, 0, err
		}
		if err = e.replan(ctx, tx, p, first, now, "creation_overdue_replanned"); err != nil {
			return Attempt{}, 0, err
		}
		if err = commit(tx); err != nil {
			return Attempt{}, 0, err
		}
		return Attempt{}, 0, ErrNotDue
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO space.creation_attempts(source_id,policy_revision,scheduled_for,ordinal,state,error_code,created_at) VALUES($1,$2,$3,0,'scheduled','',$4) ON CONFLICT(source_id,policy_revision,scheduled_for,ordinal) DO NOTHING`, id, slot.PolicyRevision, slot.ScheduledFor, now); err != nil {
		return Attempt{}, 0, storage(ctx)
	}
	a, err := readAttempt(tx.QueryRowContext(ctx, `SELECT `+attemptColumns+` FROM space.creation_attempts WHERE source_id=$1 AND policy_revision=$2 AND scheduled_for=$3 AND ordinal=0 FOR UPDATE`, id, slot.PolicyRevision, slot.ScheduledFor))
	if err != nil {
		return a, 0, err
	}
	if a.State != "scheduled" {
		return a, 0, ErrUnresolved
	}
	a.OwnerKey, err = ownerKey()
	if err != nil {
		return a, 0, err
	}
	a.State = "claimed"
	a.ClaimedAt = &now
	a.OperationKey = operationKey(a.ID, a.OwnerKey)
	if _, err = tx.ExecContext(ctx, `UPDATE space.creation_attempts SET state='claimed',owner_key=$2,claimed_at=$3 WHERE id=$1 AND state='scheduled'`, a.ID, a.OwnerKey, now); err != nil {
		return a, 0, storage(ctx)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.creation_slots SET state='claimed' WHERE source_id=$1 AND policy_revision=$2 AND scheduled_for=$3 AND state='scheduled'`, id, slot.PolicyRevision, slot.ScheduledFor); err != nil {
		return a, 0, storage(ctx)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO space.creation_claims(source_id,attempt_id,owner_key,claimed_at) VALUES($1,$2,$3,$4)`, id, a.ID, a.OwnerKey, now); err != nil {
		return a, 0, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.creation_policies SET last_attempted_at=$2::bigint,updated_at=greatest(updated_at+1,$2::bigint) WHERE source_id=$1`, id, now); err != nil {
		return a, 0, storage(ctx)
	}
	if err = event(ctx, tx, id, a.OperationKey, "creation_claimed", "started", "", now); err != nil {
		return a, 0, storage(ctx)
	}
	if err = audit(ctx, tx, id, a.OperationKey, "creation_attempt_claimed", "success", now); err != nil {
		return a, 0, storage(ctx)
	}
	if err = commit(tx); err != nil {
		return a, 0, err
	}
	return a, source.revision, nil
}
func (e *Engine) replan(ctx context.Context, tx *sql.Tx, p Policy, first, now int64, phase string) error {
	revision, err := nextRevision(p.Revision)
	if err != nil {
		return err
	}
	slots, err := e.plan(first, p.AttemptsPerRound)
	if err != nil {
		return err
	}
	if err = cancelScheduled(ctx, tx, p.SourceID, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.creation_policies SET revision=$2,updated_at=greatest(updated_at+1,$3) WHERE source_id=$1`, p.SourceID, revision, now); err != nil {
		return storage(ctx)
	}
	if err = insertPlan(ctx, tx, p.SourceID, revision, slots, now); err != nil {
		return err
	}
	return event(ctx, tx, p.SourceID, "", phase, "progress", "", now)
}
