package creationengine

import (
	"context"
	"database/sql"
	"errors"
)

const attemptColumns = `id,source_id,policy_revision,scheduled_for,ordinal,state,owner_key,operation_key,claimed_at,finished_at,error_code,created_at`

func readAttempt(row scanner) (Attempt, error) {
	var a Attempt
	var owner, key sql.NullString
	var claimed, finished sql.NullInt64
	err := row.Scan(&a.ID, &a.SourceID, &a.PolicyRevision, &a.ScheduledFor, &a.Ordinal, &a.State, &owner, &key, &claimed, &finished, &a.ErrorCode, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, ErrStorage
	}
	a.OwnerKey = owner.String
	a.OperationKey = key.String
	a.ClaimedAt = nullable(claimed)
	a.FinishedAt = nullable(finished)
	if a.OperationKey == "" {
		a.OperationKey = operationKey(a.ID, a.OwnerKey)
	}
	return a, nil
}
func (e *Engine) Attempt(ctx context.Context, source, id int64) (Attempt, error) {
	if e == nil || source < 1 || id < 1 {
		return Attempt{}, ErrInvalid
	}
	a, err := readAttempt(e.db.QueryRowContext(ctx, `SELECT `+attemptColumns+` FROM space.creation_attempts WHERE source_id=$1 AND id=$2`, source, id))
	if err != nil {
		return a, err
	}
	if a.OperationKey != "" {
		var address sql.NullInt64
		err = e.db.QueryRowContext(ctx, `SELECT state,address_id FROM space.address_operations WHERE source_id=$1 AND operation_key=$2 AND kind='create' AND owner_key=$3`, source, a.OperationKey, a.OwnerKey).Scan(&a.OperationState, &address)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return a, storage(ctx)
		}
		a.AddressID = nullable(address)
	}
	return a, nil
}
func (e *Engine) Attempts(ctx context.Context, source, after int64, limit int) ([]Attempt, error) {
	if e == nil || source < 1 || after < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	rows, err := e.db.QueryContext(ctx, `SELECT `+attemptColumns+` FROM space.creation_attempts WHERE source_id=$1 AND id>$2 ORDER BY id LIMIT $3`, source, after, limit)
	if err != nil {
		return nil, storage(ctx)
	}
	defer rows.Close()
	result := []Attempt{}
	for rows.Next() {
		a, err := readAttempt(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	if rows.Err() != nil {
		return nil, storage(ctx)
	}
	return result, nil
}

// Recover is the startup fence, never a lease expiry or retry. Previously
// claimed/unknown work remains claimed and the policy is paused for review.
func (e *Engine) Recover(ctx context.Context) error {
	if e == nil {
		return ErrInvalid
	}
	var after int64
	for {
		rows, err := e.db.QueryContext(ctx, `SELECT p.source_id FROM space.creation_policies p WHERE p.source_id>$1 AND (
 EXISTS(SELECT 1 FROM space.creation_claims c WHERE c.source_id=p.source_id)
 OR EXISTS(SELECT 1 FROM space.creation_attempts a WHERE a.source_id=p.source_id AND a.state IN ('claimed','unknown'))
 OR EXISTS(SELECT 1 FROM space.creation_slots s WHERE s.source_id=p.source_id AND s.state IN ('claimed','unknown'))) ORDER BY p.source_id LIMIT 128`, after)
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
			guarded, close, err := e.enter(ctx, id)
			if err != nil {
				return err
			}
			err = e.pause(guarded, id, 0, "unresolved_attempt")
			close()
			if err != nil {
				return err
			}
			after = id
		}
		if len(ids) < 128 {
			return nil
		}
	}
}
func (e *Engine) pause(ctx context.Context, source, attempt int64, code string) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = readSource(ctx, tx, source); err != nil {
		return err
	}
	p, err := readPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM space.creation_policies WHERE source_id=$1 FOR UPDATE`, source))
	if err != nil {
		return err
	}
	now := e.options.Clock()
	revision := p.Revision
	if p.Enabled || p.PausedReason == "" {
		revision, err = nextRevision(revision)
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.creation_policies SET enabled=false,revision=$2,paused_reason=$3,last_error_detail=$3,updated_at=greatest(updated_at+1,$4) WHERE source_id=$1`, source, revision, safeCode(code), now); err != nil {
		return storage(ctx)
	}
	if attempt > 0 {
		a, err := readAttempt(tx.QueryRowContext(ctx, `SELECT `+attemptColumns+` FROM space.creation_attempts WHERE source_id=$1 AND id=$2 FOR UPDATE`, source, attempt))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil && (a.State == "claimed" || a.State == "unknown") {
			var operation any
			var exists bool
			if a.OperationKey != "" {
				if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_operations WHERE source_id=$1 AND operation_key=$2 AND owner_key=$3 AND kind='create')`, source, a.OperationKey, a.OwnerKey).Scan(&exists); err != nil {
					return storage(ctx)
				}
				if exists {
					operation = a.OperationKey
				}
			}
			if _, err = tx.ExecContext(ctx, `UPDATE space.creation_attempts SET state='unknown',operation_key=COALESCE(operation_key,$3),error_code=$4 WHERE source_id=$1 AND id=$2`, source, attempt, operation, safeCode(code)); err != nil {
				return storage(ctx)
			}
			if _, err = tx.ExecContext(ctx, `UPDATE space.creation_slots SET state='unknown' WHERE source_id=$1 AND policy_revision=$2 AND scheduled_for=$3 AND state='claimed'`, source, a.PolicyRevision, a.ScheduledFor); err != nil {
				return storage(ctx)
			}
		}
	}
	if err = event(ctx, tx, source, "", "creation_paused", "failed", code, now); err != nil {
		return storage(ctx)
	}
	if err = audit(ctx, tx, source, "", "creation_policy_paused", "unknown", now); err != nil {
		return storage(ctx)
	}
	return commit(tx)
}
