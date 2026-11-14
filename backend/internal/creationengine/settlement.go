package creationengine

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"icloudspace/internal/addresses"
	"icloudspace/internal/provider/apple"
	"icloudspace/internal/providersession"
)

func rateLimited(err error) bool {
	var persistence *providersession.PersistenceError
	if errors.As(err, &persistence) {
		return false
	}
	var remote *apple.Error
	return errors.As(err, &remote) && !remote.Unknown && (remote.Kind == apple.RateLimited || remote.Code == "-41015")
}

// Step owns one source lease from its durable claim through the single HME
// call and acknowledgement. Ordinary repeated callers never reclaim a slot.
func (e *Engine) Step(ctx context.Context, source int64) (Attempt, error) {
	if e == nil || source < 1 {
		return Attempt{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, e.options.OperationTimeout)
	defer cancel()
	ctx, close, err := e.enter(ctx, source)
	if err != nil {
		return Attempt{}, err
	}
	defer close()
	a, revision, err := e.claim(ctx, source)
	if err != nil {
		if errors.Is(err, ErrUnknown) {
			e.fence(ctx, source, a.ID, "claim_ack_unknown")
		}
		if errors.Is(err, ErrIneligible) || errors.Is(err, ErrCapacity) {
			e.fence(ctx, source, 0, map[bool]string{true: "capacity_reached", false: "source_ineligible"}[errors.Is(err, ErrCapacity)])
		}
		return a, err
	}
	p := e.provider(source)
	if p == nil {
		e.fence(ctx, source, a.ID, "provider_unavailable")
		return a, ErrUnresolved
	}
	op, createErr := e.creator.CreateHME(ctx, addresses.HMECreateInput{SourceID: source, RequestKey: a.OperationKey, ExpectedRevision: revision, Label: "iCloudSpace automatic", OwnerKey: a.OwnerKey, CredentialProfile: e.options.CredentialProfile}, p)
	if op.Key != "" && op.Key != a.OperationKey {
		e.fence(ctx, source, a.ID, "operation_binding_changed")
		return a, ErrUnresolved
	}
	var persistence *providersession.PersistenceError
	if errors.As(createErr, &persistence) || op.State != "confirmed" && op.State != "failed" || op.Key == "" {
		e.fence(ctx, source, a.ID, "creation_unsettled")
		result, _ := e.Attempt(context.WithoutCancel(ctx), source, a.ID)
		if result.ID > 0 {
			a = result
		}
		return a, ErrUnresolved
	}
	if op.State == "confirmed" && createErr != nil {
		e.fence(ctx, source, a.ID, "creation_ack_unknown")
		return a, ErrUnresolved
	}
	persist, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer done()
	result, err := e.finish(persist, a, op, rateLimited(createErr) || rejectedRateCode(op))
	if err != nil {
		e.fence(ctx, source, a.ID, "attempt_ack_unknown")
		return a, ErrUnknown
	}
	if err = e.releaseClaim(persist, a, false); err != nil {
		e.fence(ctx, source, a.ID, "claim_release_unknown")
		return result, ErrUnknown
	}
	e.notify()
	return result, nil
}
func (e *Engine) fence(parent context.Context, source, attempt int64, code string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	if err := e.pause(ctx, source, attempt, code); err != nil {
		// The original live claim is still the admission fence when SQL is down.
		e.options.Logger.Error("Automatic creation pause could not be acknowledged", "component", "creation", "source_id", source, "attempt_id", attempt, "phase", "creation_pause", "outcome", "unknown", "error_code", safeCode(code))
	}
}

func (e *Engine) finish(ctx context.Context, a Attempt, op addresses.Operation, cooldown bool) (Attempt, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return a, err
	}
	defer tx.Rollback()
	if _, err = readSource(ctx, tx, a.SourceID); err != nil {
		return a, err
	}
	p, err := readPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM space.creation_policies WHERE source_id=$1 FOR UPDATE`, a.SourceID))
	if err != nil {
		return a, err
	}
	current, err := readAttempt(tx.QueryRowContext(ctx, `SELECT `+attemptColumns+` FROM space.creation_attempts WHERE source_id=$1 AND id=$2 FOR UPDATE`, a.SourceID, a.ID))
	if err != nil {
		return a, err
	}
	if current.OwnerKey != a.OwnerKey || current.OperationKey != op.Key || current.ClaimedAt == nil {
		return a, ErrConflict
	}
	if current.State == "confirmed" || current.State == "not_created" {
		return current, nil
	}
	if current.State != "claimed" && current.State != "unknown" {
		return a, ErrConflict
	}
	var operationState string
	var address sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT state,address_id FROM space.address_operations WHERE source_id=$1 AND operation_key=$2 AND owner_key=$3 AND kind='create' FOR UPDATE`, a.SourceID, op.Key, a.OwnerKey).Scan(&operationState, &address); err != nil {
		return a, storage(ctx)
	}
	if operationState != op.State || operationState != "confirmed" && operationState != "failed" || operationState == "confirmed" && !address.Valid {
		return a, ErrUnresolved
	}
	now := e.options.Clock()
	state, code, phase, outcome, auditOutcome := "not_created", safeCode(op.ErrorCode), "creation_not_created", "failed", "rejected"
	lastAddress := p.LastAddress
	confirmed := p.LastConfirmedAt
	if operationState == "confirmed" {
		state, code, phase, outcome, auditOutcome = "confirmed", "", "creation_confirmed", "completed", "success"
		if err = tx.QueryRowContext(ctx, `SELECT email FROM space.private_addresses WHERE source_id=$1 AND id=$2`, a.SourceID, address.Int64).Scan(&lastAddress); err != nil {
			return a, storage(ctx)
		}
		confirmed = &now
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.creation_attempts SET state=$2,operation_key=$3,finished_at=$4,error_code=$5 WHERE id=$1`, a.ID, state, op.Key, now, code); err != nil {
		return a, storage(ctx)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.creation_slots SET state='finished' WHERE source_id=$1 AND policy_revision=$2 AND scheduled_for=$3 AND state IN ('claimed','unknown')`, a.SourceID, a.PolicyRevision, a.ScheduledFor); err != nil {
		return a, storage(ctx)
	}
	// Admission's claimed_at precedes SQL/COMMIT and provider IO. Rest from
	// this terminal observation so that those delays cannot shorten the
	// minimum interval between actual provider attempts. Keep claimed_at intact.
	if _, err = tx.ExecContext(ctx, `UPDATE space.creation_policies SET last_confirmed_at=$2,last_address=$3,last_error_detail=$4,last_attempted_at=greatest(last_attempted_at,$5::bigint),paused_reason=CASE WHEN enabled THEN paused_reason ELSE 'awaiting_enable' END,updated_at=greatest(updated_at+1,$5::bigint) WHERE source_id=$1`, a.SourceID, confirmed, lastAddress, code, now); err != nil {
		return a, storage(ctx)
	}
	if cooldown {
		first, err := add(*a.ClaimedAt, int64(RateLimitCooldown))
		if err != nil {
			return a, err
		}
		if err = e.replan(ctx, tx, p, first, now, "creation_rate_cooldown"); err != nil {
			return a, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE space.creation_policies SET cooldown_until=$2 WHERE source_id=$1`, a.SourceID, first); err != nil {
			return a, storage(ctx)
		}
	}
	if err = event(ctx, tx, a.SourceID, op.Key, phase, outcome, code, now); err != nil {
		return a, storage(ctx)
	}
	if err = audit(ctx, tx, a.SourceID, op.Key, "creation_attempt_finished", auditOutcome, now); err != nil {
		return a, storage(ctx)
	}
	if err = commit(tx); err != nil {
		return a, err
	}
	current.State = state
	current.ErrorCode = code
	current.FinishedAt = &now
	current.OperationState = operationState
	current.AddressID = nullable(address)
	return current, nil
}
func (e *Engine) releaseClaim(ctx context.Context, a Attempt, reviewed bool) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var p Policy
	if reviewed {
		if _, err = readSource(ctx, tx, a.SourceID); err != nil {
			return err
		}
		p, err = readPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM space.creation_policies WHERE source_id=$1 FOR UPDATE`, a.SourceID))
		if err != nil {
			return err
		}
		var terminal bool
		if err = tx.QueryRowContext(ctx, `SELECT state IN ('confirmed','not_created') FROM space.creation_attempts WHERE source_id=$1 AND id=$2 AND owner_key=$3 FOR UPDATE`, a.SourceID, a.ID, a.OwnerKey).Scan(&terminal); err != nil {
			return storage(ctx)
		}
		if !terminal {
			return ErrUnresolved
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM space.creation_claims c USING space.creation_attempts a WHERE c.source_id=$1 AND c.attempt_id=$2 AND c.owner_key=$3 AND a.id=c.attempt_id AND a.state IN ('confirmed','not_created')`, a.SourceID, a.ID, a.OwnerKey); err != nil {
		return storage(ctx)
	}
	if reviewed {
		blocked, err := unresolved(ctx, tx, a.SourceID)
		if err != nil {
			return err
		}
		revision := p.Revision
		if p.Enabled {
			revision, err = nextRevision(revision)
			if err != nil {
				return err
			}
		}
		reason := "awaiting_enable"
		if blocked {
			reason = "unresolved_attempt"
		}
		now := e.options.Clock()
		// Removing the original admission fence and disabling the policy are
		// one fact, even if the earlier best-effort pause could not be stored.
		if _, err = tx.ExecContext(ctx, `UPDATE space.creation_policies SET enabled=false,revision=$2,paused_reason=$3,updated_at=greatest(updated_at+1,$4) WHERE source_id=$1`, a.SourceID, revision, reason, now); err != nil {
			return storage(ctx)
		}
		if err = audit(ctx, tx, a.SourceID, a.OperationKey, "creation_attempt_reviewed", "success", now); err != nil {
			return err
		}
	}
	return commit(tx)
}

// Resolve reads the original domain operation and records a terminal fact only.
// It never calls a provider and never re-enables the paused policy.
func (e *Engine) Resolve(ctx context.Context, source, id int64) (Attempt, error) {
	ctx, close, err := e.enter(ctx, source)
	if err != nil {
		return Attempt{}, err
	}
	defer close()
	a, err := e.Attempt(ctx, source, id)
	if err != nil {
		return a, err
	}
	if a.State == "confirmed" || a.State == "not_created" {
		if err = e.releaseClaim(ctx, a, true); err != nil {
			return a, err
		}
		return a, nil
	}
	if a.OperationKey == "" || a.OperationState != "confirmed" && a.OperationState != "failed" {
		return a, ErrUnresolved
	}
	var op addresses.Operation
	var address sql.NullInt64
	err = e.db.QueryRowContext(ctx, `SELECT operation_key,source_id,address_id,state,error_code FROM space.address_operations WHERE source_id=$1 AND operation_key=$2 AND owner_key=$3 AND kind='create'`, source, a.OperationKey, a.OwnerKey).Scan(&op.Key, &op.SourceID, &address, &op.State, &op.ErrorCode)
	if err != nil {
		return a, storage(ctx)
	}
	op.AddressID = nullable(address)
	result, err := e.finish(ctx, a, op, rejectedRateCode(op))
	if err != nil {
		return a, err
	}
	if err = e.releaseClaim(ctx, a, true); err != nil {
		return result, err
	}
	return result, nil
}

func rejectedRateCode(op addresses.Operation) bool {
	return op.State == "failed" && (op.ErrorCode == "-41015" || op.ErrorCode == "rate_limited")
}
