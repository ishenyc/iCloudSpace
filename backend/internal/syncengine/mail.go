package syncengine

import (
	"context"
	"errors"

	"icloudspace/internal/accounts"
	"icloudspace/internal/intake"
	upstream "icloudspace/internal/provider/imap"
	"icloudspace/internal/rounds"
)

func frontier(c intake.Cursor) *rounds.MailFrontier {
	return &rounds.MailFrontier{UIDValidity: c.UIDValidity, CapturedUpper: c.Observed, Committed: c.Committed}
}
func backfill(b *intake.Backfill) *rounds.BackfillFrontier {
	if b == nil {
		return nil
	}
	return &rounds.BackfillFrontier{AddressID: b.AddressID, ScanEpoch: b.ScanEpoch, UIDValidity: b.UIDValidity, CapturedUpper: b.Upper, Committed: b.Committed}
}
func counters(result intake.Result) rounds.Counters {
	return rounds.Counters{Discovered: int64(result.Messages), Archived: int64(result.Publications), Links: int64(result.Links), Bytes: result.Bytes}
}
func sameSource(metadata accounts.Metadata, s intake.Source) bool {
	return metadata.ID == s.ID && metadata.Revision == s.Revision && metadata.SourceGeneration == s.Generation && metadata.CredentialGeneration == s.CredentialGeneration && metadata.Enabled == s.Enabled && string(metadata.Kind) == s.Kind && metadata.AddressNamespace == s.Namespace && metadata.Endpoint.Host == s.Host && metadata.Endpoint.Port == int(s.Port) && metadata.Endpoint.Username == s.Username
}

func (e *Executor) mail(ctx context.Context, in rounds.StepInput, metadata accounts.Metadata, settings Settings) (rounds.StepResult, error) {
	key, err := e.config.Intake.PendingBatch(ctx, in.Gate, metadata.ID)
	if err != nil {
		return providerFailure(err, "intake_receipt")
	}
	if key != "" {
		return e.resolve(ctx, in, settings, key)
	}
	after := e.pendingAfter(in.Source.Scope)
	snapshot, err := e.config.Intake.LoadSnapshot(ctx, in.Gate, metadata.ID, settings.Mailbox, after)
	if err != nil {
		return providerFailure(err, "intake_snapshot")
	}
	if !sameSource(metadata, snapshot.Source) {
		return failed(rounds.ErrStale, "source_changed", false, false)
	}
	if in.Frontier != nil {
		f := in.Frontier
		if !snapshot.Cursor.Exists || snapshot.Cursor.UIDValidity != f.UIDValidity || snapshot.Cursor.Observed != f.CapturedUpper || snapshot.Cursor.Committed < f.Committed {
			return failed(rounds.ErrStale, "mail_frontier_changed", false, false)
		}
		if f.Committed == f.CapturedUpper {
			return e.history(ctx, in, metadata, settings, snapshot)
		}
	}
	return e.run(ctx, in, metadata, settings, snapshot)
}
func (e *Executor) run(ctx context.Context, in rounds.StepInput, metadata accounts.Metadata, settings Settings, snapshot intake.Snapshot) (rounds.StepResult, error) {
	revealed, err := e.config.Accounts.Reveal(ctx, metadata.ID)
	if err != nil {
		return providerFailure(err, "source_credentials")
	}
	if !sameSource(revealed.Source, snapshot.Source) {
		return failed(rounds.ErrStale, "source_changed", false, false)
	}
	if _, _, err = e.current(ctx, in); err != nil {
		return sourceFailure(err)
	}
	endpoint := upstream.Endpoint{Host: metadata.Endpoint.Host, Port: uint16(metadata.Endpoint.Port), Username: metadata.Endpoint.Username, Password: revealed.Credentials.IMAPPassword}
	upper := uint32(0)
	if snapshot.Backfill != nil {
		upper = snapshot.Backfill.Upper
	} else if in.Frontier != nil {
		upper = in.Frontier.CapturedUpper
	}
	result, err := e.config.Pipeline.Run(ctx, intake.InputSnapshot{Gate: in.Gate, Snapshot: snapshot, Endpoint: endpoint, CapturedUpper: upper})
	if err != nil {
		if result.BatchKey != "" {
			lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.config.RecoveryTimeout)
			pending, pendingErr := e.config.Intake.PendingBatch(lookup, in.Gate, metadata.ID)
			cancel()
			if pendingErr == nil && pending != "" {
				return e.resolve(ctx, in, settings, pending)
			}
		}
		if result.BatchKey != "" && (errors.Is(err, intake.ErrUnknown) || errors.Is(err, intake.ErrUnresolved)) {
			return e.resolve(ctx, in, settings, result.BatchKey)
		}
		if errors.Is(err, intake.ErrStale) {
			if _, _, changed := e.current(ctx, in); changed != nil {
				return sourceFailure(changed)
			}
			return failed(err, "mail_snapshot_changed", true, false)
		}
		return providerFailure(err, "mail")
	}
	e.remember(in.Source.Scope, result.PendingAfter)
	if snapshot.Backfill != nil {
		f := frontier(snapshot.Cursor)
		f.Backfill = backfill(snapshot.Backfill)
		f.Backfill.Committed = result.Through
		if result.Complete {
			next, err := e.nextBackfill(ctx, in.Source.Scope, settings.Mailbox, f, f.Backfill)
			if err != nil {
				return providerFailure(err, "backfill_catalog")
			}
			if next == nil {
				return rounds.StepResult{State: rounds.StepComplete, Frontier: f, Counters: counters(result)}, nil
			}
			if in.Frontier.Backfill != nil && in.Frontier.Backfill.Committed == in.Frontier.Backfill.CapturedUpper {
				f.Backfill = backfill(next)
			}
		}
		return rounds.StepResult{State: rounds.StepPending, Frontier: f, Counters: counters(result)}, nil
	}
	current, err := e.cursor(ctx, in.Source.Scope, settings.Mailbox)
	if err != nil {
		return providerFailure(err, "mail_frontier")
	}
	if !current.Exists || current.Committed != result.Through || current.Observed != result.CapturedUpper {
		return failed(intake.ErrUnresolved, "mail_frontier_unknown", false, true)
	}
	f := frontier(current)
	if !result.Complete {
		return rounds.StepResult{State: rounds.StepPending, Frontier: f, Counters: counters(result)}, nil
	}
	return e.afterLive(ctx, in, settings, f, counters(result))
}
func (e *Executor) afterLive(ctx context.Context, in rounds.StepInput, settings Settings, f *rounds.MailFrontier, count rounds.Counters) (rounds.StepResult, error) {
	if err := e.prepareBackfills(ctx, in, settings.Mailbox, f); err != nil {
		return providerFailure(err, "backfill_prepare")
	}
	next, err := e.nextBackfill(ctx, in.Source.Scope, settings.Mailbox, f, nil)
	if err != nil {
		return providerFailure(err, "backfill_catalog")
	}
	if next == nil {
		return rounds.StepResult{State: rounds.StepComplete, Frontier: f, Counters: count}, nil
	}
	f.Backfill = backfill(next)
	return rounds.StepResult{State: rounds.StepPending, Frontier: f, Counters: count}, nil
}
func (e *Executor) history(ctx context.Context, in rounds.StepInput, metadata accounts.Metadata, settings Settings, snapshot intake.Snapshot) (rounds.StepResult, error) {
	f := in.Frontier
	if f.Backfill == nil {
		return failed(ErrInvalid, "invalid_backfill_continuation", false, false)
	}
	loaded, err := e.config.Intake.LoadBackfill(ctx, in.Gate, snapshot, f.Backfill.AddressID)
	if err == nil && loaded.Backfill.ScanEpoch == f.Backfill.ScanEpoch && loaded.Backfill.UIDValidity == f.Backfill.UIDValidity && loaded.Backfill.Upper == f.Backfill.CapturedUpper && loaded.Backfill.Committed >= f.Backfill.Committed {
		return e.run(ctx, in, metadata, settings, loaded)
	}
	if f.Backfill.Committed != f.Backfill.CapturedUpper {
		return failed(rounds.ErrStale, "backfill_changed", false, false)
	}
	next, err := e.nextBackfill(ctx, in.Source.Scope, settings.Mailbox, f, f.Backfill)
	if err != nil {
		return providerFailure(err, "backfill_catalog")
	}
	if next == nil {
		return rounds.StepResult{State: rounds.StepComplete, Frontier: frontier(snapshot.Cursor)}, nil
	}
	loaded, err = e.config.Intake.LoadBackfill(ctx, in.Gate, snapshot, next.AddressID)
	if err != nil {
		return providerFailure(err, "backfill_snapshot")
	}
	return e.run(ctx, in, metadata, settings, loaded)
}
func (e *Executor) resolve(ctx context.Context, in rounds.StepInput, settings Settings, key string) (rounds.StepResult, error) {
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.config.RecoveryTimeout)
	defer cancel()
	resolution, result, err := e.config.Intake.ResolveBatch(recovery, in.Gate, key)
	if err != nil || resolution != intake.Committed {
		return failed(errors.Join(ErrRecoveryRequired, err), "intake_recovery_required", false, true)
	}
	if _, _, err = e.current(recovery, in); err != nil {
		return sourceFailure(err)
	}
	snapshot, err := e.config.Intake.LoadSnapshot(recovery, in.Gate, in.Source.Scope.SourceID, settings.Mailbox, e.pendingAfter(in.Source.Scope))
	if err != nil {
		return providerFailure(err, "intake_snapshot")
	}
	if !snapshot.Cursor.Exists {
		return failed(intake.ErrUnresolved, "mail_frontier_unknown", false, true)
	}
	f := frontier(snapshot.Cursor)
	if f.Committed < f.CapturedUpper {
		return rounds.StepResult{State: rounds.StepPending, Frontier: f, Counters: counters(result)}, nil
	}
	if in.Frontier != nil && in.Frontier.Backfill != nil {
		old := in.Frontier.Backfill
		var b intake.Backfill
		b.AddressID = old.AddressID
		err = e.config.Intake.DB.QueryRowContext(recovery, `SELECT scan_epoch,uid_validity,lower_uid,captured_upper_uid,committed_uid,state FROM space.address_backfills WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3 AND address_id=$4 AND scan_epoch=$5`, in.Source.Scope.SourceID, in.Source.Scope.Generation, settings.Mailbox, old.AddressID, old.ScanEpoch).Scan(&b.ScanEpoch, &b.UIDValidity, &b.Lower, &b.Upper, &b.Committed, &b.State)
		if err != nil || b.State == "cancelled" {
			return failed(rounds.ErrStale, "backfill_changed", false, false)
		}
		f.Backfill = backfill(&b)
		if b.Committed < b.Upper {
			return rounds.StepResult{State: rounds.StepPending, Frontier: f, Counters: counters(result)}, nil
		}
		next, e2 := e.nextBackfill(recovery, in.Source.Scope, settings.Mailbox, f, f.Backfill)
		if e2 != nil {
			return providerFailure(e2, "backfill_catalog")
		}
		if next != nil {
			return rounds.StepResult{State: rounds.StepPending, Frontier: f, Counters: counters(result)}, nil
		}
		return rounds.StepResult{State: rounds.StepComplete, Frontier: f, Counters: counters(result)}, nil
	}
	return e.afterLive(recovery, in, settings, f, counters(result))
}
