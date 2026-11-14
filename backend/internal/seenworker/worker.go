package seenworker

import (
	"context"
	"errors"
)

func queryCode(j job, fallback string) string {
	if j.State == "claimed" && j.LastError != "" {
		return j.LastError
	}
	return fallback
}

func (s *Service) deferred(ctx context.Context, j job, code string, pending bool, result *Result) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	e := s.deferJob(ctx, j, code, pending)
	if errors.Is(e, ErrStale) {
		return nil
	}
	if e != nil {
		return e
	}
	result.Deferred++
	return nil
}
func (s *Service) process(ctx context.Context, original job, result *Result) error {
	ctx, cancelWork := context.WithTimeout(ctx, s.sourceBudget)
	defer cancelWork()
	admission, cancelAdmission := context.WithTimeout(ctx, s.admissionBudget)
	gate, e := s.guards.Acquire(admission, original.SourceID)
	if e != nil {
		cancelAdmission()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errAdmissionUnavailable
	}
	defer gate.Close()
	permit, e := s.slots.Acquire(admission, gate)
	cancelAdmission()
	if e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errAdmissionUnavailable
	}
	defer permit.Close()
	// Both the source gate and shared global slot may have waited. Everything
	// concerning credentials/source generation/job ownership is read afterward.
	source, j, e := s.load(ctx, original)
	if e != nil {
		switch {
		case errors.Is(e, ErrDisabled):
			return s.deferred(ctx, original, queryCode(original, "source_disabled"), false, result)
		case errors.Is(e, ErrStale):
			return s.deferred(ctx, original, queryCode(original, "scope_changed"), false, result)
		case errors.Is(e, ErrCredentials):
			return s.deferred(ctx, original, queryCode(original, "credentials_unavailable"), false, result)
		case errors.Is(e, ErrUnknown):
			result.Unknown++
			return nil
		default:
			return e
		}
	}
	connection, e := s.open(ctx, OpenRequest{Gate: gate, Permit: permit, Source: source, Identity: j.Identity, QueryOnly: j.State == "claimed"})
	if e != nil {
		if errors.Is(e, ErrStale) {
			return s.deferred(ctx, j, queryCode(j, "uid_validity_changed"), false, result)
		}
		return s.deferred(ctx, j, queryCode(j, "connect_failed"), false, result)
	}
	if connection == nil {
		return s.deferred(ctx, j, queryCode(j, "connect_failed"), false, result)
	}
	defer connection.Close()
	if connection.UIDValidity() != j.UIDValidity {
		return s.deferred(ctx, j, queryCode(j, "uid_validity_changed"), false, result)
	}
	flags, e := connection.Flags(ctx, j.UID)
	if e != nil {
		return s.deferred(ctx, j, queryCode(j, "flags_query_failed"), false, result)
	}
	if !flags.Exists || flags.Seen {
		e = s.complete(ctx, source, j)
		if errors.Is(e, ErrUnknown) {
			result.Unknown++
			return nil
		}
		if errors.Is(e, ErrStale) || errors.Is(e, ErrDisabled) {
			return s.deferred(ctx, j, "scope_changed", false, result)
		}
		if e != nil {
			return e
		}
		result.Completed++
		return nil
	}
	if j.State == "claimed" {
		// Imported/in-flight/lost-ACK claims are observation-only forever. A
		// currently Unseen message is not proof that a previous STORE was unsent.
		return s.deferred(ctx, j, queryCode(j, "unconfirmed_unseen"), false, result)
	}
	claimed, e := s.claim(ctx, source, j)
	if errors.Is(e, ErrUnknown) {
		result.Unknown++
		return nil
	}
	if errors.Is(e, ErrStale) || errors.Is(e, ErrDisabled) {
		return s.deferred(ctx, j, "scope_changed", false, result)
	}
	if errors.Is(e, ErrInvalid) {
		return s.deferred(ctx, j, "attempt_limit", false, result)
	}
	if e != nil {
		return e
	}
	j = claimed
	result.Claimed++
	outcome, storeErr := connection.StoreSeen(ctx, j.UID)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if outcome == Accepted && storeErr == nil {
		result.Stored++
		e = s.complete(ctx, source, j)
		if errors.Is(e, ErrUnknown) {
			result.Unknown++
			return nil
		}
		if errors.Is(e, ErrStale) || errors.Is(e, ErrDisabled) {
			return s.deferred(ctx, j, "scope_changed", false, result)
		}
		if e != nil {
			return e
		}
		result.Completed++
		return nil
	}
	switch outcome {
	case NotSent:
		return s.deferred(ctx, j, "before_write_failed", true, result)
	case Rejected:
		result.Rejected++
		return s.deferred(ctx, j, "store_rejected", false, result)
	default:
		result.Unknown++
		return s.deferred(ctx, j, "store_unknown", false, result)
	}
}
