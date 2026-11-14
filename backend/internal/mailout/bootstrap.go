package mailout

import (
	"context"
	"icloudspace/internal/content"
	"time"
)

func recipient(raw string) (string, error) {
	p, e := content.Prepare(content.Draft{Recipient: raw, Body: content.Body{Format: content.BodyText}})
	if e != nil {
		return "", ErrInvalid
	}
	return p.To.Address, nil
}

// PrepareContext performs explicit reference preparation for an owned request.
// Management performs preparation within Send using the held helper below;
// queries never grant another APPEND or Seed attempt.
func (s *Service) PrepareContext(ctx context.Context, r ContextRequest) (result ContextStatus, retErr error) {
	if r.AddressID < 1 || !validQueryKey(r.Key) {
		return ContextStatus{}, ErrInvalid
	}
	to, e := recipient(r.Recipient)
	if e != nil {
		return ContextStatus{}, e
	}
	source, e := s.sourceID(ctx, r.AddressID)
	if e != nil {
		return ContextStatus{}, e
	}
	ctx, gate, close, e := s.enter(ctx, source)
	if e != nil {
		return ContextStatus{}, e
	}
	defer close()
	scope, e := s.scope(ctx, source, r.AddressID, gate)
	if e != nil {
		return ContextStatus{}, e
	}
	rows, e := s.ensureContext(ctx, scope, r.Key, to)
	if e != nil {
		return ContextStatus{}, e
	}
	selected := rows[0]
	bound := false
	bind := func() error {
		if bound {
			return nil
		}
		bound = true
		return s.bindContextRequest(ctx, scope, r.Key, selected)
	}
	defer func() {
		if e := bind(); e != nil {
			result = ContextStatus{}
			retErr = e
		}
	}()
	initialState := rows[0].State
	op, e := s.provider.Open(ctx, scope)
	if e != nil {
		return contextStatus(rows[0]), ErrProvider
	}
	defer func() {
		if op.Close() != nil {
			result.Code = "session_persist_failed"
			if retErr == nil {
				retErr = ErrUnknown
			}
		}
	}()
	route, e := op.ValidateRoute(ctx, to)
	if e != nil || !s.route(scope, to, route) {
		return contextStatus(rows[0]), ErrProvider
	}
	for i := range rows {
		status, e := s.refreshContext(ctx, op, scope, route, &rows[i])
		if e != nil {
			selected = rows[i]
			return status, e
		}
		if status.Ready {
			selected = rows[i]
			return status, nil
		}
	}
	return s.bootstrapHeld(ctx, op, scope, route, rows[0], initialState, r.Bootstrap, bind)
}

// bootstrapHeld uses the caller's original source lease and provider session.
// It is invoked inside the new Send, never by a result-query operation.
func (s *Service) bootstrapHeld(ctx context.Context, op Operation, scope Scope, route Route, row contextRow, initialState string, authorized bool, bind func() error) (ContextStatus, error) {
	status := contextStatus(row)
	status.Code = "reference_pending"
	if initialState == "candidate_unknown" || initialState == "preparing" || initialState == "seed_unknown" {
		return status, nil
	}
	if !authorized || row.QueryOnly || scope.Source.Kind != "apple_direct" {
		return status, nil
	}
	if row.State != "reserved" && row.State != "draft_ready" {
		return status, nil
	}
	if e := bind(); e != nil {
		return ContextStatus{}, e
	}
	doc, e := s.openContext(row)
	if e != nil {
		return status, e
	}
	// Display labels/groups may advance generic metadata revisions while the
	// reserved, immutable envelope still names this exact mailbox and HME.
	// Current provider ownership is re-proved above; never replace its nonce.
	if doc.Source.ID != scope.Source.ID || doc.Address.ID != scope.Address.ID || !sameAddress(doc.Plan.Draft.From, scope.Source.PrimaryAddress) || !sameAddress(doc.Plan.Draft.To, scope.Address.Email) || !sameAddress(doc.Plan.Draft.ReplyTo, row.Recipient) {
		return status, ErrConflict
	}
	if row.State == "reserved" {
		if s.options.AuthorizeBootstrap == nil {
			return status, ErrBudget
		}
		if e = s.options.AuthorizeBootstrap(ctx, scope, row.ContextKey, AppendStage); e != nil {
			return status, e
		}
		unknown := Unknown
		row.AppendOutcome = &unknown
		if e = s.writeContext(ctx, &row, doc, "candidate_unknown", ""); e != nil {
			return contextStatus(row), e
		}
		appendPlan := doc.Plan
		appendPlan.RPCID = row.Nonce
		receipt, appendErr := op.AppendDraft(ctx, route, appendPlan)
		doc.Diagnostic = diagnose("append", appendErr)
		observed := Unknown
		if receipt.Outcome == NotSent {
			observed = NotSent
		} else if receipt.Matched && (receipt.Outcome == Accepted || receipt.Outcome == Rejected) {
			observed = receipt.Outcome
		}
		row.AppendOutcome = &observed
		if observed == Rejected || observed == NotSent {
			if e = s.writeContext(ctx, &row, doc, "failed", "append_rejected"); e != nil {
				return contextStatus(row), e
			}
			return contextStatus(row), nil
		}
		if receipt.Matched && validCandidate(receipt.Candidate, row.Evidence) {
			row.CandidateID = receipt.Candidate.ID
			row.CandidateMessageID = receipt.Candidate.MessageID
			row.CandidateUIDValidity = receipt.Candidate.UIDValidity
		}
		if e = s.writeContext(ctx, &row, doc, "candidate_unknown", ""); e != nil {
			return contextStatus(row), e
		}
		route, e = op.ValidateRoute(ctx, row.Recipient)
		if e != nil || !s.route(scope, row.Recipient, route) {
			return contextStatus(row), ErrReference
		}
		wait, cancel := context.WithTimeout(ctx, min(s.options.ReferenceWait, 25*time.Second))
		defer cancel()
		candidate, found, e := op.FindCandidate(wait, route, row.Evidence)
		if observed == Accepted && (e != nil || !found) {
			for !found && wait.Err() == nil {
				timer := time.NewTimer(2 * time.Second)
				select {
				case <-wait.Done():
					timer.Stop()
				case <-timer.C:
				}
				if wait.Err() != nil {
					break
				}
				if !s.fresh(route.CheckedAt) {
					route, e = op.ValidateRoute(wait, row.Recipient)
					if e != nil {
						break
					}
				}
				candidate, found, e = op.FindCandidate(wait, route, row.Evidence)
			}
		}
		if e != nil || !found {
			doc.Diagnostic = diagnose("draft_read", e)
			if writeErr := s.writeContext(ctx, &row, doc, "candidate_unknown", "draft_not_visible"); writeErr != nil {
				return contextStatus(row), writeErr
			}
			return contextStatus(row), nil
		}
		if !validCandidate(candidate, row.Evidence) {
			return contextStatus(row), ErrProvider
		}
		row.CandidateID = candidate.ID
		row.CandidateMessageID = candidate.MessageID
		row.CandidateUIDValidity = candidate.UIDValidity
		doc.CandidateConfirmed = true
		doc.Candidate = &candidate
		if e = s.writeContext(ctx, &row, doc, "draft_ready", ""); e != nil {
			return contextStatus(row), e
		}
		if observed == Unknown {
			return contextStatus(row), nil
		}
	}
	if row.SeedOutcome != nil {
		return contextStatus(row), nil
	}
	if doc.Candidate == nil || !validCandidate(*doc.Candidate, row.Evidence) {
		return contextStatus(row), ErrReference
	}
	if s.options.AuthorizeBootstrap == nil {
		return contextStatus(row), ErrBudget
	}
	if e = s.options.AuthorizeBootstrap(ctx, scope, row.ContextKey, SeedStage); e != nil {
		return contextStatus(row), e
	}
	seedPlan := doc.Plan
	candidate := *doc.Candidate
	route, e = op.ValidateRoute(ctx, row.Recipient)
	if e != nil || !s.route(scope, row.Recipient, route) {
		if e==nil {e=ErrProvider}
		status:=contextStatus(row)
		status.Diagnostic=diagnose("seed_route",e)
		return status,e
	}
	unknown := Unknown
	row.SeedOutcome = &unknown
	if e = s.writeContext(ctx, &row, doc, "seed_unknown", ""); e != nil {
		return contextStatus(row), e
	}
	receipt, seedErr := op.SubmitSeed(ctx, route, candidate, seedPlan)
	doc.Diagnostic = diagnose("seed", seedErr)
	observed := Unknown
	if receipt.Outcome == NotSent {
		observed = NotSent
	}
	if receipt.Matched && receipt.RPCID == doc.Plan.RPCID {
		if receipt.ObservedMessageID != "" {
			if !token(receipt.ObservedMessageID, 2048) {
				return contextStatus(row), ErrProvider
			}
			row.SeedMessageID = receipt.ObservedMessageID
		}
		switch receipt.Outcome {
		case Accepted:
			observed = Accepted
			row.SeedID = receipt.UpstreamID
		case Rejected:
			observed = Rejected
		case NotSent:
			observed = NotSent
		}
	}
	row.SeedOutcome = &observed
	state := "seed_unknown"
	if observed == Rejected || observed == NotSent {
		state = "failed"
	}
	if e = s.writeContext(ctx, &row, doc, state, ""); e != nil {
		return contextStatus(row), e
	}
	status,readErr:=s.refreshContext(ctx,op,scope,route,&row)
	if readErr!=nil && status.Diagnostic==nil {status.Diagnostic=diagnose("reference",readErr)}
	return status,readErr
}
