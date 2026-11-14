package mailout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"mime"
	"strings"
	"time"
)

func (s *Service) Send(ctx context.Context, r Request) (Result, error) {
	if s == nil || r.AddressID < 1 || !validQueryKey(r.Key) {
		return Result{}, ErrInvalid
	}
	if row, e := s.submission(ctx, s.db, r.Key); e == nil {
		if row.AddressID != r.AddressID {
			return Result{}, ErrConflict
		}
		if row.QueryOnly {
			return row.Result, nil
		}
		p, e := prepareVersion(r, row.FingerprintVersion)
		if e != nil {
			return Result{}, e
		}
		return existing(row, r, p)
	} else if !errors.Is(e, ErrNotFound) {
		return Result{}, e
	}
	if !validNativeKey(r.Key) {
		return Result{}, ErrInvalid
	}
	p, e := prepare(r)
	if e != nil {
		return Result{}, e
	}
	source, e := s.sourceID(ctx, r.AddressID)
	if e != nil {
		return Result{}, e
	}
	ctx, gate, close, e := s.enter(ctx, source)
	if e != nil {
		return Result{}, e
	}
	defer close()
	// A first caller may have completed while this caller waited for the source.
	if row, e := s.submission(ctx, s.db, r.Key); e == nil {
		return existing(row, r, p)
	} else if !errors.Is(e, ErrNotFound) {
		return Result{}, e
	}
	scope, e := s.scope(ctx, source, r.AddressID, gate)
	if e != nil {
		return Result{}, e
	}
	owner, e := randomID()
	if e != nil {
		return Result{}, e
	}
	reserved, e := s.reserve(ctx, scope, r, p, owner)
	if e != nil {
		return reserved, e
	}
	pendingRoute, e := s.unresolvedRoute(ctx, s.db, scope, p.mail.To.Address, r.Key)
	if e != nil {
		return s.finish(ctx, scope, r.Key, owner, NotSent, "", "route_intent_ack_unknown")
	}
	if pendingRoute {
		return s.finish(ctx, scope, r.Key, owner, NotSent, "", "route_unknown")
	}
	rows, e := s.ensureContext(ctx, scope, "", p.mail.To.Address)
	if e != nil {
		return s.finish(ctx, scope, r.Key, owner, NotSent, "", "context_unavailable")
	}
	if e = s.submissionPhase(ctx, scope, r.Key, owner, "preparing", rows[0].ContextKey, "", nil); e != nil {
		return Result{Key: r.Key, AddressID: r.AddressID, Outcome: Unknown, State: "preparing", Code: "prepare_ack_unknown"}, ErrUnknown
	}
	op, e := s.provider.Open(ctx, scope)
	if e != nil {
		return s.finish(ctx, scope, r.Key, owner, NotSent, "", "session_unavailable")
	}
	closed := false
	closeOperation := func() error {
		if closed {
			return nil
		}
		closed = true
		return op.Close()
	}
	defer closeOperation()
	var detail *Diagnostic
	done := func(outcome Outcome, upstream, code string) (Result, error) {
		if closeOperation() != nil && code == "" {
			code = "session_persist_failed"
		}
		return s.finish(ctx, scope, r.Key, owner, outcome, upstream, code, detail)
	}
	route, e := op.ValidateRoute(ctx, p.mail.To.Address)
	if e != nil || !s.route(scope, p.mail.To.Address, route) {
		detail = diagnose("route", e)
		return done(NotSent, "", "route_rejected")
	}
	var selected contextRow
	var reference Reference
	ready := false
	for _, row := range rows {
		ref, ok, e := s.readReference(ctx, op, scope, route, row.Evidence)
		if e != nil {
			detail = diagnose("reference", e)
			return done(NotSent, "", "reference_unavailable")
		}
		if e == nil && ok {
			selected = row
			reference = ref
			ready = true
			break
		}
	}
	if !ready {
		selected = rows[0]
		// Only this fresh reserved context can receive this Send's one-time
		// preparation grant. Recovered unknowns remain read-only.
		if selected.QueryOnly || selected.State != "reserved" {
			code := "reference_pending"
			if selected.QueryOnly || selected.AppendOutcome != nil && *selected.AppendOutcome == Unknown || selected.SeedOutcome != nil && *selected.SeedOutcome == Unknown {
				code = "historical_context_unknown"
			}
			return done(NotSent, "", code)
		}
		if scope.Source.Kind != "apple_direct" || s.options.AuthorizeBootstrap == nil {
			return done(NotSent, "", "reference_pending")
		}
		status, prepareErr := s.bootstrapHeld(ctx, op, scope, route, selected, selected.State, true, func() error { return nil })
		detail = status.Diagnostic
		if prepareErr != nil && detail==nil {
			detail = diagnose("prepare", prepareErr)
		}
		selected, e = s.context(ctx, selected.ContextKey)
		if e != nil {
			return done(NotSent, "", "bootstrap_unknown")
		}
		if selected.State == "failed" {
			return done(NotSent, "", "bootstrap_rejected")
		}
		if selected.SeedOutcome == nil {
			return done(NotSent, "", "bootstrap_unknown")
		}
		route, e = op.ValidateRoute(ctx, p.mail.To.Address)
		if e != nil {
			detail = diagnose("route", e)
			return done(NotSent, "", "reference_pending")
		}
		wait, cancel := context.WithTimeout(ctx, s.options.ReferenceWait)
		defer cancel()
		for {
			if !s.fresh(route.CheckedAt) {
				route, e = op.ValidateRoute(wait, p.mail.To.Address)
				if e != nil {
					break
				}
			}
			reference, ready, e = s.readReference(wait, op, scope, route, selected.Evidence)
			if e == nil && ready {
				break
			}
			if prepareErr != nil || status.ReadOnly {
				break
			}
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-wait.Done():
				timer.Stop()
			case <-timer.C:
			}
			if wait.Err() != nil {
				break
			}
		}
		if !ready {
			code := "reference_pending"
			if *selected.SeedOutcome == Unknown {
				code = "bootstrap_unknown"
			}
			return done(NotSent, "", code)
		}
	}
	if e = s.submissionPhase(ctx, scope, r.Key, owner, "preparing", selected.ContextKey, "", nil); e != nil {
		return Result{Key: r.Key, AddressID: r.AddressID, Outcome: Unknown, State: "preparing", Code: "prepare_ack_unknown"}, ErrUnknown
	}
	if e = s.routeAttempt(ctx, scope, r.Key, owner, reference, route, nil); e != nil {
		return done(NotSent, "", "route_intent_ack_unknown")
	}
	routeReceipt, routeErr := op.ResolveRoute(ctx, route, reference)
	if !routeReceipt.Matched || routeReceipt.Outcome != Accepted && routeReceipt.Outcome != Rejected && routeReceipt.Outcome != NotSent {
		routeReceipt.Outcome = Unknown
	}
	detail = diagnose("route_registration", routeErr)
	if e = s.routeAttempt(ctx, scope, r.Key, owner, reference, route, &routeReceipt); e != nil {
		return done(NotSent, "", "route_unknown")
	}
	if routeReceipt.Outcome != Accepted {
		code := "route_rejected"
		if routeReceipt.Outcome == Unknown {
			code = "route_unknown"
		}
		return done(NotSent, "", code)
	}
	uploads := make([]Uploaded, 0, len(p.mail.Attachments))
	uploadCtx, cancelUploads := context.WithTimeout(ctx, 4*time.Minute)
	defer cancelUploads()
	finalCIDs := map[string]bool{}
	uploadIDs := map[string]bool{}
	for _, file := range p.mail.Attachments {
		if !s.fresh(route.CheckedAt) {
			route, e = op.ValidateRoute(uploadCtx, p.mail.To.Address)
			if e != nil {
				return done(NotSent, "", "route_rejected")
			}
		}
		reference, ready, e = s.readReference(uploadCtx, op, scope, route, selected.Evidence)
		if e != nil || !ready {
			return done(NotSent, "", "reference_pending")
		}
		hash := sha256.New()
		measured := &measuredReader{r: bytes.NewReader(file.Bytes), hash: hash}
		expected := sha256.Sum256(file.Bytes)
		uploaded, e := op.Upload(uploadCtx, route, reference, Upload{Filename: file.Filename, MediaType: file.MediaType, LogicalCID: file.ContentID, Inline: file.Inline, ByteSize: int64(len(file.Bytes)), SHA256: expected, Body: measured})
		if e != nil {
			detail = diagnose("upload", e)
			return done(NotSent, "", "attachment_upload_unresolved")
		}
		actual := hash.Sum(nil)
		if measured.size != int64(len(file.Bytes)) || subtle.ConstantTimeCompare(actual, expected[:]) != 1 || uploaded.ByteSize != int64(len(file.Bytes)) || uploaded.SHA256 != expected || uploaded.Filename != file.Filename || !sameMedia(uploaded.MediaType, file.MediaType) || !token(uploaded.ID, 2048) || uploadIDs[uploaded.ID] {
			return done(NotSent, "", "attachment_descriptor_rejected")
		}
		uploadIDs[uploaded.ID] = true
		if file.Inline && uploaded.ContentID == "" {
			return done(NotSent, "", "attachment_descriptor_rejected")
		}
		if uploaded.ContentID != "" {
			if !wireCID(uploaded.ContentID) || finalCIDs[uploaded.ContentID] {
				return done(NotSent, "", "attachment_descriptor_rejected")
			}
			finalCIDs[uploaded.ContentID] = true
		}
		uploaded.Inline = file.Inline
		uploaded.LogicalCID = file.ContentID
		uploads = append(uploads, uploaded)
	}
	html, e := rewriteCIDs(p.mail.Body.HTML, uploads)
	if e != nil {
		return done(NotSent, "", "attachment_cid_rejected")
	}
	rpc, e := randomID()
	if e != nil {
		return done(NotSent, "", "rpc_identity_unavailable")
	}
	// Refresh the observed route/reference after every upload. Persist the exact
	// proof used with the final intent, then reject an unexpectedly long SQL wait.
	route, e = op.ValidateRoute(ctx, p.mail.To.Address)
	if e != nil || !s.route(scope, p.mail.To.Address, route) {
		return done(NotSent, "", "route_rejected")
	}
	reference, ready, e = s.readReference(ctx, op, scope, route, selected.Evidence)
	if e != nil || !ready {
		return done(NotSent, "", "reference_pending")
	}
	if e = s.submissionPhase(ctx, scope, r.Key, owner, "submitting", selected.ContextKey, rpc, &reference); e != nil {
		return Result{Key: r.Key, AddressID: r.AddressID, Outcome: Unknown, State: "submitting", ContextKey: selected.ContextKey, RPCID: rpc, ReferenceID: reference.ID, ReferenceKind: reference.Kind, Code: "submit_intent_ack_unknown"}, ErrUnknown
	}
	if !s.fresh(reference.CheckedAt) || !s.fresh(route.CheckedAt) || ctx.Err() != nil {
		return done(NotSent, "", "reference_expired")
	}
	receipt, sendErr := op.Submit(ctx, Submission{Key: r.Key, OwnerKey: owner, RPCID: rpc, Route: route, Reference: reference, Recipient: p.mail.To.Address, Subject: p.mail.Subject, Text: p.mail.Body.Text, HTML: html, Attachments: append([]Uploaded(nil), uploads...)})
	outcome := Unknown
	code := "submission_unknown"
	upstream := ""
	if receipt.Outcome == NotSent {
		outcome = NotSent
		code = "provider_not_sent"
	}
	if receipt.Matched && receipt.RPCID == rpc {
		switch receipt.Outcome {
		case Accepted:
			if receipt.UpstreamID == "" || token(receipt.UpstreamID, 2048) {
				outcome = Accepted
				code = ""
				upstream = receipt.UpstreamID
			}
		case Rejected:
			outcome = Rejected
			code = "provider_rejected"
		case NotSent:
			outcome = NotSent
			code = "provider_not_sent"
		}
	}
	// A definite matched RPC result survives subsequent session/storage errors.
	detail = diagnose("submit", sendErr)
	return done(outcome, upstream, code)
}
func sameMedia(a, b string) bool {
	x, _, e := mime.ParseMediaType(a)
	if e != nil {
		return false
	}
	y, _, e := mime.ParseMediaType(b)
	return e == nil && strings.EqualFold(x, y)
}
