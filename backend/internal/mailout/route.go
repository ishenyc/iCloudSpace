package mailout

import (
	"context"
	"encoding/json"
	"errors"
	"icloudspace/internal/vault"
	"regexp"
	"time"
)

var diagnosticToken = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func safeDiagnostic(d Diagnostic) bool {
	for _, value := range []string{d.Kind, d.ProviderCode, d.Operation, d.TransportPhase, d.TransportReason} {
		if value != "" && !diagnosticToken.MatchString(value) {
			return false
		}
	}
	return diagnosticToken.MatchString(d.Stage) && d.HTTPStatus >= 0 && d.HTTPStatus <= 599 && d.Attempts >= 0 && d.Attempts <= 3
}
func diagnose(stage string, err error) *Diagnostic {
	if err == nil {
		return nil
	}
	d := &Diagnostic{Stage: stage, Kind: "unavailable"}
	var safe interface{ SafeDiagnostic() (string, int, string) }
	if errors.As(err, &safe) {
		d.Kind, d.HTTPStatus, d.ProviderCode = safe.SafeDiagnostic()
	}
	var transport interface {
		SafeTransportDiagnostic() (string, int, string, string)
	}
	if errors.As(err, &transport) {
		d.Operation, d.Attempts, d.TransportPhase, d.TransportReason = transport.SafeTransportDiagnostic()
	}
	if !safeDiagnostic(*d) {
		return &Diagnostic{Stage: stage, Kind: "unavailable"}
	}
	return d
}
func retryable(r Result) bool {
	return r.Durable && !r.QueryOnly && r.State == "finished" && (r.Outcome == NotSent || r.Outcome == Rejected) && (r.RouteOutcome == nil || *r.RouteOutcome != Unknown) && r.Code != "bootstrap_unknown" && r.Code != "historical_context_unknown" && r.Code != "route_unknown" && r.Code != "route_intent_ack_unknown"
}

// A credential/session revision does not settle a previous registration for
// this same selected address and recipient. Keep its original sealed identity
// and request, even if the next Send would choose a different context hash.
func (s *Service) unresolvedRoute(ctx context.Context, q rowQuery, scope Scope, recipient, key string) (bool, error) {
	var pending bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.send_submissions s JOIN space.compose_contexts c ON c.context_key=s.context_key AND c.source_id=s.source_id AND c.address_id=s.address_id WHERE s.source_id=$1 AND s.address_id=$2 AND lower(btrim(c.route_recipient))=lower(btrim($3::text)) AND s.route_outcome='unknown' AND s.request_key<>$4)`, scope.Source.ID, scope.Address.ID, recipient, key).Scan(&pending)
	if err != nil {
		return false, storage(ctx)
	}
	return pending, nil
}

func (s *Service) routeAttempt(ctx context.Context, scope Scope, key, owner string, reference Reference, route Route, receipt *RouteReceipt) error {
	if receipt != nil {
		persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		ctx = persist
	}
	outcome := Unknown
	if receipt != nil {
		outcome = receipt.Outcome
	}
	doc := struct {
		Version    int
		Key, Owner string
		Source     Source
		Address    Address
		Reference  Reference
		Route      Route
		Outcome    Outcome
	}{1, key, owner, scope.Source, scope.Address, reference, route, outcome}
	raw, err := json.Marshal(doc)
	if err != nil {
		return ErrStorage
	}
	defer clear(raw)
	envelope, err := s.box.Seal(vault.Binding{InstallationID: s.installation, SubjectType: "send_submission", SubjectID: key, Purpose: "mail_route", Revision: 1}, raw)
	if err != nil {
		return ErrStorage
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storage(ctx)
	}
	defer tx.Rollback()
	if err = s.writable(ctx, tx); err != nil {
		return err
	}
	if receipt == nil {
		pending, err := s.unresolvedRoute(ctx, tx, scope, route.Recipient, key)
		if err != nil {
			return err
		}
		if pending {
			return ErrUnknown
		}
	}
	condition := "route_outcome IS NULL"
	if receipt != nil {
		condition = "route_outcome='unknown'"
	}
	result, err := tx.ExecContext(ctx, `UPDATE space.send_submissions SET route_outcome=$3,route_envelope=$4,updated_at=$5 WHERE request_key=$1 AND owner_key=$2 AND NOT query_only AND state='preparing' AND `+condition, key, owner, string(outcome), []byte(envelope), s.options.Clock())
	if err != nil {
		return ErrConflict
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrConflict
	}
	if s.commit(tx) != nil {
		return ErrUnknown
	}
	return nil
}
