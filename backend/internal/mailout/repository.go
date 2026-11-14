package mailout

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type submissionRow struct {
	Result
	sourceID    int64
	owner       string
	fingerprint []byte
}
type rowQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Service) submission(ctx context.Context, q rowQuery, key string) (submissionRow, error) {
	var out submissionRow
	var upstream, contextKey, rpc, reference, referenceKind, route sql.NullString
	var detail string
	e := q.QueryRowContext(ctx, `SELECT request_key,source_id,address_id,fingerprint_version,fingerprint,query_only,owner_key,state,outcome,upstream_id,error_code,context_key,rpc_id,reference_id,reference_kind,route_outcome,error_detail FROM space.send_submissions WHERE request_key=$1`, key).Scan(&out.Key, &out.sourceID, &out.AddressID, &out.FingerprintVersion, &out.fingerprint, &out.QueryOnly, &out.owner, &out.State, &out.Outcome, &upstream, &out.Code, &contextKey, &rpc, &reference, &referenceKind, &route, &detail)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, storage(ctx)
	}
	out.UpstreamID = upstream.String
	out.ContextKey = contextKey.String
	out.RPCID = rpc.String
	out.ReferenceID = reference.String
	out.ReferenceKind = ReferenceKind(referenceKind.String)
	out.Durable = true
	if route.Valid {
		v := Outcome(route.String)
		out.RouteOutcome = &v
	}
	var diagnostic Diagnostic
	if json.Unmarshal([]byte(detail), &diagnostic) == nil && safeDiagnostic(diagnostic) {
		out.Diagnostic = &diagnostic
	}
	out.Retryable = retryable(out.Result)
	return out, nil
}
func existing(row submissionRow, r Request, p *prepared) (Result, error) {
	if row.AddressID != r.AddressID {
		return Result{}, ErrConflict
	}
	if row.QueryOnly {
		return row.Result, nil
	}
	if p == nil || row.FingerprintVersion != p.version || len(row.fingerprint) != 32 || subtle.ConstantTimeCompare(row.fingerprint, p.fingerprint[:]) != 1 {
		return Result{}, ErrConflict
	}
	return row.Result, nil
}
func (s *Service) Query(ctx context.Context, address int64, key string) (Result, error) {
	if address < 1 || !validQueryKey(key) {
		return Result{}, ErrInvalid
	}
	row, e := s.submission(ctx, s.db, key)
	if e != nil {
		return Result{}, e
	}
	if row.AddressID != address {
		return Result{}, ErrNotFound
	}
	return row.Result, nil
}
func (s *Service) reserve(ctx context.Context, scope Scope, r Request, p *prepared, owner string) (Result, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Result{}, storage(ctx)
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return Result{}, e
	}
	current, e := s.loadScope(ctx, tx, scope.Source.ID, scope.Address.ID, scope.Gate)
	if e != nil {
		return Result{}, e
	}
	if current.Source != scope.Source || current.Address != scope.Address {
		return Result{}, ErrConflict
	}
	now := s.options.Clock()
	_, e = tx.ExecContext(ctx, `INSERT INTO space.send_submissions(request_key,source_id,address_id,fingerprint_version,fingerprint,query_only,owner_key,state,outcome,error_code,error_detail,created_at,updated_at) VALUES($1,$2,$3,$4,$5,false,$6,'reserved','unknown','','',$7,$7)`, r.Key, scope.Source.ID, r.AddressID, FingerprintVersion, p.fingerprint[:], owner, now)
	if e != nil {
		return Result{}, ErrConflict
	}
	result := Result{Key: r.Key, AddressID: r.AddressID, State: "reserved", Outcome: Unknown, FingerprintVersion: FingerprintVersion}
	if s.commit(tx) != nil {
		return result, ErrUnknown
	}
	result.Durable = true
	return result, nil
}
func (s *Service) submissionPhase(ctx context.Context, scope Scope, key, owner, state, contextKey, rpc string, reference *Reference) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return storage(ctx)
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return e
	}
	current, e := s.loadScope(ctx, tx, scope.Source.ID, scope.Address.ID, scope.Gate)
	if e != nil {
		return e
	}
	if current.Source != scope.Source || current.Address != scope.Address {
		return ErrConflict
	}
	var contextValue, rpcValue any
	var referenceValue, kindValue any
	if reference != nil {
		referenceValue = reference.ID
		kindValue = string(reference.Kind)
	}
	if contextKey != "" {
		contextValue = contextKey
	}
	if rpc != "" {
		rpcValue = rpc
	}
	r, e := tx.ExecContext(ctx, `UPDATE space.send_submissions SET state=$3,context_key=$4,rpc_id=$5,updated_at=$6,reference_id=$7,reference_kind=$8 WHERE request_key=$1 AND owner_key=$2 AND NOT query_only AND state IN ('reserved','preparing') AND outcome='unknown'`, key, owner, state, contextValue, rpcValue, s.options.Clock(), referenceValue, kindValue)
	if e != nil {
		return storage(ctx)
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return ErrConflict
	}
	if s.commit(tx) != nil {
		return ErrUnknown
	}
	return nil
}
func (s *Service) finish(ctx context.Context, scope Scope, key, owner string, outcome Outcome, upstream, code string, diagnostic ...*Diagnostic) (Result, error) {
	ctx,cancel:=context.WithTimeout(context.WithoutCancel(ctx),5*time.Second)
	defer cancel()
	result := Result{Key: key, AddressID: scope.Address.ID, State: "finished", Outcome: outcome, UpstreamID: upstream, Code: code, FingerprintVersion: FingerprintVersion}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, ErrUnknown
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return result, ErrUnknown
	}
	var contextKey, rpc, reference, referenceKind sql.NullString
	e = tx.QueryRowContext(ctx, `SELECT context_key,rpc_id,reference_id,reference_kind FROM space.send_submissions WHERE request_key=$1 AND owner_key=$2 FOR UPDATE`, key, owner).Scan(&contextKey, &rpc, &reference, &referenceKind)
	if e != nil {
		return result, ErrUnknown
	}
	result.ContextKey = contextKey.String
	result.RPCID = rpc.String
	result.ReferenceID = reference.String
	result.ReferenceKind = ReferenceKind(referenceKind.String)
	var upstreamValue any
	if upstream != "" {
		upstreamValue = upstream
	}
	now := s.options.Clock()
	detail := ""
	if len(diagnostic) > 0 && diagnostic[0] != nil && safeDiagnostic(*diagnostic[0]) {
		raw, _ := json.Marshal(diagnostic[0])
		detail = string(raw)
		result.Diagnostic = diagnostic[0]
	}
	r, e := tx.ExecContext(ctx, `UPDATE space.send_submissions SET state='finished',outcome=$3,upstream_id=$4,error_code=$5,error_detail=$7,updated_at=$6,finished_at=$6 WHERE request_key=$1 AND owner_key=$2 AND NOT query_only AND state IN ('reserved','preparing','submitting')`, key, owner, string(outcome), upstreamValue, code, now, detail)
	if e != nil {
		return result, ErrUnknown
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return result, ErrUnknown
	}
	if s.commit(tx) != nil {
		return result, ErrUnknown
	}
	result.Durable = true
	stored, err := s.submission(ctx, s.db, key)
	if err != nil {
		return result, ErrUnknown
	}
	return stored.Result, nil
}
