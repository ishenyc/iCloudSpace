package mailout

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
)

type contextQuery interface {
	rowQuery
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// A browser may only retain the key it persisted before dispatch. Resolve that
// exact request reference to its original owner, including an older context
// selected for the route. No lookup creates or advances provider work.
func (s *Service) lookupContext(ctx context.Context, q rowQuery, key string) (contextRow, error) {
	var canonical string
	var source, address int64
	e := q.QueryRowContext(ctx, `SELECT context_key,source_id,address_id FROM space.compose_context_requests WHERE request_key=$1`, key).Scan(&canonical, &source, &address)
	if errors.Is(e, sql.ErrNoRows) {
		return s.loadContext(ctx, q, key)
	}
	if e != nil {
		return contextRow{}, storage(ctx)
	}
	row, e := s.loadContext(ctx, q, canonical)
	if e != nil {
		return contextRow{}, e
	}
	if row.sourceID != source || row.addressID != address {
		return contextRow{}, ErrStorage
	}
	return row, nil
}

func (s *Service) rememberContextRequest(ctx context.Context, tx *sql.Tx, key string, row contextRow) error {
	// Direct context keys and request aliases share the public lookup namespace.
	// A key already owned by another context may never become an alias here.
	var direct string
	e := tx.QueryRowContext(ctx, `SELECT context_key FROM space.compose_contexts WHERE context_key=$1`, key).Scan(&direct)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return storage(ctx)
	}
	if e == nil && direct != row.ContextKey {
		return ErrConflict
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO space.compose_context_requests(request_key,source_id,address_id,context_key,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(request_key) DO NOTHING`, key, row.sourceID, row.addressID, row.ContextKey, s.options.Clock())
	if e != nil {
		return storage(ctx)
	}
	var source, address int64
	var canonical string
	if tx.QueryRowContext(ctx, `SELECT source_id,address_id,context_key FROM space.compose_context_requests WHERE request_key=$1`, key).Scan(&source, &address, &canonical) != nil {
		return storage(ctx)
	}
	if source != row.sourceID || address != row.addressID || canonical != row.ContextKey {
		return ErrConflict
	}
	return nil
}

// With several retained rows, the existing read-only reference search chooses
// the usable owner. Bind that selection before returning it or authorizing the
// first bootstrap side effect. An already committed alias is never reassigned.
func (s *Service) bindContextRequest(ctx context.Context, scope Scope, key string, row contextRow) error {
	var source, address int64
	var canonical string
	e := s.db.QueryRowContext(ctx, `SELECT source_id,address_id,context_key FROM space.compose_context_requests WHERE request_key=$1`, key).Scan(&source, &address, &canonical)
	if e == nil {
		if source != row.sourceID || address != row.addressID || canonical != row.ContextKey {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return storage(ctx)
	}
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
	if e = s.contextScope(row, scope, row.Recipient); e != nil {
		return e
	}
	if e = s.rememberContextRequest(ctx, tx, key, row); e != nil {
		return e
	}
	if s.commit(tx) != nil {
		return ErrUnknown
	}
	return nil
}

func (s *Service) contextScope(row contextRow, scope Scope, recipient string) error {
	matches, e := s.contextRouteMatches(row, scope, recipient)
	if e != nil {
		return e
	}
	if !matches {
		return ErrConflict
	}
	return nil
}

// A valid retained owner may belong to an earlier source generation. Fresh
// request keys can select a current owner without erasing that old query fact.
// Integrity failures remain errors even when the route identity is obsolete.
func (s *Service) contextRouteMatches(row contextRow, scope Scope, recipient string) (bool, error) {
	matches := row.sourceID == scope.Source.ID && row.addressID == scope.Address.ID && sameAddress(row.Recipient, recipient)
	if row.QueryOnly {
		if !matches {
			return false, ErrConflict
		}
		return true, nil
	}
	doc, e := s.openContext(row)
	if e != nil {
		return false, e
	}
	// Fingerprints retain their original immutable input. Metadata revisions
	// may advance, but an alias cannot skip the original route identity fence.
	fingerprint := routeFingerprint(Scope{Source: doc.Source, Address: doc.Address}, row.Recipient)
	if row.FingerprintScheme != routeScheme || len(row.Fingerprint) != len(fingerprint) || subtle.ConstantTimeCompare(row.Fingerprint, fingerprint[:]) != 1 {
		return false, ErrConflict
	}
	if doc.Source.ID != scope.Source.ID || doc.Source.Generation != scope.Source.Generation || doc.Source.CredentialGeneration != scope.Source.CredentialGeneration || doc.Source.PrincipalRevision != scope.Source.PrincipalRevision || doc.Source.Kind != scope.Source.Kind || !sameAddress(doc.Source.PrimaryAddress, scope.Source.PrimaryAddress) || doc.Address.ID != scope.Address.ID || !sameAddress(doc.Address.Email, scope.Address.Email) || doc.Address.ProviderID != scope.Address.ProviderID || doc.Address.ProviderOwner != scope.Address.ProviderOwner {
		return false, nil
	}
	return matches, nil
}
