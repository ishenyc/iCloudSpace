package mailout

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"icloudspace/internal/pgschema"
	"icloudspace/internal/sourceguard"
	"icloudspace/internal/vault"
	"strings"
	"time"
)

type Service struct {
	db           *sql.DB
	installation string
	box          *vault.Vault
	guards       *sourceguard.Registry
	provider     Provider
	options      Options
	commit       func(*sql.Tx) error
}

func New(ctx context.Context, db *sql.DB, installation string, box *vault.Vault, guards *sourceguard.Registry, provider Provider, options Options) (*Service, error) {
	if db == nil || box == nil || guards == nil || provider == nil || !token(installation, 256) {
		return nil, ErrInvalid
	}
	if pgschema.Check(ctx, db) != nil {
		return nil, ErrStorage
	}
	var actual string
	var proof []byte
	if db.QueryRowContext(ctx, `SELECT i.installation_id,k.proof FROM space.installation i JOIN space.key_binding k ON k.singleton=i.singleton WHERE i.singleton AND k.binding_version=1`).Scan(&actual, &proof) != nil || actual != installation {
		return nil, ErrStorage
	}
	want, e := box.Fingerprint(installation)
	if e != nil || subtle.ConstantTimeCompare(proof, want[:]) != 1 {
		return nil, ErrStorage
	}
	if options.Clock == nil {
		options.Clock = func() int64 { return time.Now().UnixNano() }
	}
	if options.ReferenceWait == 0 {
		options.ReferenceWait = 30 * time.Second
	}
	if options.ReferenceWait < 0 || options.ReferenceWait > time.Minute {
		return nil, ErrInvalid
	}
	return &Service{db: db, installation: installation, box: box, guards: guards, provider: provider, options: options, commit: func(tx *sql.Tx) error { return tx.Commit() }}, nil
}
func storage(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrStorage
}
func randomID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrStorage
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func (s *Service) sourceID(ctx context.Context, address int64) (int64, error) {
	var source int64
	e := s.db.QueryRowContext(ctx, `SELECT source_id FROM space.private_addresses WHERE id=$1`, address).Scan(&source)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if e != nil {
		return 0, storage(ctx)
	}
	return source, nil
}

// A management transport may already own this source while rechecking its
// browser session after the wait. Borrow only the matching live capability.
func (s *Service) enter(ctx context.Context, source int64) (context.Context, *sourceguard.Lease, func(), error) {
	if held := sourceguard.LeaseFromContext(ctx); held != nil {
		if !held.ValidFor(s.guards, source) {
			return ctx, nil, nil, ErrInvalid
		}
		if err := ctx.Err(); err != nil {
			return ctx, nil, nil, err
		}
		return ctx, held, func() {}, nil
	}
	gate, err := s.guards.Acquire(ctx, source)
	if err != nil {
		return ctx, nil, nil, err
	}
	return sourceguard.WithLease(ctx, gate), gate, func() { gate.Close() }, nil
}
func (s *Service) scope(ctx context.Context, source, address int64, gate *sourceguard.Lease) (Scope, error) {
	if !gate.ValidFor(s.guards, source) {
		return Scope{}, ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Scope{}, storage(ctx)
	}
	defer tx.Rollback()
	scope, e := s.loadScope(ctx, tx, source, address, gate)
	if e != nil {
		return scope, e
	}
	if tx.Commit() != nil {
		return Scope{}, storage(ctx)
	}
	return scope, nil
}
func (s *Service) writable(ctx context.Context, tx *sql.Tx) error {
	var actual string
	var enabled bool
	if tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton`).Scan(&actual, &enabled) != nil {
		return storage(ctx)
	}
	if actual != s.installation {
		return ErrStorage
	}
	if !enabled {
		return ErrReadOnly
	}
	return nil
}
func (s *Service) loadScope(ctx context.Context, tx *sql.Tx, source, address int64, gate *sourceguard.Lease) (Scope, error) {
	out := Scope{Gate: gate}
	var enabled bool
	e := tx.QueryRowContext(ctx, `SELECT id,revision,source_generation,credential_generation,kind,address_namespace,enabled FROM space.mail_sources WHERE id=$1 FOR UPDATE`, source).Scan(&out.Source.ID, &out.Source.Revision, &out.Source.Generation, &out.Source.CredentialGeneration, &out.Source.Kind, &out.Source.PrimaryAddress, &enabled)
	if e != nil {
		return out, storage(ctx)
	}
	if !enabled || (out.Source.Kind != "apple_direct" && out.Source.Kind != "apple_forwarded") {
		return out, ErrIneligible
	}
	e = tx.QueryRowContext(ctx, `SELECT revision FROM space.apple_principals WHERE source_id=$1`, source).Scan(&out.Source.PrincipalRevision)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrIneligible
	}
	if e != nil {
		return out, storage(ctx)
	}
	var kind, lifecycle string
	var deleted sql.NullInt64
	var providerID, owner sql.NullString
	e = tx.QueryRowContext(ctx, `SELECT id,revision,email,provider_address_id,provider_owner,kind,lifecycle,enabled,deleted_at FROM space.private_addresses WHERE source_id=$1 AND id=$2 FOR UPDATE`, source, address).Scan(&out.Address.ID, &out.Address.Revision, &out.Address.Email, &providerID, &owner, &kind, &lifecycle, &enabled, &deleted)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, storage(ctx)
	}
	if kind != "apple" && kind != "manual" || lifecycle != "confirmed" || deleted.Valid || !enabled {
		return out, ErrIneligible
	}
	out.Address.ProviderID = providerID.String
	out.Address.ProviderOwner = owner.String
	if out.Source.Kind == "apple_direct" {
		// Consumption changes local visibility, not the remote message's
		// identity. These bounded coordinates are only discovery hints; the
		// provider still has to prove each message and its current epoch.
		rows, err := tx.QueryContext(ctx, `SELECT m.uid_validity,m.remote_uid
FROM space.mailbox_entries e
JOIN space.source_messages m ON m.source_id=e.source_id AND m.id=e.message_id
JOIN space.mailbox_cursors c ON c.source_id=m.source_id AND c.source_generation=m.source_generation AND c.mailbox_name=m.mailbox_name AND c.uid_validity=m.uid_validity
WHERE e.source_id=$1 AND e.address_id=$2 AND m.source_generation=$3 AND m.mailbox_name='INBOX'
ORDER BY m.remote_uid DESC LIMIT 20`, source, address, out.Source.Generation)
		if err != nil {
			return out, storage(ctx)
		}
		defer rows.Close()
		for rows.Next() {
			var hint RemoteHint
			if rows.Scan(&hint.UIDValidity, &hint.UID) != nil {
				return out, storage(ctx)
			}
			out.RemoteHints = append(out.RemoteHints, hint)
		}
		if rows.Err() != nil {
			return out, storage(ctx)
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.id,CASE WHEN m.raw_header_complete AND m.declared_body_size<=2097152 THEN m.raw_header ELSE ''::bytea END,m.uid_validity,m.remote_uid FROM space.mailbox_entries e
JOIN space.source_messages m ON m.source_id=e.source_id AND m.id=e.message_id
JOIN space.content_objects o ON o.source_id=m.source_id AND o.object_key=m.object_key AND o.state='available'
WHERE e.source_id=$1 AND e.address_id=$2 AND m.source_generation=$3 AND m.mailbox_name='INBOX'
ORDER BY e.local_uid DESC LIMIT 100`, source, address, out.Source.Generation)
	if err != nil {
		return out, storage(ctx)
	}
	defer rows.Close()
	for rows.Next() {
		var hint ArchiveHint
		if rows.Scan(&hint.ID, &hint.Header, &hint.UIDValidity, &hint.UID) != nil {
			return out, storage(ctx)
		}
		out.ArchiveHints = append(out.ArchiveHints, hint)
	}
	if rows.Err() != nil {
		return out, storage(ctx)
	}
	return out, nil
}
func sameAddress(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
func (s *Service) fresh(checked int64) bool {
	now := s.options.Clock()
	return checked <= now && uint64(now)-uint64(checked) <= uint64(30*time.Second)
}
func (s *Service) route(scope Scope, recipient string, r Route) bool {
	return r.SourceID == scope.Source.ID && r.AddressID == scope.Address.ID && sameAddress(r.Alias, scope.Address.Email) && sameAddress(r.Recipient, recipient) && sameAddress(r.PrimaryAddress, scope.Source.PrimaryAddress) && r.OwnerVerified && r.Active && token(r.ProviderAddressID, 1024) && (scope.Address.ProviderID == "" || r.ProviderAddressID == scope.Address.ProviderID) && token(r.ProviderFrom, 2048) && s.fresh(r.CheckedAt)
}
func (s *Service) readReference(ctx context.Context, op Operation, scope Scope, route Route, e Evidence) (Reference, bool, error) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, ready, err := op.ReadReference(bounded, route, e)
	if err != nil {
		return Reference{}, false, err
	}
	if !ready {
		return Reference{}, false, nil
	}
	if r.ContextKey != e.ContextKey || r.OwnerKey != e.OwnerKey || r.Nonce != e.Nonce || !sameAddress(r.Alias, scope.Address.Email) || !sameAddress(r.Recipient, route.Recipient) || !token(r.ID, 2048) || r.Kind != RouteReference && !token(r.MessageID, 2048) || !s.fresh(r.CheckedAt) {
		return Reference{}, false, ErrProvider
	}
	// A naturally received HME message proves the current route, not any
	// earlier uncertain draft/seed. Its vendor-verified role has different
	// sender/subject rules; no original bootstrap fact is inferred from it.
	if r.Kind == IncomingReference || r.Kind == RouteReference {
		return r, true, nil
	}
	if r.Kind != SeedReference {
		return Reference{}, false, ErrProvider
	}
	if e.CandidateID != "" && r.CandidateID != e.CandidateID || e.CandidateUIDValidity != 0 && r.CandidateUIDValidity != e.CandidateUIDValidity || e.SeedID != "" && r.SeedID != e.SeedID {
		return Reference{}, false, ErrProvider
	}
	if e.SeedMessageID != "" && r.MessageID != e.SeedMessageID {
		return Reference{}, false, ErrProvider
	}
	if e.ReferenceID != "" && r.ID != e.ReferenceID {
		return Reference{}, false, ErrProvider
	}
	if r.Subject != e.Nonce {
		return Reference{}, false, ErrReference
	}
	return r, true, nil
}
