package addressauth

import (
	"context"
	"database/sql"
	"errors"
	"sync"
)

type PendingDelivery struct {
	DeliveryKey                     string
	SourceID, AddressID, Generation int64
	Acknowledged                    bool
	Revoked                         bool
	CanCopyOTP                      bool
	Secret                          Pending
}

func (PendingDelivery) String() string   { return "addressauth: private pending delivery" }
func (PendingDelivery) GoString() string { return "addressauth: private pending delivery" }

// The application root holds RevealScope until the sensitive response body is
// completely encoded/written. Do not acquire another Authority read scope
// inside this scope: a queued exclusive writer intentionally blocks admission.
type RevealScope struct {
	a       *Authority
	mu      sync.Mutex
	release func()
	closed  bool
}

func (a *Authority) BeginReveal(ctx context.Context) (*RevealScope, error) {
	if a == nil {
		return nil, ErrInvalid
	}
	release, e := a.gate.read(ctx)
	if e != nil {
		return nil, e
	}
	if !a.readReady() {
		release()
		return nil, ErrOutcomeUnknown
	}
	return &RevealScope{a: a, release: release}, nil
}
func (s *RevealScope) Close() error {
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.closed {
			s.closed = true
			s.release()
		}
	}
	return nil
}
func (*RevealScope) String() string   { return "addressauth: sensitive reveal scope" }
func (*RevealScope) GoString() string { return "addressauth: sensitive reveal scope" }

// Reveal methods are management-owner ports; the application root must require
// its current management session. They never create a grant or acknowledge a
// delivery. Historical unacknowledged pending secrets keep their original AAD
// and remain recoverable even when that old generation has been revoked.
func (s *RevealScope) Bundle(ctx context.Context, addressID int64) (Bundle, error) {
	if s == nil || addressID < 1 {
		return Bundle{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Bundle{}, ErrInvalid
	}
	a := s.a
	tx, e := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return Bundle{}, storageError(ctx)
	}
	defer tx.Rollback()
	snapshot, e := readScope(ctx, tx, addressID, a.clock(), false)
	if e != nil {
		return Bundle{}, e
	}
	if len(snapshot.Addresses) != 1 {
		return Bundle{}, ErrUnavailable
	}
	address := snapshot.Addresses[0]
	if address.Lifecycle != "confirmed" || address.Deleted.Valid || !address.Mailbox {
		return Bundle{}, ErrUnavailable
	}
	bundle, e := a.readBundleMaterial(ctx, tx, address)
	if e != nil {
		return Bundle{}, e
	}
	if tx.Commit() != nil {
		return Bundle{}, storageError(ctx)
	}
	return bundle, nil
}

// readBundleMaterial checks the canonical secrets and grant facts. Eligibility
// belongs to its caller: ordinary reveal requires confirmed, while an explicit
// current delivery can retain a complete tuple before activation.
func (a *Authority) readBundleMaterial(ctx context.Context, tx *sql.Tx, address scopeAddress) (Bundle, error) {
	var envelope []byte
	if e := tx.QueryRowContext(ctx, `SELECT bundle_envelope FROM space.address_credential_bundles WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3`, address.SourceID, address.ID, address.Generation).Scan(&envelope); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return Bundle{}, ErrUnavailable
		}
		return Bundle{}, storageError(ctx)
	}
	bundle, e := OpenBundle(a.box, Owner{InstallationID: a.installationID, AddressID: address.ID, Generation: address.Generation}, envelope)
	if e != nil {
		return Bundle{}, e
	}
	// A complete document may retain an API key with a reduced permission set.
	// Match each secret to its own current long-lived authenticator; do not
	// require unrelated API permissions or infer mailbox authority from bytes.
	for _, material := range []struct{ kind, raw string }{{"api_key", bundle.API.Key}, {"imap_password", bundle.IMAP.Password}, {"client_id", bundle.OAuth.ClientID}, {"refresh_token", bundle.OAuth.RefreshToken}} {
		hash := Hash(material.raw)
		var found bool
		e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_grants WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND authenticator_kind=$4 AND authenticator_hash=$5 AND hash_scheme=$6 AND hash_version=$7 AND parent_grant_id IS NULL AND revoked_at IS NULL AND issued_at<=$8 AND (expires_at IS NULL OR expires_at>$8) AND ((authenticator_kind='api_key' AND purpose IN ('latest_read','mail_read','mail_consume','raw_read')) OR (authenticator_kind='imap_password' AND purpose='imap_login') OR (authenticator_kind='client_id' AND purpose='oauth_client') OR (authenticator_kind='refresh_token' AND purpose='oauth_refresh')))`, address.SourceID, address.ID, address.Generation, material.kind, hash[:], HashScheme, HashVersion, a.clock()).Scan(&found)
		if e != nil {
			return Bundle{}, storageError(ctx)
		}
		if !found {
			return Bundle{}, ErrUnavailable
		}
	}
	return bundle, nil
}
func (s *RevealScope) Pending(ctx context.Context, delivery, owner string) (PendingDelivery, error) {
	if s == nil || !validKey(delivery) || !validKey(owner) {
		return PendingDelivery{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return PendingDelivery{}, ErrInvalid
	}
	a := s.a
	var p PendingDelivery
	var envelope []byte
	var ack sql.NullInt64
	e := a.db.QueryRowContext(ctx, `SELECT delivery_key,source_id,address_id,auth_generation,secret_envelope,acknowledged_at FROM space.pending_reveals WHERE delivery_key=$1 AND owner_key=$2`, delivery, owner).Scan(&p.DeliveryKey, &p.SourceID, &p.AddressID, &p.Generation, &envelope, &ack)
	if errors.Is(e, sql.ErrNoRows) {
		return PendingDelivery{}, ErrUnavailable
	}
	if e != nil {
		return PendingDelivery{}, storageError(ctx)
	}
	p.Acknowledged = ack.Valid
	p.Secret, e = OpenPending(a.box, Owner{InstallationID: a.installationID, AddressID: p.AddressID, Generation: p.Generation}, envelope)
	if e != nil {
		return PendingDelivery{}, e
	}
	hash := Hash(p.Secret.APIKey)
	var live bool
	if a.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_grants g JOIN space.private_addresses a ON a.source_id=g.source_id AND a.id=g.address_id WHERE g.source_id=$1 AND g.address_id=$2 AND g.auth_generation=$3 AND a.auth_generation=$3 AND g.authenticator_kind='api_key' AND g.authenticator_hash=$4 AND g.hash_scheme=$5 AND g.hash_version=$6 AND g.revoked_at IS NULL AND g.issued_at<=$7 AND (g.expires_at IS NULL OR g.expires_at>$7))`, p.SourceID, p.AddressID, p.Generation, hash[:], HashScheme, HashVersion, a.clock()).Scan(&live) != nil {
		return PendingDelivery{}, storageError(ctx)
	}
	p.Revoked = !live
	if live {
		if a.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_grants g JOIN space.private_addresses a ON a.source_id=g.source_id AND a.id=g.address_id WHERE g.source_id=$1 AND g.address_id=$2 AND a.deleted_at IS NULL AND g.auth_generation=$3 AND a.auth_generation=$3 AND g.authenticator_kind='api_key' AND g.purpose='mail_read' AND g.parent_grant_id IS NULL AND g.authenticator_hash=$4 AND g.hash_scheme=$5 AND g.hash_version=$6 AND `+currentGrantFactsSQL("$7")+`)`, p.SourceID, p.AddressID, p.Generation, hash[:], HashScheme, HashVersion, a.clock()).Scan(&p.CanCopyOTP) != nil {
			return PendingDelivery{}, storageError(ctx)
		}
	}
	return p, e
}
func (a *Authority) AcknowledgePending(ctx context.Context, delivery, owner string) error {
	if a == nil || !validKey(delivery) || !validKey(owner) {
		return ErrInvalid
	}
	release, e := a.gate.read(ctx)
	if e != nil {
		return e
	}
	defer release()
	if !a.readReady() {
		return ErrOutcomeUnknown
	}
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return storageError(ctx)
	}
	defer tx.Rollback()
	if e = a.checkWritable(ctx, tx); e != nil {
		return e
	}
	var source, address int64
	if tx.QueryRowContext(ctx, `SELECT source_id,address_id FROM space.pending_reveals WHERE delivery_key=$1 AND owner_key=$2`, delivery, owner).Scan(&source, &address) != nil {
		return ErrUnavailable
	}
	var id int64
	if tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, source).Scan(&id) != nil {
		return ErrUnavailable
	}
	if tx.QueryRowContext(ctx, `SELECT id FROM space.private_addresses WHERE source_id=$1 AND id=$2 FOR UPDATE`, source, address).Scan(&id) != nil {
		return ErrUnavailable
	}
	result, e := tx.ExecContext(ctx, `UPDATE space.pending_reveals SET acknowledged_at=COALESCE(acknowledged_at,$3) WHERE delivery_key=$1 AND owner_key=$2`, delivery, owner, a.clock())
	if e != nil {
		return storageError(ctx)
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrUnavailable
	}
	if a.commit(tx) != nil {
		return ErrOutcomeUnknown
	}
	return nil
}
