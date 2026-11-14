package addressauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strconv"

	"icloudspace/internal/operationlog"
	"icloudspace/internal/sourceguard"
)

type secretGrant struct{ purpose, kind, raw string }

func modernGrants(b Bundle) []secretGrant {
	return []secretGrant{{"mail_read", "api_key", b.API.Key}, {"mail_consume", "api_key", b.API.Key}, {"raw_read", "api_key", b.API.Key}, {"imap_login", "imap_password", b.IMAP.Password}, {"oauth_client", "client_id", b.OAuth.ClientID}, {"oauth_refresh", "refresh_token", b.OAuth.RefreshToken}}
}

// A complete mailbox requires independent canonical authority facts, not just
// a retained document. This guards the single-bundle rotation boundary.
func (a *Authority) completeBundle(ctx context.Context, tx *sql.Tx, address scopeAddress, now int64) (Bundle, error) {
	if address.Lifecycle != "confirmed" || address.Deleted.Valid || !address.Mailbox {
		return Bundle{}, ErrConflict
	}
	var encoded []byte
	var generation int64
	e := tx.QueryRowContext(ctx, `SELECT bundle_envelope,auth_generation FROM space.address_credential_bundles WHERE source_id=$1 AND address_id=$2`, address.SourceID, address.ID).Scan(&encoded, &generation)
	if errors.Is(e, sql.ErrNoRows) {
		return Bundle{}, ErrConflict
	}
	if e != nil {
		return Bundle{}, storageError(ctx)
	}
	if generation != address.Generation {
		return Bundle{}, ErrConflict
	}
	b, e := OpenBundle(a.box, Owner{InstallationID: a.installationID, AddressID: address.ID, Generation: generation}, encoded)
	if e != nil {
		return Bundle{}, e
	}
	for _, g := range modernGrants(b) {
		hash := Hash(g.raw)
		var exists bool
		e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_grants WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND purpose=$4 AND authenticator_kind=$5 AND authenticator_hash=$6 AND hash_scheme=$7 AND hash_version=$8 AND parent_grant_id IS NULL AND revoked_at IS NULL AND issued_at<=$9 AND (expires_at IS NULL OR expires_at>$9))`, address.SourceID, address.ID, generation, g.purpose, g.kind, hash[:], HashScheme, HashVersion, now).Scan(&exists)
		if e != nil {
			return Bundle{}, storageError(ctx)
		}
		if !exists {
			return Bundle{}, ErrConflict
		}
	}
	return b, nil
}

type EnsurePendingRequest struct {
	AddressID, Generation int64
	DeliveryKey, OwnerKey string
}
type EnsurePendingResult struct {
	SourceID, AddressID, Generation int64
	DeliveryKey                     string
	AlreadyComplete                 bool
}

// EnsurePendingBundle is an explicit management action for the original
// unacknowledged key. It never runs from list/reveal/ACK or a credential check.
// The original API bytes, delivery owner/key, generation and UID facts remain.
func (a *Authority) EnsurePendingBundle(ctx context.Context, r EnsurePendingRequest) (EnsurePendingResult, error) {
	if a == nil || r.AddressID < 1 || r.Generation < 1 || !validKey(r.DeliveryKey) || !validKey(r.OwnerKey) {
		return EnsurePendingResult{}, ErrInvalid
	}
	ids, e := a.rotationSources(ctx, r.AddressID)
	if e != nil {
		return EnsurePendingResult{}, e
	}
	guard, e := a.guards.Acquire(ctx, ids[0])
	if e != nil {
		return EnsurePendingResult{}, e
	}
	defer guard.Close()
	release, e := a.gate.read(ctx)
	if e != nil {
		return EnsurePendingResult{}, e
	}
	defer release()
	if !a.readReady() {
		return EnsurePendingResult{}, ErrOutcomeUnknown
	}
	if e = sourceguard.CheckLocalMutation(ctx); e != nil {
		return EnsurePendingResult{}, e
	}
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return EnsurePendingResult{}, storageError(ctx)
	}
	defer tx.Rollback()
	if e = a.checkWritable(ctx, tx); e != nil {
		return EnsurePendingResult{}, e
	}
	snapshot, e := readScope(ctx, tx, r.AddressID, a.clock(), true)
	if e != nil {
		return EnsurePendingResult{}, e
	}
	if len(snapshot.Addresses) != 1 {
		return EnsurePendingResult{}, ErrConflict
	}
	address := snapshot.Addresses[0]
	if address.SourceID != ids[0] || address.Generation != r.Generation || address.Lifecycle != "confirmed" || address.Deleted.Valid {
		return EnsurePendingResult{}, ErrConflict
	}
	var encoded []byte
	var acknowledged sql.NullInt64
	var pendingGeneration int64
	e = tx.QueryRowContext(ctx, `SELECT secret_envelope,auth_generation,acknowledged_at FROM space.pending_reveals WHERE source_id=$1 AND address_id=$2 AND delivery_key=$3 AND owner_key=$4 FOR UPDATE`, address.SourceID, address.ID, r.DeliveryKey, r.OwnerKey).Scan(&encoded, &pendingGeneration, &acknowledged)
	if errors.Is(e, sql.ErrNoRows) {
		return EnsurePendingResult{}, ErrConflict
	}
	if e != nil {
		return EnsurePendingResult{}, storageError(ctx)
	}
	if acknowledged.Valid || pendingGeneration != r.Generation {
		return EnsurePendingResult{}, ErrConflict
	}
	p, e := OpenPending(a.box, Owner{InstallationID: a.installationID, AddressID: address.ID, Generation: r.Generation}, encoded)
	if e != nil {
		return EnsurePendingResult{}, e
	}
	hash := Hash(p.APIKey)
	hasAPI := false
	for _, g := range snapshot.Grants {
		if g.Kind == "api_key" {
			if subtle.ConstantTimeCompare(g.Hash, hash[:]) != 1 {
				return EnsurePendingResult{}, ErrConflict
			}
			hasAPI = true
		}
	}
	if !hasAPI {
		return EnsurePendingResult{}, ErrConflict
	}
	result := EnsurePendingResult{SourceID: address.SourceID, AddressID: address.ID, Generation: r.Generation, DeliveryKey: r.DeliveryKey}
	var envelope []byte
	var bundleGeneration int64
	e = tx.QueryRowContext(ctx, `SELECT bundle_envelope,auth_generation FROM space.address_credential_bundles WHERE source_id=$1 AND address_id=$2`, address.SourceID, address.ID).Scan(&envelope, &bundleGeneration)
	if e == nil {
		b, e := a.completeBundle(ctx, tx, address, a.clock())
		if e != nil || b.API.Key != p.APIKey {
			if e != nil {
				return EnsurePendingResult{}, e
			}
			return EnsurePendingResult{}, ErrConflict
		}
		result.AlreadyComplete = true
		if tx.Commit() != nil {
			return EnsurePendingResult{}, storageError(ctx)
		}
		return result, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return EnsurePendingResult{}, storageError(ctx)
	}
	if address.Mailbox {
		return EnsurePendingResult{}, ErrConflict
	}
	b, e := Generate()
	if e != nil {
		return EnsurePendingResult{}, e
	}
	b.API.Key = p.APIKey
	envelope, e = SealBundle(a.box, Owner{InstallationID: a.installationID, AddressID: address.ID, Generation: r.Generation}, b)
	if e != nil {
		return EnsurePendingResult{}, e
	}
	now := a.clock()
	if _, e = tx.ExecContext(ctx, `INSERT INTO space.address_credential_bundles(address_id,source_id,bundle_envelope,bundle_version,auth_generation,updated_at) VALUES($1,$2,$3,$4,$5,$6)`, address.ID, address.SourceID, envelope, DocumentVersion, r.Generation, now); e != nil {
		return EnsurePendingResult{}, storageError(ctx)
	}
	for _, g := range modernGrants(b) {
		hash := Hash(g.raw)
		_, e = tx.ExecContext(ctx, `INSERT INTO space.address_grants(source_id,address_id,purpose,authenticator_kind,authenticator_hash,hash_scheme,hash_version,auth_generation,issued_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(address_id,purpose,authenticator_kind,authenticator_hash,auth_generation) DO NOTHING`, address.SourceID, address.ID, g.purpose, g.kind, hash[:], HashScheme, HashVersion, r.Generation, now)
		if e != nil {
			return EnsurePendingResult{}, storageError(ctx)
		}
	}
	if e = operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: now, Action: "credentials.supplement", ResourceKind: "address", ResourceRef: strconv.FormatInt(address.ID, 10), Outcome: "success", SourceID: &address.SourceID, Fields: map[string]string{"operation_kind": "mailbox"}})); e != nil {
		return EnsurePendingResult{}, storageError(ctx)
	}
	if a.commit(tx) != nil {
		return EnsurePendingResult{}, ErrOutcomeUnknown
	}
	return result, nil
}
