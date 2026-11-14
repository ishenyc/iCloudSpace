package addressauth

import (
	"context"
	"database/sql"
	"time"
)

// DeriveAccess is the narrow API-to-opaque direct-link port. The requested
// purpose must be independently present on the same API key; a mail_read
// grant never implies raw_read, consume or IMAP. No delegation chain is issued.
func (a *Authority) DeriveAccess(ctx context.Context, key string, purpose Purpose, selector Selector, ttl time.Duration) (IssuedAccess, error) {
	if ttl < time.Second || ttl > time.Hour || purpose == IMAPLogin {
		return IssuedAccess{}, ErrInvalid
	}
	lease, e := a.Authenticate(ctx, Credential{Kind: APIKey, Raw: key}, purpose, selector)
	if e != nil {
		return IssuedAccess{}, e
	}
	defer lease.Close()
	identity := lease.Identity()
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return IssuedAccess{}, storageError(ctx)
	}
	defer tx.Rollback()
	if e = a.checkWritable(ctx, tx); e != nil {
		return IssuedAccess{}, e
	}
	var enabled bool
	var generation, sourceGeneration, uidValidity int64
	var email, lifecycle string
	var deleted sql.NullInt64
	if tx.QueryRowContext(ctx, `SELECT enabled FROM space.mail_sources WHERE id=$1 FOR UPDATE`, identity.SourceID).Scan(&enabled) != nil || !enabled {
		return IssuedAccess{}, ErrUnauthenticated
	}
	if tx.QueryRowContext(ctx, `SELECT a.auth_generation,s.source_generation,a.uid_validity,a.normalized_email,a.lifecycle,a.deleted_at,a.enabled FROM space.private_addresses a JOIN space.mail_sources s ON s.id=a.source_id WHERE a.source_id=$1 AND a.id=$2 FOR UPDATE OF a`, identity.SourceID, identity.AddressID).Scan(&generation, &sourceGeneration, &uidValidity, &email, &lifecycle, &deleted, &enabled) != nil || !enabled || deleted.Valid || lifecycle != "confirmed" || generation != identity.Generation || sourceGeneration != identity.SourceGeneration || uidValidity != identity.UIDValidity || email != identity.Email {
		return IssuedAccess{}, ErrUnauthenticated
	}
	now := a.clock()
	hash := Hash(key)
	var parent int64
	var parentExpiry sql.NullInt64
	if tx.QueryRowContext(ctx, `SELECT id,expires_at FROM space.address_grants WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND authenticator_kind='api_key' AND purpose=$4 AND authenticator_hash=$5 AND hash_scheme=$6 AND hash_version=$7 AND parent_grant_id IS NULL AND revoked_at IS NULL AND issued_at<=$8 AND (expires_at IS NULL OR expires_at>$8)`, identity.SourceID, identity.AddressID, generation, string(purpose), hash[:], HashScheme, HashVersion, now).Scan(&parent, &parentExpiry) != nil {
		return IssuedAccess{}, ErrUnauthenticated
	}
	expires := now + int64(ttl)
	if expires <= now {
		return IssuedAccess{}, ErrInvalid
	}
	if parentExpiry.Valid && parentExpiry.Int64 < expires {
		expires = parentExpiry.Int64
	}
	token, e := opaque("spa_")
	if e != nil {
		return IssuedAccess{}, e
	}
	accessHash := Hash(token)
	if e = insertDerivedGrant(ctx, tx, identity.SourceID, identity.AddressID, generation, string(purpose), accessHash[:], now, expires, parent); e != nil {
		return IssuedAccess{}, e
	}
	if a.commit(tx) != nil {
		return IssuedAccess{}, ErrOutcomeUnknown
	}
	return IssuedAccess{Token: token, ExpiresAt: expires, Identity: identity, Purposes: []Purpose{purpose}}, nil
}
