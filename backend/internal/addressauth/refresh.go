package addressauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"math"
	"sort"
	"time"
)

type RefreshRequest struct {
	ClientID, RefreshToken string
	Purposes               []Purpose
	Selector               Selector
}

func (RefreshRequest) String() string   { return "addressauth: private refresh request" }
func (RefreshRequest) GoString() string { return "addressauth: private refresh request" }

type IssuedAccess struct {
	Token     string
	ExpiresAt int64
	Identity  Identity
	Purposes  []Purpose
}

func (IssuedAccess) String() string   { return "addressauth: private access grant" }
func (IssuedAccess) GoString() string { return "addressauth: private access grant" }

func opaque(prefix string) (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrStorage
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Refresh exchanges the two independently granted long-lived authenticators.
// A retained bundle and a previous bearer do not contribute any authority.
// The read scope spans COMMIT so a concurrent full revoke cannot miss newly
// issued access. It never acquires the source's network-operation guard.
func (a *Authority) Refresh(ctx context.Context, request RefreshRequest) (IssuedAccess, error) {
	if a == nil || !validSecret(request.ClientID) || !validSecret(request.RefreshToken) {
		return IssuedAccess{}, ErrUnauthenticated
	}
	selector, e := normalizeSelector(request.Selector)
	if e != nil {
		return IssuedAccess{}, ErrUnauthenticated
	}
	requested := make(map[Purpose]bool)
	for _, p := range request.Purposes {
		if !validPurpose(p) {
			return IssuedAccess{}, ErrInvalid
		}
		requested[p] = true
	}
	release, e := a.gate.read(ctx)
	if e != nil {
		return IssuedAccess{}, e
	}
	defer release()
	if !a.readReady() {
		return IssuedAccess{}, ErrOutcomeUnknown
	}
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return IssuedAccess{}, storageError(ctx)
	}
	defer tx.Rollback()
	if e = a.checkWritable(ctx, tx); e != nil {
		return IssuedAccess{}, e
	}
	now := a.clock()
	client, refresh := Hash(request.ClientID), Hash(request.RefreshToken)
	rows, e := tx.QueryContext(ctx, `SELECT DISTINCT s.id,a.id,s.source_generation,a.auth_generation,a.uid_validity,a.normalized_email
 FROM space.private_addresses a JOIN space.mail_sources s ON s.id=a.source_id
 JOIN space.address_grants c ON c.source_id=a.source_id AND c.address_id=a.id
 JOIN space.address_grants r ON r.source_id=a.source_id AND r.address_id=a.id
 WHERE c.authenticator_kind='client_id' AND c.purpose='oauth_client' AND c.authenticator_hash=$1
 AND r.authenticator_kind='refresh_token' AND r.purpose='oauth_refresh' AND r.authenticator_hash=$2
 AND c.hash_scheme=$3 AND r.hash_scheme=$3 AND c.hash_version=$4 AND r.hash_version=$4
 AND c.auth_generation=a.auth_generation AND r.auth_generation=a.auth_generation AND c.parent_grant_id IS NULL AND r.parent_grant_id IS NULL
 AND c.revoked_at IS NULL AND r.revoked_at IS NULL AND c.issued_at<=$5 AND r.issued_at<=$5
 AND (c.expires_at IS NULL OR c.expires_at>$5) AND (r.expires_at IS NULL OR r.expires_at>$5)
 AND a.lifecycle='confirmed' AND a.deleted_at IS NULL AND a.enabled AND s.enabled
 AND ($6::bigint=0 OR a.id=$6) AND ($7::text='' OR a.normalized_email=$7) LIMIT 2`, client[:], refresh[:], HashScheme, HashVersion, now, selector.AddressID, selector.Email)
	if e != nil {
		return IssuedAccess{}, storageError(ctx)
	}
	var identity Identity
	n := 0
	for rows.Next() {
		if e = rows.Scan(&identity.SourceID, &identity.AddressID, &identity.SourceGeneration, &identity.Generation, &identity.UIDValidity, &identity.Email); e != nil {
			rows.Close()
			return IssuedAccess{}, ErrStorage
		}
		n++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return IssuedAccess{}, storageError(ctx)
	}
	if n != 1 {
		return IssuedAccess{}, ErrUnauthenticated
	}
	// Fixed parent/child row ordering also serializes local source/address
	// disable with this transaction. No external I/O occurs under these locks.
	var enabled bool
	if e = tx.QueryRowContext(ctx, `SELECT enabled FROM space.mail_sources WHERE id=$1 FOR UPDATE`, identity.SourceID).Scan(&enabled); e != nil || !enabled {
		return IssuedAccess{}, ErrUnauthenticated
	}
	var gen, sourceGen, uidValidity int64
	var email, lifecycle string
	var deleted sql.NullInt64
	if e = tx.QueryRowContext(ctx, `SELECT a.auth_generation,s.source_generation,a.uid_validity,a.normalized_email,a.lifecycle,a.deleted_at,a.enabled FROM space.private_addresses a JOIN space.mail_sources s ON s.id=a.source_id WHERE a.source_id=$1 AND a.id=$2 FOR UPDATE OF a`, identity.SourceID, identity.AddressID).Scan(&gen, &sourceGen, &uidValidity, &email, &lifecycle, &deleted, &enabled); e != nil || !enabled || deleted.Valid || lifecycle != "confirmed" || gen != identity.Generation || sourceGen != identity.SourceGeneration || uidValidity != identity.UIDValidity || email != identity.Email {
		return IssuedAccess{}, ErrUnauthenticated
	}
	// Recheck both factors after row waits; the preliminary lookup was only a
	// way to determine a unique owner, never a stale authorization decision.
	var factors int
	if e = tx.QueryRowContext(ctx, `SELECT count(DISTINCT authenticator_kind) FROM space.address_grants WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND hash_scheme=$4 AND hash_version=$5 AND parent_grant_id IS NULL AND revoked_at IS NULL AND issued_at<=$6 AND (expires_at IS NULL OR expires_at>$6) AND ((authenticator_kind='client_id' AND purpose='oauth_client' AND authenticator_hash=$7) OR (authenticator_kind='refresh_token' AND purpose='oauth_refresh' AND authenticator_hash=$8))`, identity.SourceID, identity.AddressID, gen, HashScheme, HashVersion, a.clock(), client[:], refresh[:]).Scan(&factors); e != nil {
		return IssuedAccess{}, storageError(ctx)
	}
	if factors != 2 {
		return IssuedAccess{}, ErrUnauthenticated
	}
	now = a.clock()
	if now > math.MaxInt64-int64(time.Hour) {
		return IssuedAccess{}, ErrInvalid
	}
	rows, e = tx.QueryContext(ctx, `SELECT DISTINCT purpose FROM space.address_grants WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND hash_scheme=$4 AND hash_version=$5 AND octet_length(authenticator_hash)=32 AND parent_grant_id IS NULL AND revoked_at IS NULL AND issued_at<=$6 AND (expires_at IS NULL OR expires_at>$6) AND ((authenticator_kind='api_key' AND purpose IN ('mail_read','mail_consume','raw_read')) OR (authenticator_kind='imap_password' AND purpose='imap_login'))`, identity.SourceID, identity.AddressID, gen, HashScheme, HashVersion, now)
	if e != nil {
		return IssuedAccess{}, storageError(ctx)
	}
	var purposes []Purpose
	for rows.Next() {
		var p Purpose
		if rows.Scan(&p) != nil {
			rows.Close()
			return IssuedAccess{}, ErrStorage
		}
		if len(requested) == 0 || requested[p] {
			purposes = append(purposes, p)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return IssuedAccess{}, storageError(ctx)
	}
	if len(purposes) == 0 {
		return IssuedAccess{}, ErrUnauthenticated
	}
	sort.Slice(purposes, func(i, j int) bool { return purposes[i] < purposes[j] })
	token, e := opaque("spa_")
	if e != nil {
		return IssuedAccess{}, e
	}
	hash := Hash(token)
	expires := now + int64(time.Hour)
	var parent int64
	if tx.QueryRowContext(ctx, `SELECT id FROM space.address_grants WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND authenticator_kind='refresh_token' AND purpose='oauth_refresh' AND authenticator_hash=$4 AND revoked_at IS NULL`, identity.SourceID, identity.AddressID, gen, refresh[:]).Scan(&parent) != nil {
		return IssuedAccess{}, ErrUnauthenticated
	}
	for _, p := range purposes {
		if e = insertDerivedGrant(ctx, tx, identity.SourceID, identity.AddressID, gen, string(p), hash[:], now, expires, parent); e != nil {
			return IssuedAccess{}, e
		}
	}
	if a.commit(tx) != nil {
		return IssuedAccess{}, ErrOutcomeUnknown
	}
	return IssuedAccess{Token: token, ExpiresAt: expires, Identity: identity, Purposes: purposes}, nil
}
func insertDerivedGrant(ctx context.Context, tx *sql.Tx, source, address, generation int64, purpose string, hash []byte, now, expires, parent int64) error {
	_, e := tx.ExecContext(ctx, `INSERT INTO space.address_grants(source_id,address_id,purpose,authenticator_kind,authenticator_hash,hash_scheme,hash_version,auth_generation,issued_at,expires_at,parent_grant_id) VALUES($1,$2,$3,'opaque',$4,$5,$6,$7,$8,$9,$10)`, source, address, purpose, hash, HashScheme, HashVersion, generation, now, expires, parent)
	if e != nil {
		return storageError(ctx)
	}
	return nil
}

func storageError(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	return ErrStorage
}
func (a *Authority) checkWritable(ctx context.Context, tx *sql.Tx) error {
	var installation string
	var enabled bool
	var proof []byte
	if tx.QueryRowContext(ctx, `SELECT i.installation_id,i.writes_enabled,k.proof FROM space.installation i JOIN space.key_binding k ON k.singleton=i.singleton WHERE i.singleton AND k.binding_version=1`).Scan(&installation, &enabled, &proof) != nil {
		return storageError(ctx)
	}
	if installation != a.installationID {
		return ErrInstallation
	}
	want, e := a.box.Fingerprint(a.installationID)
	if e != nil || subtle.ConstantTimeCompare(want[:], proof) != 1 {
		return ErrInstallation
	}
	if !enabled {
		return ErrReadOnly
	}
	return nil
}
func insertGrant(ctx context.Context, tx *sql.Tx, source, address, generation int64, purpose, kind string, hash []byte, now int64, expires *int64) error {
	_, e := tx.ExecContext(ctx, `INSERT INTO space.address_grants(source_id,address_id,purpose,authenticator_kind,authenticator_hash,hash_scheme,hash_version,auth_generation,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, source, address, purpose, kind, hash, HashScheme, HashVersion, generation, now, expires)
	if e != nil {
		return storageError(ctx)
	}
	return nil
}
