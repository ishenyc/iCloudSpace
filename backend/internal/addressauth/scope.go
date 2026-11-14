package addressauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
)

type ScopeState struct {
	Digest        string
	AddressCount  int
	EligibleCount int
}
type scopeSource struct {
	ID, Generation int64
	Enabled        bool
}
type scopeAddress struct {
	SourceID, ID, Generation int64
	UIDValidity              int64
	Mailbox                  bool
	Email, Lifecycle         string
	Enabled                  bool
	Deleted                  sql.NullInt64
}
type grantFact struct {
	SourceID, AddressID, Generation int64
	Purpose, Kind                   string
	Hash                            []byte
	Issued                          int64
	Expires                         sql.NullInt64
}
type scopeSnapshot struct {
	Version   int
	Sources   []scopeSource
	Addresses []scopeAddress
	Grants    []grantFact
}

// Scope describes the confirmation CAS for full rotation. The digest covers
// source/address eligibility and current effective long-lived grant facts,
// including their original expiry. It contains no wall-clock nonce.
func (a *Authority) Scope(ctx context.Context) (ScopeState, error) { return a.scope(ctx, 0) }
func (a *Authority) AddressScope(ctx context.Context, addressID int64) (ScopeState, error) {
	if addressID < 1 {
		return ScopeState{}, ErrInvalid
	}
	return a.scope(ctx, addressID)
}
func (a *Authority) scope(ctx context.Context, addressID int64) (ScopeState, error) {
	if a == nil {
		return ScopeState{}, ErrInvalid
	}
	release, e := a.gate.read(ctx)
	if e != nil {
		return ScopeState{}, e
	}
	defer release()
	tx, e := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return ScopeState{}, storageError(ctx)
	}
	defer tx.Rollback()
	snapshot, e := readScope(ctx, tx, addressID, a.clock(), false)
	if e != nil {
		return ScopeState{}, e
	}
	if addressID != 0 && len(snapshot.Addresses) != 1 {
		return ScopeState{}, ErrUnavailable
	}
	if tx.Commit() != nil {
		return ScopeState{}, storageError(ctx)
	}
	eligible := 0
	for _, address := range snapshot.Addresses {
		if !address.Deleted.Valid && (addressID == 0 || address.Lifecycle == "confirmed") {
			eligible++
		}
	}
	return ScopeState{Digest: scopeDigest(snapshot), AddressCount: len(snapshot.Addresses), EligibleCount: eligible}, nil
}
func scopeDigest(s scopeSnapshot) string {
	encoded, _ := json.Marshal(s)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func readScope(ctx context.Context, tx *sql.Tx, address, now int64, lock bool) (scopeSnapshot, error) {
	s := scopeSnapshot{Version: 1}
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	rows, e := tx.QueryContext(ctx, `SELECT id,source_generation,enabled FROM space.mail_sources WHERE ($1::bigint=0 OR id=(SELECT source_id FROM space.private_addresses WHERE id=$1)) ORDER BY id`+suffix, address)
	if e != nil {
		return s, storageError(ctx)
	}
	for rows.Next() {
		var v scopeSource
		if rows.Scan(&v.ID, &v.Generation, &v.Enabled) != nil {
			rows.Close()
			return s, ErrStorage
		}
		s.Sources = append(s.Sources, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return s, storageError(ctx)
	}
	rows, e = tx.QueryContext(ctx, `SELECT a.source_id,a.id,a.auth_generation,a.uid_validity,a.normalized_email,a.lifecycle,a.enabled,a.deleted_at,
 (SELECT count(DISTINCT authenticator_kind)=3 FROM space.address_grants g WHERE g.source_id=a.source_id AND g.address_id=a.id AND g.auth_generation=a.auth_generation AND g.parent_grant_id IS NULL AND g.hash_scheme='sha256-raw' AND g.hash_version=1 AND octet_length(g.authenticator_hash)=32 AND ((g.authenticator_kind='imap_password' AND g.purpose='imap_login') OR (g.authenticator_kind='client_id' AND g.purpose='oauth_client') OR (g.authenticator_kind='refresh_token' AND g.purpose='oauth_refresh')))
 FROM space.private_addresses a WHERE ($1::bigint=0 OR a.id=$1) ORDER BY a.source_id,a.id`+suffix, address)
	if e != nil {
		return s, storageError(ctx)
	}
	for rows.Next() {
		var v scopeAddress
		if rows.Scan(&v.SourceID, &v.ID, &v.Generation, &v.UIDValidity, &v.Email, &v.Lifecycle, &v.Enabled, &v.Deleted, &v.Mailbox) != nil {
			rows.Close()
			return s, ErrStorage
		}
		s.Addresses = append(s.Addresses, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return s, storageError(ctx)
	}
	rows, e = tx.QueryContext(ctx, `SELECT g.source_id,g.address_id,g.auth_generation,g.purpose,g.authenticator_kind,g.authenticator_hash,g.issued_at,g.expires_at
 FROM space.address_grants g JOIN space.private_addresses a ON a.source_id=g.source_id AND a.id=g.address_id
 WHERE ($1::bigint=0 OR a.id=$1) AND g.auth_generation=a.auth_generation AND g.hash_scheme=$2 AND g.hash_version=$3
 AND octet_length(g.authenticator_hash)=32 AND g.parent_grant_id IS NULL AND g.revoked_at IS NULL
 AND g.issued_at<=$4 AND (g.expires_at IS NULL OR g.expires_at>$4)
 AND ((g.authenticator_kind='api_key' AND g.purpose IN ('latest_read','mail_read','mail_consume','raw_read')) OR (g.authenticator_kind='imap_password' AND g.purpose='imap_login') OR (g.authenticator_kind='client_id' AND g.purpose='oauth_client') OR (g.authenticator_kind='refresh_token' AND g.purpose='oauth_refresh'))
 ORDER BY g.source_id,g.address_id,g.authenticator_kind,g.purpose,g.authenticator_hash,g.id`, address, HashScheme, HashVersion, now)
	if e != nil {
		return s, storageError(ctx)
	}
	for rows.Next() {
		var v grantFact
		if rows.Scan(&v.SourceID, &v.AddressID, &v.Generation, &v.Purpose, &v.Kind, &v.Hash, &v.Issued, &v.Expires) != nil {
			rows.Close()
			return s, ErrStorage
		}
		s.Grants = append(s.Grants, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return s, storageError(ctx)
	}
	return s, nil
}
