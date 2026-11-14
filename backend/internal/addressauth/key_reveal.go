package addressauth

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
)

// APIKeyMaterial contains only the independently granted API authenticator.
// It is not a mailbox bundle and never contributes IMAP/OAuth permission.
type APIKeyMaterial struct {
	Key      string    `json:"key"`
	Purposes []Purpose `json:"purposes"`
}

func (APIKeyMaterial) String() string   { return "addressauth: private API key material" }
func (APIKeyMaterial) GoString() string { return "addressauth: private API key material" }

// APIKey is an explicit management reveal. A current encrypted bundle or an
// original pending owner's document supplies bytes, while effective grants
// independently authorize those exact bytes. Hash-only material is unavailable;
// this method never generates/rotates credentials or acknowledges delivery.
func (s *RevealScope) APIKey(ctx context.Context, addressID int64) (APIKeyMaterial, error) {
	if s == nil || addressID < 1 {
		return APIKeyMaterial{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return APIKeyMaterial{}, ErrInvalid
	}
	a := s.a
	tx, e := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return APIKeyMaterial{}, storageError(ctx)
	}
	defer tx.Rollback()
	var source, generation int64
	e = tx.QueryRowContext(ctx, `SELECT source_id,auth_generation FROM space.private_addresses WHERE id=$1 AND lifecycle='confirmed' AND deleted_at IS NULL`, addressID).Scan(&source, &generation)
	if errors.Is(e, sql.ErrNoRows) {
		return APIKeyMaterial{}, ErrUnavailable
	}
	if e != nil {
		return APIKeyMaterial{}, storageError(ctx)
	}
	rows, e := tx.QueryContext(ctx, `SELECT DISTINCT g.authenticator_hash,g.purpose FROM space.address_grants g JOIN space.private_addresses a ON a.source_id=g.source_id AND a.id=g.address_id
 WHERE a.id=$1 AND g.auth_generation=a.auth_generation AND g.authenticator_kind='api_key' AND g.purpose IN ('latest_read','mail_read','mail_consume','raw_read')
 AND g.hash_scheme=$2 AND g.hash_version=$3 AND octet_length(g.authenticator_hash)=32 AND g.revoked_at IS NULL AND g.issued_at<=$4 AND (g.expires_at IS NULL OR g.expires_at>$4) `+validAncestry("$4")+` ORDER BY g.purpose`, addressID, HashScheme, HashVersion, a.clock())
	if e != nil {
		return APIKeyMaterial{}, storageError(ctx)
	}
	var expected []byte
	purposes := []Purpose{}
	for rows.Next() {
		var hash []byte
		var purpose Purpose
		if e = rows.Scan(&hash, &purpose); e != nil {
			rows.Close()
			return APIKeyMaterial{}, storageError(ctx)
		}
		if expected == nil {
			expected = append([]byte(nil), hash...)
		} else if !bytes.Equal(expected, hash) {
			rows.Close()
			return APIKeyMaterial{}, ErrUnavailable
		}
		purposes = append(purposes, purpose)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return APIKeyMaterial{}, storageError(ctx)
	}
	if len(expected) != 32 {
		return APIKeyMaterial{}, ErrUnavailable
	}
	owner := Owner{InstallationID: a.installationID, AddressID: addressID, Generation: generation}
	var envelope []byte
	e = tx.QueryRowContext(ctx, `SELECT bundle_envelope FROM space.address_credential_bundles WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3`, source, addressID, generation).Scan(&envelope)
	key := ""
	if e == nil {
		bundle, de := OpenBundle(a.box, owner, envelope)
		if de != nil {
			return APIKeyMaterial{}, de
		}
		hash := Hash(bundle.API.Key)
		if !bytes.Equal(hash[:], expected) {
			key = "" // a residual document is not current API authority
		} else {
			key = bundle.API.Key
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return APIKeyMaterial{}, storageError(ctx)
	}
	if key == "" {
		// Acknowledged documents can still be the only retained original API
		// bytes. Their original owner is never replaced and ACK is never changed.
		var before int64
		for {
			var id int64
			var originalOwner string
			e = tx.QueryRowContext(ctx, `SELECT id,owner_key,secret_envelope FROM space.pending_reveals WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND ($4::bigint=0 OR id<$4) ORDER BY id DESC LIMIT 1`, source, addressID, generation, before).Scan(&id, &originalOwner, &envelope)
			if errors.Is(e, sql.ErrNoRows) {
				return APIKeyMaterial{}, ErrUnavailable
			}
			if e != nil {
				return APIKeyMaterial{}, storageError(ctx)
			}
			if originalOwner == "" {
				return APIKeyMaterial{}, ErrUnavailable
			}
			pending, de := OpenPending(a.box, owner, envelope)
			if de != nil {
				return APIKeyMaterial{}, de
			}
			hash := Hash(pending.APIKey)
			if bytes.Equal(hash[:], expected) {
				key = pending.APIKey
				break
			}
			before = id
		}
	}
	if tx.Commit() != nil {
		return APIKeyMaterial{}, storageError(ctx)
	}
	return APIKeyMaterial{Key: key, Purposes: purposes}, nil
}
