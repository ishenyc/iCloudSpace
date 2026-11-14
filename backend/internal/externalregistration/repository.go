package externalregistration

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"icloudspace/internal/addresses"
)

type registration struct {
	Receipt
	ownerHash, digest []byte
	deliveryOwner     string
}

const receiptColumns = `operation_key,source_id,owner_hash,request_digest,normalized_email,delivery_owner,state,address_id,auth_generation,delivery_key`

type scanner interface{ Scan(...any) error }

func scanRegistration(row scanner) (registration, error) {
	var r registration
	var address, generation sql.NullInt64
	var delivery sql.NullString
	err := row.Scan(&r.OperationKey, &r.SourceID, &r.ownerHash, &r.digest, &r.Address, &r.deliveryOwner, &r.State, &address, &generation, &delivery)
	r.AddressID, r.Generation, r.DeliveryKey = address.Int64, generation.Int64, delivery.String
	r.QueryOnly = true
	return r, err
}
func canonicalRequest(r Request) (Request, [32]byte, error) {
	if r.SourceID < 1 || !validKey(r.OperationKey) {
		return r, [32]byte{}, ErrInvalid
	}
	normalized, err := addresses.NormalizeAddress(r.Address)
	if err != nil {
		return r, [32]byte{}, ErrInvalid
	}
	r.Address = normalized
	b, _ := json.Marshal(struct {
		Version int
		Source  int64
		Address string
	}{1, r.SourceID, r.Address})
	return r, sha256.Sum256(append([]byte("external-registration/v1\x00"), b...)), nil
}
func deliveryOwner(owner [32]byte, key string) string {
	b, _ := json.Marshal(struct {
		Owner [32]byte
		Key   string
	}{owner, key})
	h := sha256.Sum256(append([]byte("external-registration-delivery/v1\x00"), b...))
	return "external/" + hex.EncodeToString(h[:])
}
func (s *Service) beginWrite(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storage(ctx)
	}
	var id string
	var enabled bool
	if tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton FOR SHARE`).Scan(&id, &enabled) != nil || id != s.installation {
		tx.Rollback()
		return nil, ErrStorage
	}
	if !enabled {
		tx.Rollback()
		return nil, ErrReadOnly
	}
	return tx, nil
}
func lockSource(ctx context.Context, tx *sql.Tx, id int64) (bool, bool, error) {
	var enabled bool
	var retired sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT enabled,retired_at FROM space.mail_sources WHERE id=$1 FOR UPDATE`, id).Scan(&enabled, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, ErrNotFound
	}
	if err != nil {
		return false, false, storage(ctx)
	}
	return enabled, retired.Valid, nil
}
func matchOwner(r registration, a Access, source int64) bool {
	return r.SourceID == source && len(r.ownerHash) == 32 && subtle.ConstantTimeCompare(r.ownerHash, a.hash[:]) == 1
}

func (s *Service) prepare(ctx context.Context, a Access, r Request, digest [32]byte) (registration, bool, error) {
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return registration{}, false, err
	}
	attempted := false
	defer func() {
		if !attempted {
			tx.Rollback()
		}
	}()
	_, retired, err := lockSource(ctx, tx, r.SourceID)
	if err != nil {
		return registration{}, false, err
	}
	if err = compatibilityInput(ctx, tx, r); err != nil {
		return registration{}, false, err
	}
	existing, err := scanRegistration(tx.QueryRowContext(ctx, `SELECT `+receiptColumns+` FROM space.external_registrations WHERE operation_key=$1 FOR UPDATE`, r.OperationKey))
	if err == nil {
		if !matchOwner(existing, a, r.SourceID) || len(existing.digest) != 32 || subtle.ConstantTimeCompare(existing.digest, digest[:]) != 1 {
			return registration{}, false, ErrConflict
		}
		return existing, false, ErrQueryOnly
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return registration{}, false, storage(ctx)
	}
	if retired {
		return registration{}, false, ErrNotFound
	}
	owner := deliveryOwner(a.hash, r.OperationKey)
	_, err = tx.ExecContext(ctx, `INSERT INTO space.external_registrations(operation_key,source_id,owner_hash,request_digest,normalized_email,delivery_owner,state,created_at) VALUES($1,$2,$3,$4,$5,$6,'prepared',$7)`, r.OperationKey, r.SourceID, a.hash[:], digest[:], r.Address, owner, s.clock())
	if err != nil {
		return registration{}, false, classify(err)
	}
	out := registration{Receipt: Receipt{OperationKey: r.OperationKey, SourceID: r.SourceID, Address: r.Address, State: "prepared", QueryOnly: true}, ownerHash: append([]byte{}, a.hash[:]...), digest: append([]byte{}, digest[:]...), deliveryOwner: owner}
	attempted = true
	if err = s.commit(tx); err != nil {
		return out, true, ErrUnknown
	}
	return out, true, nil
}

// cancelPrepared takes the same source conflict lock before declaring the
// absence of committed business state. A timeout is never rollback proof.
func (s *Service) cancelPrepared(ctx context.Context, a Access, source int64, key string) (registration, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return registration{}, storage(ctx)
	}
	defer tx.Rollback()
	_, _, err = lockSource(ctx, tx, source)
	if err != nil {
		return registration{}, err
	}
	r, err := scanRegistration(tx.QueryRowContext(ctx, `SELECT `+receiptColumns+` FROM space.external_registrations WHERE operation_key=$1 FOR UPDATE`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return registration{}, ErrNotFound
	}
	if err != nil {
		return registration{}, storage(ctx)
	}
	if !matchOwner(r, a, source) {
		return registration{}, ErrNotFound
	}
	if r.State == "prepared" {
		var writes bool
		var installation string
		if tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton FOR SHARE`).Scan(&installation, &writes) != nil || installation != s.installation {
			return registration{}, ErrStorage
		}
		if writes {
			if _, err = tx.ExecContext(ctx, `UPDATE space.external_registrations SET state='cancelled',cancelled_at=$2 WHERE operation_key=$1 AND state='prepared'`, key, s.clock()); err != nil {
				return registration{}, storage(ctx)
			}
			r.State = "cancelled"
		}
	}
	if tx.Commit() != nil {
		return registration{}, ErrUnknown
	}
	return r, nil
}

func classify(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		if pg.Code == "23505" || pg.Code == "23503" || pg.Code == "40001" || pg.Code == "40P01" {
			return ErrConflict
		}
	}
	return ErrStorage
}
