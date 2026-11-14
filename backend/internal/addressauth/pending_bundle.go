package addressauth

import (
	"context"
	"database/sql"
	"errors"
)

// PendingBundle is an explicit read of an already-issued current tuple. It
// never supplements a key, acknowledges its delivery, enables an address or
// changes a provider operation. Superseded deliveries retain their original
// API key through Pending, but cannot borrow the current generation's bundle.
func (s *RevealScope) PendingBundle(ctx context.Context, source int64, delivery, owner string) (Bundle, error) {
	if s == nil || source < 1 || !validKey(delivery) || !validKey(owner) {
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
	var addressID, generation int64
	var encoded []byte
	e = tx.QueryRowContext(ctx, `SELECT address_id,auth_generation,secret_envelope FROM space.pending_reveals WHERE source_id=$1 AND delivery_key=$2 AND owner_key=$3`, source, delivery, owner).Scan(&addressID, &generation, &encoded)
	if errors.Is(e, sql.ErrNoRows) {
		return Bundle{}, ErrUnavailable
	}
	if e != nil {
		return Bundle{}, storageError(ctx)
	}
	snapshot, e := readScope(ctx, tx, addressID, a.clock(), false)
	if e != nil {
		return Bundle{}, e
	}
	if len(snapshot.Addresses) != 1 {
		return Bundle{}, ErrUnavailable
	}
	address := snapshot.Addresses[0]
	if address.SourceID != source || address.Generation != generation || address.Deleted.Valid || !address.Mailbox {
		return Bundle{}, ErrUnavailable
	}
	pending, e := OpenPending(a.box, Owner{InstallationID: a.installationID, AddressID: addressID, Generation: generation}, encoded)
	if e != nil {
		return Bundle{}, e
	}
	bundle, e := a.readBundleMaterial(ctx, tx, address)
	if e != nil {
		return Bundle{}, e
	}
	if !equalBytes([]byte(bundle.API.Key), []byte(pending.APIKey)) {
		return Bundle{}, ErrUnavailable
	}
	if tx.Commit() != nil {
		return Bundle{}, storageError(ctx)
	}
	return bundle, nil
}
