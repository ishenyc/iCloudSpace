package addressauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	"icloudspace/internal/sourceguard"
)

// DeliveryRef is internal metadata. OwnerKey is needed to open historical
// owner-bound pending material; transports expose the delivery key, never this
// internal owner or its encrypted document.
type DeliveryRef struct {
	ID, SourceID, AddressID, Generation        int64
	Key, OwnerKey                              string
	CreatedAt                                  int64
	AcknowledgedAt                             *int64
	Address, Label, SourceLabel, Lifecycle     string
	Deleted, Enabled, Current, BundleAvailable bool
}

func (DeliveryRef) String() string   { return "addressauth: pending delivery reference" }
func (DeliveryRef) GoString() string { return "addressauth: pending delivery reference" }

type deliveryMetadata struct {
	DeliveryRef
	envelope []byte
}

func scanDelivery(row interface{ Scan(...any) error }) (deliveryMetadata, error) {
	var ref deliveryMetadata
	err := row.Scan(&ref.ID, &ref.SourceID, &ref.AddressID, &ref.Generation, &ref.Key, &ref.OwnerKey, &ref.CreatedAt, &ref.AcknowledgedAt,
		&ref.Address, &ref.Label, &ref.SourceLabel, &ref.Lifecycle, &ref.Deleted, &ref.Enabled, &ref.Current, &ref.BundleAvailable, &ref.envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return deliveryMetadata{}, ErrUnavailable
	}
	if err != nil {
		return deliveryMetadata{}, ErrStorage
	}
	return ref, nil
}

const deliveryColumns = `p.id,p.source_id,p.address_id,p.auth_generation,p.delivery_key,p.owner_key,p.created_at,p.acknowledged_at,
 a.email,a.label,coalesce(nullif(s.display_name,''),s.address_namespace),a.lifecycle,a.deleted_at IS NOT NULL,
 a.enabled AND s.enabled AND s.retired_at IS NULL,a.auth_generation=p.auth_generation,
 a.deleted_at IS NULL AND a.auth_generation=p.auth_generation AND EXISTS(SELECT 1 FROM space.address_credential_bundles b WHERE b.source_id=a.source_id AND b.address_id=a.id AND b.auth_generation=p.auth_generation),p.secret_envelope`
const deliveryTables = ` FROM space.pending_reveals p JOIN space.private_addresses a ON a.source_id=p.source_id AND a.id=p.address_id JOIN space.mail_sources s ON s.id=p.source_id`

func (a *Authority) Delivery(ctx context.Context, sourceID int64, key string) (DeliveryRef, error) {
	if a == nil || sourceID < 1 || !validKey(key) {
		return DeliveryRef{}, ErrInvalid
	}
	items, err := a.deliveryMetadata(ctx, ` WHERE p.source_id=$1 AND p.delivery_key=$2`, sourceID, key)
	if err != nil {
		return DeliveryRef{}, err
	}
	if len(items) != 1 {
		return DeliveryRef{}, ErrUnavailable
	}
	return items[0], nil
}

// PendingDeliveries returns only metadata in stable ID order. The original
// pending API key is opened internally solely to match its grant hash; neither
// secret material nor its hash leaves Authority. Reads never ACK or supplement.
func (a *Authority) PendingDeliveries(ctx context.Context, sourceID, afterID int64, limit int) ([]DeliveryRef, error) {
	if a == nil || sourceID < 1 || afterID < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	return a.deliveryMetadata(ctx, ` WHERE p.source_id=$1 AND p.id>$2 AND p.acknowledged_at IS NULL ORDER BY p.id LIMIT $3`, sourceID, afterID, limit)
}

func (a *Authority) deliveryMetadata(ctx context.Context, predicate string, args ...any) ([]DeliveryRef, error) {
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, storageError(ctx)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+deliveryColumns+deliveryTables+predicate, args...)
	if err != nil {
		return nil, storageError(ctx)
	}
	defer rows.Close()
	pending := []deliveryMetadata{}
	defer func() {
		for i := range pending {
			clear(pending[i].envelope)
		}
	}()
	for rows.Next() {
		ref, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		pending = append(pending, ref)
	}
	if rows.Err() != nil {
		return nil, storageError(ctx)
	}
	rows.Close()
	items := make([]DeliveryRef, 0, len(pending))
	now := a.clock()
	for _, item := range pending {
		ref := item.DeliveryRef
		if ref.Current {
			secret, err := OpenPending(a.box, Owner{InstallationID: a.installationID, AddressID: ref.AddressID, Generation: ref.Generation}, item.envelope)
			if err != nil {
				return nil, err
			}
			hash := Hash(secret.APIKey)
			secret.APIKey = ""
			// Generation is deliberately unchanged by API-key-only rotation.
			// Match this delivery's exact original key, never a newer bundle or timestamp.
			err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_grants WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND authenticator_kind='api_key' AND authenticator_hash=$4 AND hash_scheme=$5 AND hash_version=$6 AND parent_grant_id IS NULL AND revoked_at IS NULL AND issued_at<=$7 AND (expires_at IS NULL OR expires_at>$7))`, ref.SourceID, ref.AddressID, ref.Generation, hash[:], HashScheme, HashVersion, now).Scan(&ref.Current)
			clear(hash[:])
			if err != nil {
				return nil, storageError(ctx)
			}
		}
		ref.BundleAvailable = ref.BundleAvailable && ref.Current
		items = append(items, ref)
	}
	if tx.Commit() != nil {
		return nil, storageError(ctx)
	}
	return items, nil
}

// AcknowledgeDeliveries confirms exactly this source's explicit selection.
// Every key is checked before any write, including already-acknowledged keys.
// The original delivery owner, secret and first acknowledgement remain intact.
func (a *Authority) AcknowledgeDeliveries(ctx context.Context, sourceID int64, keys []string) error {
	if a == nil || sourceID < 1 || len(keys) < 1 || len(keys) > 1000 {
		return ErrInvalid
	}
	keys = append([]string(nil), keys...)
	sort.Strings(keys)
	for i, key := range keys {
		if !validKey(key) || i > 0 && key == keys[i-1] {
			return ErrInvalid
		}
	}
	release, err := a.gate.read(ctx)
	if err != nil {
		return err
	}
	defer release()
	if !a.readReady() {
		return ErrOutcomeUnknown
	}
	if err = sourceguard.CheckLocalMutation(ctx); err != nil {
		return err
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(ctx)
	}
	defer tx.Rollback()
	if err = a.checkWritable(ctx, tx); err != nil {
		return err
	}
	var locked int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, sourceID).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		return storageError(ctx)
	}
	selection, _ := json.Marshal(keys)
	rows, err := tx.QueryContext(ctx, `SELECT a.id FROM space.private_addresses a WHERE a.source_id=$1 AND a.id IN (SELECT address_id FROM space.pending_reveals WHERE source_id=$1 AND delivery_key IN (SELECT jsonb_array_elements_text($2::jsonb))) ORDER BY a.id FOR UPDATE`, sourceID, selection)
	if err != nil {
		return storageError(ctx)
	}
	for rows.Next() {
		if rows.Scan(&locked) != nil {
			rows.Close()
			return ErrStorage
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError(ctx)
	}
	rows, err = tx.QueryContext(ctx, `SELECT id FROM space.pending_reveals WHERE source_id=$1 AND delivery_key IN (SELECT jsonb_array_elements_text($2::jsonb)) ORDER BY id FOR UPDATE`, sourceID, selection)
	if err != nil {
		return storageError(ctx)
	}
	count := 0
	for rows.Next() {
		if rows.Scan(&locked) != nil {
			rows.Close()
			return ErrStorage
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storageError(ctx)
	}
	if count != len(keys) {
		return ErrUnavailable
	}
	_, err = tx.ExecContext(ctx, `UPDATE space.pending_reveals SET acknowledged_at=$3 WHERE source_id=$1 AND delivery_key IN (SELECT jsonb_array_elements_text($2::jsonb)) AND acknowledged_at IS NULL`, sourceID, selection, a.clock())
	if err != nil {
		return storageError(ctx)
	}
	if a.commit(tx) != nil {
		return ErrOutcomeUnknown
	}
	return nil
}
