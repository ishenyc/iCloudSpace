package localcleanup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"icloudspace/internal/blobstore"
	"icloudspace/internal/operationlog"
)

type request struct {
	Kind, Key, Owner, Confirmation string
	SourceID, AddressID, Revision  int64
}

func (s *Service) DeleteSource(ctx context.Context, r SourceDeleteRequest, fresh FreshAuthorization) (Receipt, error) {
	return s.retire(ctx, request{Kind: "source_delete", Key: r.OperationKey, Owner: r.OwnerKey, Confirmation: r.ConfirmNamespace, SourceID: r.SourceID, Revision: r.ExpectedRevision}, fresh)
}
func (s *Service) PurgeAddress(ctx context.Context, r AddressPurgeRequest, fresh FreshAuthorization) (Receipt, error) {
	if s == nil || r.AddressID < 1 || r.ExpectedSourceID < 0 {
		return Receipt{}, ErrInvalid
	}
	var source int64
	e := s.db.QueryRowContext(ctx, `SELECT source_id FROM space.private_addresses WHERE id=$1`, r.AddressID).Scan(&source)
	if errors.Is(e, sql.ErrNoRows) {
		return Receipt{}, ErrNotFound
	}
	if e != nil {
		return Receipt{}, storage(ctx)
	}
	if r.ExpectedSourceID != 0 && r.ExpectedSourceID != source {
		return Receipt{}, ErrConflict
	}
	return s.retire(ctx, request{Kind: "address_purge", Key: r.OperationKey, Owner: r.OwnerKey, Confirmation: r.ConfirmAddress, SourceID: source, AddressID: r.AddressID, Revision: r.ExpectedRevision}, fresh)
}
func (s *Service) retire(ctx context.Context, r request, fresh FreshAuthorization) (Receipt, error) {
	if s == nil || !key(r.Key) || !text(r.Owner, 256) || !text(r.Confirmation, 1024) || r.SourceID < 1 || r.Revision < 1 || fresh == nil {
		return Receipt{}, ErrInvalid
	}
	wire, _ := json.Marshal(r)
	digest := sha256.Sum256(wire)
	base := Receipt{OperationKey: r.Key, Kind: r.Kind, SourceID: r.SourceID, State: "unknown"}
	if r.AddressID != 0 {
		base.AddressID = &r.AddressID
	}
	guard, e := s.guards.Acquire(ctx, r.SourceID)
	if e != nil {
		return base, e
	}
	defer guard.Close()
	fence, e := s.options.BeginFence(ctx, guard)
	if e != nil {
		return base, e
	}
	defer fence.Close()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return base, storage(ctx)
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return base, e
	}
	var revision, generation int64
	var namespace string
	var retired sql.NullInt64
	e = tx.QueryRowContext(ctx, `SELECT revision,source_generation,address_namespace,retired_at FROM space.mail_sources WHERE id=$1 FOR UPDATE`, r.SourceID).Scan(&revision, &generation, &namespace, &retired)
	if errors.Is(e, sql.ErrNoRows) {
		return base, ErrNotFound
	}
	if e != nil {
		return base, storage(ctx)
	}
	// Same-key reconciliation precedes stale revision checks and never repeats
	// retirement. Fresh authorization is still required after the EX wait.
	if e = fresh(ctx, tx); e != nil {
		return base, e
	}
	var oldDigest []byte
	var oldOwner string
	e = tx.QueryRowContext(ctx, `SELECT request_digest,owner_key FROM space.local_cleanup_operations WHERE operation_key=$1 FOR UPDATE`, r.Key).Scan(&oldDigest, &oldOwner)
	if e == nil {
		if oldOwner != r.Owner || !bytes.Equal(oldDigest, digest[:]) {
			return base, ErrConflict
		}
		return readReceipt(ctx, tx, r.Key, r.Owner)
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return base, storage(ctx)
	}
	if retired.Valid || revision == math.MaxInt64 {
		return base, ErrConflict
	}
	if r.Kind == "source_delete" {
		if revision != r.Revision || namespace != r.Confirmation {
			return base, ErrConflict
		}
	} else {
		var address, lifecycle, kind string
		var deleted sql.NullInt64
		var rev int64
		e = tx.QueryRowContext(ctx, `SELECT email,lifecycle,kind,deleted_at,revision FROM space.private_addresses WHERE source_id=$1 AND id=$2 FOR UPDATE`, r.SourceID, r.AddressID).Scan(&address, &lifecycle, &kind, &deleted, &rev)
		if errors.Is(e, sql.ErrNoRows) {
			return base, ErrNotFound
		}
		if e != nil {
			return base, storage(ctx)
		}
		historical := deleted.Valid && (kind == "manual" || kind == "random")
		if rev != r.Revision || rev == math.MaxInt64 || address != r.Confirmation || !historical && (deleted.Valid || lifecycle != "archived") {
			return base, ErrConflict
		}
		if historical {
			var owned bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.local_cleanup_operations WHERE source_id=$1 AND (kind='source_delete' OR address_id=$2))`, r.SourceID, r.AddressID).Scan(&owned); e != nil {
				return base, storage(ctx)
			}
			if owned {
				return base, ErrConflict
			}
		}
	}
	now := s.options.Clock()
	var address any
	if r.AddressID != 0 {
		address = r.AddressID
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO space.local_cleanup_operations(operation_key,kind,source_id,address_id,owner_key,request_digest,expected_revision,source_generation,state,payload_scrubbed,inventory_complete,last_error_code,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'retired',false,false,'',$9,$9)`, r.Key, r.Kind, r.SourceID, address, r.Owner, digest[:], r.Revision, generation, now)
	if e != nil {
		return base, ErrConflict
	}
	if e = s.inventory(ctx, tx, r, now); e != nil {
		return base, fmt.Errorf("inventory: %w", e)
	}
	if r.Kind == "source_delete" {
		_, e = tx.ExecContext(ctx, `UPDATE space.mail_sources SET retired_at=$2::bigint,enabled=false,revision=revision+1,updated_at=greatest(updated_at+1,$2::bigint) WHERE id=$1`, r.SourceID, now)
		if e != nil {
			return base, sqlFailure(ctx, e, "source-retirement")
		}
	}
	_, e = tx.ExecContext(ctx, `UPDATE space.private_addresses SET deleted_at=coalesce(deleted_at,$3),enabled=false,revision=revision+1,label='',group_id=NULL,updated_at=greatest(updated_at+1,$3) WHERE source_id=$1 AND ($2::bigint=0 OR id=$2) AND (deleted_at IS NULL OR ($2::bigint<>0 AND id=$2))`, r.SourceID, r.AddressID, now)
	if e != nil {
		return base, storage(ctx)
	}
	_, e = tx.ExecContext(ctx, `UPDATE space.address_grants SET revoked_at=coalesce(revoked_at,$3) WHERE source_id=$1 AND ($2::bigint=0 OR address_id=$2)`, r.SourceID, r.AddressID, now)
	if e != nil {
		return base, storage(ctx)
	}
	if e = s.scrub(ctx, tx, r, now); e != nil {
		return base, fmt.Errorf("scrub: %w", e)
	}
	if e = operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: now, Action: "local_cleanup." + r.Kind, ResourceKind: "source", ResourceRef: r.Key, SourceID: &r.SourceID, CorrelationKey: r.Key, Outcome: "success", Fields: map[string]string{"component": "localcleanup"}})); e != nil {
		return base, e
	}
	if e = s.commit(tx); e != nil {
		fence.MarkUncertain()
		tx.Rollback()
		// This only proves the original transaction ended. A separate operation
		// lookup decides whether retirement actually committed. No file work here.
		if fence.Resolve(ctx) != nil {
			return base, ErrUnknown
		}
		confirmed, proofErr := s.queryLocked(ctx, r.SourceID, r.Key, r.Owner)
		if proofErr != nil {
			return base, ErrUnknown
		}
		return confirmed, nil
	}
	return s.queryLocked(ctx, r.SourceID, r.Key, r.Owner)
}

const targetMessages = `m.source_id=$1 AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM space.mailbox_entries e WHERE e.source_id=m.source_id AND e.address_id=$2 AND e.message_id=m.id) OR EXISTS(SELECT 1 FROM space.address_snapshots a WHERE a.source_id=m.source_id AND a.address_id=$2 AND a.message_id=m.id) OR EXISTS(SELECT 1 FROM space.message_views v WHERE v.source_id=m.source_id AND v.address_id=$2 AND v.message_id=m.id))`

func (s *Service) inventory(ctx context.Context, tx *sql.Tx, r request, now int64) error {
	// Only metadata is paged. File bytes are not opened during this transaction.
	// Every historical path comes from Describe with its own owner/generation.
	after := ""
	invalid := false
	for {
		rows, e := tx.QueryContext(ctx, `SELECT o.source_id,o.object_key,p.publication_generation,o.manifest_version,p.owner_key,p.receipt_key,p.staging_ref,o.byte_size,encode(o.sha256,'hex'),p.state
 FROM space.content_objects o JOIN space.content_publications p ON p.source_id=o.source_id AND p.object_key=o.object_key
 WHERE o.source_id=$1 AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM space.source_messages m WHERE m.object_key=o.object_key AND `+targetMessages+`)) AND p.receipt_key>$3 ORDER BY p.receipt_key LIMIT 128`, r.SourceID, r.AddressID, after)
		if e != nil {
			return storage(ctx)
		}
		var page []object
		scanned := 0
		lastReceipt := ""
		for rows.Next() {
			var o object
			var state string
			o.OperationKey = r.Key
			rr := &o.Receipt
			if rows.Scan(&o.SourceID, &rr.Identity.ObjectKey, &rr.Identity.Generation, &rr.Version, &rr.Identity.OwnerKey, &rr.ReceiptKey, &rr.StagingRef, &rr.ByteSize, &rr.SHA256, &state) != nil {
				rows.Close()
				return storage(ctx)
			}
			scanned++
			lastReceipt = rr.ReceiptKey
			refs, de := blobstore.Describe(rr.Identity)
			if de != nil {
				invalid = true
				continue
			}
			rr.StorageRef = refs.StorageRef
			if !validReceipt(*rr) {
				invalid = true
				continue
			}
			o.State = "ready"
			if state == "staged" || state == "published" || state == "sql_unknown" {
				o.State = "protected"
			}
			page = append(page, o)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return storage(ctx)
		}
		for _, o := range page {
			rr := o.Receipt
			if _, e = tx.ExecContext(ctx, `INSERT INTO space.local_cleanup_objects(operation_key,source_id,object_key,publication_generation,manifest_version,owner_key,receipt_key,staging_ref,storage_ref,byte_size,sha256,state,last_error_code,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,decode($11,'hex'),$12,'',$13,$13)`, r.Key, r.SourceID, rr.Identity.ObjectKey, rr.Identity.Generation, rr.Version, rr.Identity.OwnerKey, rr.ReceiptKey, rr.StagingRef, rr.StorageRef, rr.ByteSize, rr.SHA256, o.State, now); e != nil {
				return storage(ctx)
			}
		}
		if scanned < 128 {
			break
		}
		after = lastReceipt
	}
	var missing bool
	e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.content_objects o WHERE o.source_id=$1 AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM space.source_messages m WHERE m.object_key=o.object_key AND `+targetMessages+`)) AND NOT EXISTS(SELECT 1 FROM space.content_publications p WHERE p.source_id=o.source_id AND p.object_key=o.object_key))`, r.SourceID, r.AddressID).Scan(&missing)
	if e != nil {
		return storage(ctx)
	}
	code := ""
	if missing {
		code = "publication_evidence_missing"
	}
	if invalid {
		code = "publication_evidence_invalid"
	}
	_, e = tx.ExecContext(ctx, `UPDATE space.local_cleanup_operations SET inventory_complete=$2,last_error_code=$3 WHERE operation_key=$1`, r.Key, !missing && !invalid, code)
	if e != nil {
		return storage(ctx)
	}
	return nil
}
