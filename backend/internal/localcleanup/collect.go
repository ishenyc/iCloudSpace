package localcleanup

import (
	"context"
	"database/sql"
	"errors"

	"icloudspace/internal/blobstore"
)

const objectColumns = `operation_key,source_id,object_key,publication_generation,manifest_version,owner_key,receipt_key,staging_ref,storage_ref,byte_size,encode(sha256,'hex'),state`

func scanObject(row interface{ Scan(...any) error }) (object, error) {
	var o object
	r := &o.Receipt
	e := row.Scan(&o.OperationKey, &o.SourceID, &r.Identity.ObjectKey, &r.Identity.Generation, &r.Version, &r.Identity.OwnerKey, &r.ReceiptKey, &r.StagingRef, &r.StorageRef, &r.ByteSize, &r.SHA256, &o.State)
	return o, e
}
func (s *Service) process(ctx context.Context, o object) (string, error) {
	if !validReceipt(o.Receipt) {
		return "needs_review", ErrEvidence
	}
	g, e := s.guards.Acquire(ctx, o.SourceID)
	if e != nil {
		return "", e
	}
	defer g.Close()
	state, e := s.prove(ctx, o, true)
	if errors.Is(e, ErrUnknown) {
		state, e = s.prove(ctx, o, false)
	}
	if e != nil {
		return "", e
	}
	if state != "ready" {
		return state, s.record(ctx, o, state, "")
	}
	if e = s.files.Collect(ctx, o.Receipt); e == nil {
		if _, e = s.files.VerifyRetired(ctx, o.Receipt); e != nil {
			return "needs_review", s.record(ctx, o, "needs_review", "remaining_claim_bytes")
		}
		return "collected", s.record(ctx, o, "collected", "")
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	inspection, ie := s.files.Inspect(ctx, o.Receipt.Identity)
	if ie == nil && inspection.State == blobstore.Absent {
		if state, e := s.files.VerifyRetired(ctx, o.Receipt); e == nil && state == blobstore.Absent {
			return "absent", s.record(ctx, o, "absent", "")
		}
	}
	// A valid original claim/manifest and a full actual-byte observation are
	// required even for intentionally deleting a damaged body.
	observed, e := s.files.ObserveCorrupt(ctx, o.Receipt)
	if e != nil {
		return "needs_review", s.record(ctx, o, "needs_review", "file_evidence_unavailable")
	}
	if e = s.saveObservation(ctx, o, observed); e != nil {
		return "", e
	}
	if e = s.files.RetireCorrupt(ctx, o.Receipt, observed); e != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "needs_review", s.record(ctx, o, "needs_review", "observed_body_changed")
	}
	if _, e = s.files.VerifyRetired(ctx, o.Receipt); e != nil {
		return "needs_review", s.record(ctx, o, "needs_review", "remaining_claim_bytes")
	}
	return "collected", s.record(ctx, o, "collected", "")
}
func (s *Service) prove(ctx context.Context, o object, authorize bool) (string, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return "", storage(ctx)
	}
	defer tx.Rollback()
	var source int64
	if tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, o.SourceID).Scan(&source) != nil {
		return "", ErrEvidence
	}
	if e = s.writable(ctx, tx); e != nil {
		return "", e
	}
	var scrubbed bool
	if tx.QueryRowContext(ctx, `SELECT payload_scrubbed FROM space.local_cleanup_operations WHERE operation_key=$1 AND source_id=$2 FOR UPDATE`, o.OperationKey, o.SourceID).Scan(&scrubbed) != nil || !scrubbed {
		return "", ErrEvidence
	}
	stored, e := scanObject(tx.QueryRowContext(ctx, `SELECT `+objectColumns+` FROM space.local_cleanup_objects WHERE operation_key=$1 AND object_key=$2 AND publication_generation=$3 FOR UPDATE`, o.OperationKey, o.Receipt.Identity.ObjectKey, o.Receipt.Identity.Generation))
	if e != nil || stored.Receipt != o.Receipt || stored.SourceID != o.SourceID {
		return "", ErrEvidence
	}
	if stored.State == "collected" || stored.State == "absent" || stored.State == "shared" {
		return stored.State, nil
	}
	var generation, size int64
	var digest, state string
	var version int
	e = tx.QueryRowContext(ctx, `SELECT publication_generation,manifest_version,byte_size,encode(sha256,'hex'),state FROM space.content_objects WHERE source_id=$1 AND object_key=$2 FOR UPDATE`, o.SourceID, o.Receipt.Identity.ObjectKey).Scan(&generation, &version, &size, &digest, &state)
	if e != nil || generation < o.Receipt.Identity.Generation || version != o.Receipt.Version || size != o.Receipt.ByteSize || digest != o.Receipt.SHA256 {
		return "", ErrEvidence
	}
	var owner, receipt, staging, pstate string
	e = tx.QueryRowContext(ctx, `SELECT owner_key,receipt_key,staging_ref,state FROM space.content_publications WHERE source_id=$1 AND object_key=$2 AND publication_generation=$3 FOR UPDATE`, o.SourceID, o.Receipt.Identity.ObjectKey, o.Receipt.Identity.Generation).Scan(&owner, &receipt, &staging, &pstate)
	if e != nil || owner != o.Receipt.Identity.OwnerKey || receipt != o.Receipt.ReceiptKey || staging != o.Receipt.StagingRef {
		return "", ErrEvidence
	}
	var protected bool
	e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.content_publications WHERE object_key=$1 AND state IN ('staged','published','sql_unknown')) OR EXISTS(SELECT 1 FROM space.intake_batches WHERE source_id=$2 AND state='prepared')`, o.Receipt.Identity.ObjectKey, o.SourceID).Scan(&protected)
	if e != nil {
		return "", storage(ctx)
	}
	if protected || pstate != "committed" && pstate != "abandoned" {
		return "protected", nil
	}
	if generation == o.Receipt.Identity.Generation {
		var live bool
		e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.source_messages m WHERE m.source_id=$1 AND m.object_key=$2 AND (`+liveMessage+`))`, o.SourceID, o.Receipt.Identity.ObjectKey).Scan(&live)
		if e != nil {
			return "", storage(ctx)
		}
		if live {
			return "shared", nil
		}
		if state != "evicted" {
			if !authorize {
				return "", ErrUnknown
			}
			if _, e = tx.ExecContext(ctx, `UPDATE space.content_objects SET state='evicted',evicted_at=coalesce(evicted_at,$4) WHERE source_id=$1 AND object_key=$2 AND publication_generation=$3`, o.SourceID, o.Receipt.Identity.ObjectKey, o.Receipt.Identity.Generation, s.options.Clock()); e != nil {
				return "", storage(ctx)
			}
		}
	}
	commit := s.commit
	if !authorize {
		commit = (*sql.Tx).Commit
	}
	if e = commit(tx); e != nil {
		return "", ErrUnknown
	}
	return "ready", nil
}
func (s *Service) record(ctx context.Context, o object, state, code string) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return storage(ctx)
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return e
	}
	now := s.options.Clock()
	res, e := tx.ExecContext(ctx, `UPDATE space.local_cleanup_objects SET state=$4,last_error_code=$5,updated_at=greatest(updated_at+1,$6),collected_at=CASE WHEN $4 IN ('collected','absent') THEN coalesce(collected_at,$6) ELSE collected_at END WHERE operation_key=$1 AND object_key=$2 AND publication_generation=$3`, o.OperationKey, o.Receipt.Identity.ObjectKey, o.Receipt.Identity.Generation, state, code, now)
	if e != nil {
		return storage(ctx)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrConflict
	}
	if e = s.commit(tx); e != nil {
		return ErrUnknown
	}
	return nil
}
func (s *Service) saveObservation(ctx context.Context, o object, observed blobstore.CorruptBody) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return storage(ctx)
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE space.local_cleanup_objects SET observed_byte_size=$4,observed_sha256=decode($5,'hex') WHERE operation_key=$1 AND object_key=$2 AND publication_generation=$3`, o.OperationKey, o.Receipt.Identity.ObjectKey, o.Receipt.Identity.Generation, observed.ByteSize, observed.SHA256)
	if e != nil {
		return storage(ctx)
	}
	if e = s.commit(tx); e == nil {
		return nil
	}
	tx.Rollback()
	var size int64
	var digest string
	if s.db.QueryRowContext(ctx, `SELECT observed_byte_size,encode(observed_sha256,'hex') FROM space.local_cleanup_objects WHERE operation_key=$1 AND object_key=$2 AND publication_generation=$3`, o.OperationKey, o.Receipt.Identity.ObjectKey, o.Receipt.Identity.Generation).Scan(&size, &digest) != nil || size != observed.ByteSize || digest != observed.SHA256 {
		return ErrUnknown
	}
	return nil
}
