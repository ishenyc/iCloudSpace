package bodymaintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"

	"icloudspace/internal/blobstore"
)

// This is a narrow read of the new intake owner's persisted claim document,
// not a decoder for old storage formats. The abandoned SQL row is the rollback
// proof. Merely failing to find a checkpoint, or an old timestamp, is not proof.
type orphanClaim struct {
	Batch              string
	SourceID, Ordinal  int64
	Identity           blobstore.Identity
	UID                uint32
	PreviousGeneration int64
}
type claimDocument struct {
	UID                uint32             `json:"uid"`
	Identity           blobstore.Identity `json:"identity"`
	PreviousGeneration int64              `json:"previous_generation"`
}

func decodeClaim(batch string, source, ordinal int64, raw []byte) (orphanClaim, error) {
	var doc claimDocument
	if source < 1 || ordinal < 1 || ordinal > 32 || json.Unmarshal(raw, &doc) != nil || doc.UID == 0 || doc.Identity.OwnerKey != batch || doc.PreviousGeneration < 0 || doc.PreviousGeneration >= doc.Identity.Generation {
		return orphanClaim{}, ErrEvidence
	}
	if _, e := blobstore.Describe(doc.Identity); e != nil {
		return orphanClaim{}, ErrEvidence
	}
	return orphanClaim{Batch: batch, SourceID: source, Ordinal: ordinal, Identity: doc.Identity, UID: doc.UID, PreviousGeneration: doc.PreviousGeneration}, nil
}
func (s *Service) orphanPage(ctx context.Context, result *Result) error {
	rows, e := s.db.QueryContext(ctx, `SELECT b.batch_key,b.source_id,c.ordinality,c.value FROM space.intake_batches b
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(b.plan->'intent'->'claims')='array' THEN b.plan->'intent'->'claims' ELSE '[]'::jsonb END) WITH ORDINALITY c(value,ordinality)
 WHERE b.state='abandoned' AND (b.batch_key,c.ordinality)>($1,$2::bigint) ORDER BY b.batch_key,c.ordinality LIMIT $3`, s.orphanAfter, s.orphanOrdinal, s.options.BatchSize)
	if e != nil {
		return storage(ctx)
	}
	type row struct {
		batch           string
		source, ordinal int64
		raw             []byte
	}
	var claims []row
	for rows.Next() {
		var r row
		if e = rows.Scan(&r.batch, &r.source, &r.ordinal, &r.raw); e != nil {
			rows.Close()
			return storage(ctx)
		}
		claims = append(claims, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return storage(ctx)
	}
	if len(claims) < s.options.BatchSize {
		s.orphanAfter = ""
		s.orphanOrdinal = 0
	} else {
		last := claims[len(claims)-1]
		s.orphanAfter = last.batch
		s.orphanOrdinal = last.ordinal
	}
	for _, r := range claims {
		claim, e := decodeClaim(r.batch, r.source, r.ordinal, r.raw)
		if e != nil {
			result.Unresolved++
			continue
		}
		guard, e := s.pageGuard(ctx, claim.SourceID)
		if errors.Is(e, ErrBusy) {
			result.Protected++
			continue
		}
		if e != nil {
			return e
		}
		collected, e := s.reclaimOrphanHeld(ctx, claim)
		guard.Close()
		switch {
		case e == nil:
			if collected {
				result.Collected++
				result.Orphans++
			}
		case errors.Is(e, ErrProtected) || errors.Is(e, ErrStale):
			result.Protected++
		case errors.Is(e, ErrEvidence):
			result.Unresolved++
		default:
			return e
		}
	}
	return nil
}
func (s *Service) proveOrphan(ctx context.Context, claim orphanClaim, receipt blobstore.Receipt, authorize bool) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return storage(ctx)
	}
	defer tx.Rollback()
	if e = s.lockSource(ctx, tx, claim.SourceID); e != nil {
		return e
	}
	if e = s.writable(ctx, tx); e != nil {
		return e
	}
	var state, batch, sourceText string
	var raw []byte
	e = tx.QueryRowContext(ctx, `SELECT state,coalesce(plan->'intent'->>'batch_key',''),coalesce(plan->'intent'->'snapshot'->'source'->>'id',''),plan->'intent'->'claims'->($3::integer-1) FROM space.intake_batches WHERE batch_key=$1 AND source_id=$2 FOR UPDATE`, claim.Batch, claim.SourceID, claim.Ordinal).Scan(&state, &batch, &sourceText, &raw)
	if e != nil {
		return ErrProtected
	}
	source, parseErr := strconv.ParseInt(sourceText, 10, 64)
	fresh, e := decodeClaim(batch, source, claim.Ordinal, raw)
	if parseErr != nil || e != nil || fresh != claim || state != "abandoned" {
		return ErrProtected
	}
	var pending bool
	e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.intake_batches WHERE source_id=$3 AND state='prepared') OR EXISTS(SELECT 1 FROM space.intake_batches b CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(b.plan->'intent'->'claims')='array' THEN b.plan->'intent'->'claims' ELSE '[]'::jsonb END) c
 WHERE b.state<>'abandoned' AND c->'identity'->>'object_key'=$1 AND c->'identity'->>'generation'=$2)`, claim.Identity.ObjectKey, strconv.FormatInt(claim.Identity.Generation, 10), claim.SourceID).Scan(&pending)
	if e != nil {
		return storage(ctx)
	}
	if pending {
		return ErrProtected
	}
	var pstate, powner, pkey, pstage string
	e = tx.QueryRowContext(ctx, `SELECT state,owner_key,receipt_key,staging_ref FROM space.content_publications WHERE object_key=$1 AND publication_generation=$2 FOR UPDATE`, claim.Identity.ObjectKey, claim.Identity.Generation).Scan(&pstate, &powner, &pkey, &pstage)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return storage(ctx)
	}
	if e == nil && (pstate != "abandoned" || powner != claim.Identity.OwnerKey || pkey != receipt.ReceiptKey || pstage != receipt.StagingRef) {
		return ErrProtected
	}
	var currentSource, currentGen, currentSize int64
	var currentState, currentSHA string
	e = tx.QueryRowContext(ctx, `SELECT source_id,publication_generation,state,byte_size,encode(sha256,'hex') FROM space.content_objects WHERE object_key=$1 FOR UPDATE`, claim.Identity.ObjectKey).Scan(&currentSource, &currentGen, &currentState, &currentSize, &currentSHA)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return storage(ctx)
	}
	if e == nil {
		if currentSource != claim.SourceID {
			return ErrProtected
		}
		if currentGen == claim.Identity.Generation {
			if currentState == "available" || currentSize != receipt.ByteSize || currentSHA != receipt.SHA256 {
				return ErrProtected
			}
			var referenced bool
			if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.source_messages WHERE object_key=$1)`, claim.Identity.ObjectKey).Scan(&referenced) != nil {
				return storage(ctx)
			}
			if referenced {
				return ErrProtected
			}
			if currentState != "evicted" {
				if !authorize {
					return ErrUnknown
				}
				if _, e = tx.ExecContext(ctx, `UPDATE space.content_objects SET state='evicted',evicted_at=coalesce(evicted_at,$3) WHERE object_key=$1 AND publication_generation=$2`, claim.Identity.ObjectKey, claim.Identity.Generation, s.options.Clock()); e != nil {
					return storage(ctx)
				}
			}
		}
	}
	commit := s.commit
	if !authorize {
		commit = (*sql.Tx).Commit
	}
	if e = commit(tx); e != nil {
		return ErrUnknown
	}
	return nil
}
func (s *Service) reclaimOrphan(ctx context.Context, claim orphanClaim) (bool, error) {
	guard, e := s.guards.Acquire(ctx, claim.SourceID)
	if e != nil {
		return false, e
	}
	defer guard.Close()
	return s.reclaimOrphanHeld(ctx, claim)
}
func (s *Service) reclaimOrphanHeld(ctx context.Context, claim orphanClaim) (bool, error) {
	observed, e := s.files.Inspect(ctx, claim.Identity)
	tornCollection := errors.Is(e, blobstore.ErrIncomplete) && observed.State == blobstore.Collected
	if e != nil && !tornCollection {
		return false, ErrEvidence
	}
	if observed.State == blobstore.Absent {
		return false, nil
	}
	if observed.Receipt == nil || observed.Receipt.Identity != claim.Identity {
		return false, ErrEvidence
	}
	if observed.State == blobstore.Collected && !tornCollection {
		return false, nil
	}
	if observed.State != blobstore.Published && observed.State != blobstore.Staged && !tornCollection {
		return false, ErrEvidence
	}
	receipt := *observed.Receipt
	if !validReference(Reference{SourceID: claim.SourceID, Receipt: receipt}) {
		return false, ErrEvidence
	}
	if e = s.proveOrphan(ctx, claim, receipt, true); e != nil {
		if !errors.Is(e, ErrUnknown) {
			return false, e
		}
		// Retry only the independent SQL proof. This does not publish/replay a
		// batch and cannot turn prepared or unknown into abandoned.
		if e = s.proveOrphan(ctx, claim, receipt, false); e != nil {
			return false, ErrUnknown
		}
	}
	if e = s.files.Collect(ctx, receipt); e != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, ErrEvidence
	}
	return true, nil
}
