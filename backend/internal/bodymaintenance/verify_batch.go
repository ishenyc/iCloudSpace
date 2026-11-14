package bodymaintenance

import (
	"context"
	"errors"

	"icloudspace/internal/blobstore"
)

// The caller holds one source guard for this bounded page. Lock and validate
// every observed generation before reading files, then acknowledge their exact
// verification results together. File hashes and later collection proofs stay
// independent; only the repeated SQL round trips are shared.
func (s *Service) verifyPageHeld(ctx context.Context, refs []Reference) (result Result, err error) {
	if len(refs) == 0 {
		return result, nil
	}
	keys := make([]string, len(refs))
	for i, ref := range refs {
		if ref.SourceID != refs[0].SourceID {
			return result, ErrEvidence
		}
		keys[i] = ref.Receipt.Identity.ObjectKey
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, storage(ctx)
	}
	defer tx.Rollback()
	if e = s.lockSource(ctx, tx, refs[0].SourceID); e != nil {
		return result, e
	}
	if e = s.writable(ctx, tx); e != nil {
		return result, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT `+objectColumns+objectJoin+` WHERE o.source_id=$1 AND o.object_key=ANY($2::text[]) ORDER BY o.object_key FOR UPDATE OF o`, refs[0].SourceID, keys)
	if e != nil {
		return result, storage(ctx)
	}
	current := make(map[string]object, len(refs))
	for rows.Next() {
		o, scanErr := scanObject(rows)
		if scanErr != nil {
			rows.Close()
			return result, storage(ctx)
		}
		current[o.Receipt.Identity.ObjectKey] = o
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, storage(ctx)
	}
	rows, e = tx.QueryContext(ctx, `SELECT o.object_key,
 EXISTS(SELECT 1 FROM space.content_publications p WHERE p.object_key=o.object_key AND p.state IN ('staged','published','sql_unknown'))
 OR EXISTS(SELECT 1 FROM space.intake_batches b WHERE b.source_id=o.source_id AND b.state='prepared')
 FROM space.content_objects o WHERE o.object_key=ANY($1::text[])`, keys)
	if e != nil {
		return result, storage(ctx)
	}
	protection := make(map[string]bool, len(refs))
	for rows.Next() {
		var key string
		var protected bool
		if e = rows.Scan(&key, &protected); e != nil {
			rows.Close()
			return result, storage(ctx)
		}
		protection[key] = protected
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, storage(ctx)
	}
	keys, states := keys[:0], make([]string, 0, len(refs))
	var damaged []string
	for _, ref := range refs {
		o, exists := current[ref.Receipt.Identity.ObjectKey]
		if !exists || !same(o.Reference, ref) || o.State != "available" || o.PublicationState != "committed" || protection[ref.Receipt.Identity.ObjectKey] {
			result.Protected++
			continue
		}
		file, openErr := s.files.OpenVerified(ctx, ref.Receipt)
		state := "available"
		if openErr == nil {
			file.Close()
		} else {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			if errors.Is(openErr, blobstore.ErrClosed) || errors.Is(openErr, blobstore.ErrIO) {
				return Result{}, ErrStorage
			}
			inspection, inspectErr := s.files.Inspect(ctx, ref.Receipt.Identity)
			state = "corrupt"
			if inspectErr == nil && inspection.State == blobstore.Absent {
				state = "missing"
			}
		}
		keys = append(keys, ref.Receipt.Identity.ObjectKey)
		states = append(states, state)
		if state != "available" {
			damaged = append(damaged, ref.Receipt.Identity.ObjectKey)
		}
	}
	if len(keys) == 0 {
		return result, nil
	}
	now := s.options.Clock()
	// The exact rows were checked and remain locked under the source guard.
	changed, e := tx.ExecContext(ctx, `UPDATE space.content_objects o SET state=v.state,verified_at=$3
 FROM unnest($1::text[],$2::text[]) AS v(object_key,state)
 WHERE o.object_key=v.object_key AND o.state='available'`, keys, states, now)
	if e != nil {
		return Result{}, storage(ctx)
	}
	if count, e := changed.RowsAffected(); e != nil || count != int64(len(keys)) {
		return Result{}, ErrStale
	}
	if len(damaged) != 0 {
		if _, e = tx.ExecContext(ctx, `UPDATE space.source_messages SET content_state='metadata_only' WHERE source_id=$1 AND object_key=ANY($2::text[])`, refs[0].SourceID, damaged); e != nil {
			return Result{}, storage(ctx)
		}
	}
	if e = s.commit(tx); e != nil {
		// Do not repeat the update after a lost acknowledgement. Reconcile the
		// original exact generations and timestamp in one fresh read instead.
		tx.Rollback()
		rows, e = s.db.QueryContext(ctx, `SELECT `+objectColumns+`,o.verified_at`+objectJoin+` WHERE o.object_key=ANY($1::text[])`, keys)
		if e != nil {
			return Result{}, ErrUnknown
		}
		defer rows.Close()
		matched := make(map[string]bool, len(keys))
		for rows.Next() {
			var o object
			r := &o.Receipt
			var verified *int64
			if e = rows.Scan(&o.SourceID, &r.Identity.ObjectKey, &r.Version, &r.ByteSize, &r.SHA256, &r.StorageRef, &o.State, &r.Identity.Generation, &o.RetentionOrderAt, &r.Identity.OwnerKey, &r.ReceiptKey, &r.StagingRef, &o.PublicationState, &verified); e != nil {
				return Result{}, ErrUnknown
			}
			original, exists := current[r.Identity.ObjectKey]
			if exists && same(original.Reference, o.Reference) && verified != nil && *verified == now {
				for i, key := range keys {
					if key == r.Identity.ObjectKey && states[i] == o.State {
						matched[key] = true
					}
				}
			}
		}
		if rows.Err() != nil || len(matched) != len(keys) {
			return Result{}, ErrUnknown
		}
		result.Recovered = len(keys)
	}
	result.Verified = len(keys)
	result.Damaged = len(damaged)
	return result, nil
}
