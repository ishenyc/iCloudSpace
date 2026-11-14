package bodymaintenance

import (
	"context"
	"database/sql"
	"errors"

	"icloudspace/internal/blobstore"
)

// Verify rechecks exactly the caller's observed owner/generation/size/hash.
// A delayed missing-body report cannot downgrade a newly republished body.
func (s *Service) Verify(ctx context.Context, ref Reference) (CheckResult, error) {
	leave, e := s.enter(ctx)
	if e != nil {
		return CheckResult{}, e
	}
	defer leave()
	return s.verify(ctx, ref)
}
func (s *Service) verify(ctx context.Context, ref Reference) (result CheckResult, err error) {
	if !validReference(ref) {
		return result, ErrEvidence
	}
	guard, e := s.guards.Acquire(ctx, ref.SourceID)
	if e != nil {
		return result, e
	}
	defer guard.Close()
	return s.verifyHeld(ctx, ref)
}
func (s *Service) verifyHeld(ctx context.Context, ref Reference) (result CheckResult, err error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, storage(ctx)
	}
	defer tx.Rollback()
	if e = s.lockSource(ctx, tx, ref.SourceID); e != nil {
		return result, e
	}
	if e = s.writable(ctx, tx); e != nil {
		return result, e
	}
	current, e := scanObject(tx.QueryRowContext(ctx, `SELECT `+objectColumns+objectJoin+` WHERE o.source_id=$1 AND o.object_key=$2 FOR UPDATE OF o`, ref.SourceID, ref.Receipt.Identity.ObjectKey))
	if errors.Is(e, sql.ErrNoRows) {
		return result, ErrStale
	}
	if e != nil {
		return result, storage(ctx)
	}
	if !same(current.Reference, ref) || current.State != "available" {
		return result, ErrStale
	}
	if current.PublicationState != "committed" {
		return result, ErrProtected
	}
	if yes, e := protected(ctx, tx, ref.Receipt.Identity.ObjectKey); e != nil {
		return result, storage(ctx)
	} else if yes {
		return result, ErrProtected
	}
	file, openErr := s.files.OpenVerified(ctx, ref.Receipt)
	state := "available"
	if openErr == nil {
		file.Close()
	} else {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if errors.Is(openErr, blobstore.ErrClosed) || errors.Is(openErr, blobstore.ErrIO) {
			return result, ErrStorage
		}
		inspection, ie := s.files.Inspect(ctx, ref.Receipt.Identity)
		state = "corrupt"
		if ie == nil && inspection.State == blobstore.Absent {
			state = "missing"
		}
	}
	now := s.options.Clock()
	res, e := tx.ExecContext(ctx, `UPDATE space.content_objects SET state=$7,verified_at=$8 WHERE source_id=$1 AND object_key=$2 AND publication_generation=$3 AND byte_size=$4 AND sha256=decode($5,'hex') AND storage_ref=$6 AND state='available'`, ref.SourceID, ref.Receipt.Identity.ObjectKey, ref.Receipt.Identity.Generation, ref.Receipt.ByteSize, ref.Receipt.SHA256, ref.Receipt.StorageRef, state, now)
	if e != nil {
		return result, storage(ctx)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return result, ErrStale
	}
	if state != "available" {
		// Parsed snapshots remain historical facts. Only the source-message raw
		// availability projection changes; identities/codes/views are retained.
		_, e = tx.ExecContext(ctx, `UPDATE space.source_messages m SET content_state='metadata_only' WHERE m.source_id=$1 AND m.object_key=$2 AND EXISTS(SELECT 1 FROM space.content_objects o WHERE o.source_id=m.source_id AND o.object_key=m.object_key AND o.publication_generation=$3 AND o.byte_size=$4 AND o.sha256=decode($5,'hex') AND o.state=$6)`, ref.SourceID, ref.Receipt.Identity.ObjectKey, ref.Receipt.Identity.Generation, ref.Receipt.ByteSize, ref.Receipt.SHA256, state)
		if e != nil {
			return result, storage(ctx)
		}
	}
	if e = s.commit(tx); e != nil {
		tx.Rollback()
		var actual string
		e = s.db.QueryRowContext(ctx, `SELECT state FROM space.content_objects WHERE source_id=$1 AND object_key=$2 AND publication_generation=$3 AND byte_size=$4 AND sha256=decode($5,'hex') AND storage_ref=$6 AND verified_at=$7`, ref.SourceID, ref.Receipt.Identity.ObjectKey, ref.Receipt.Identity.Generation, ref.Receipt.ByteSize, ref.Receipt.SHA256, ref.Receipt.StorageRef, now).Scan(&actual)
		if e != nil || actual != state {
			return result, ErrUnknown
		}
		result.Recovered = true
	}
	result.State = state
	result.Changed = state != "available"
	return result, nil
}
func (s *Service) verifyPage(ctx context.Context, result *Result) error {
	rows, e := s.db.QueryContext(ctx, `SELECT `+objectColumns+objectJoin+` WHERE o.state='available' AND o.object_key>$1 ORDER BY o.object_key LIMIT $2`, s.verifyAfter, s.options.BatchSize)
	if e != nil {
		return storage(ctx)
	}
	var refs []Reference
	for rows.Next() {
		o, e := scanObject(rows)
		if e != nil {
			rows.Close()
			return storage(ctx)
		}
		refs = append(refs, o.Reference)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return storage(ctx)
	}
	if len(refs) < s.options.BatchSize {
		s.verifyAfter = ""
	} else {
		s.verifyAfter = refs[len(refs)-1].Receipt.Identity.ObjectKey
	}
	groups := make(map[int64][]Reference)
	for _, ref := range refs {
		groups[ref.SourceID] = append(groups[ref.SourceID], ref)
	}
	for _, source := range sourceIDs(refs) {
		page := groups[source]
		guard, e := s.pageGuard(ctx, source)
		if errors.Is(e, ErrBusy) {
			result.Protected += len(page)
			continue
		}
		if e != nil {
			return e
		}
		checked, e := s.verifyPageHeld(ctx, page)
		guard.Close()
		if e != nil {
			return e
		}
		result.Verified += checked.Verified
		result.Damaged += checked.Damaged
		result.Protected += checked.Protected
		result.Unresolved += checked.Unresolved
		result.Recovered += checked.Recovered
	}
	return nil
}
