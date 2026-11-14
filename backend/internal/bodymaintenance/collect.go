package bodymaintenance

import (
	"context"
	"errors"
	"sync"

	"icloudspace/internal/blobstore"
)

func (s *Service) collect(ctx context.Context, ref Reference) (bool, error) {
	if !validReference(ref) {
		return false, ErrEvidence
	}
	guard, e := s.guards.Acquire(ctx, ref.SourceID)
	if e != nil {
		return false, e
	}
	defer guard.Close()
	return s.collectHeld(ctx, ref)
}

// proveCollection is a fresh SQL read after acquiring the shared source guard.
// A current evicted generation or a strictly superseded committed generation
// has no live body reference. Source-message references always resolve through
// the current content_object generation, never a historical file generation.
func (s *Service) proveCollection(ctx context.Context, ref Reference) error {
	proofs, e := s.proveCollectionPage(ctx, []Reference{ref})
	if e != nil {
		return e
	}
	return proofs[0]
}

// A page shares the same source guard through this fresh SQL proof and every
// subsequent file operation. Row locks end before file IO; the source owner
// still cannot replace a generation between proof and collection.
func (s *Service) proveCollectionPage(ctx context.Context, refs []Reference) ([]error, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	keys, receipts := make([]string, len(refs)), make([]string, len(refs))
	for i, ref := range refs {
		keys[i], receipts[i] = ref.Receipt.Identity.ObjectKey, ref.Receipt.ReceiptKey
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, storage(ctx)
	}
	defer tx.Rollback()
	for _, source := range sourceIDs(refs) {
		if e = s.lockSource(ctx, tx, source); e != nil {
			return nil, e
		}
	}
	if e = s.writable(ctx, tx); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT `+objectColumns+objectJoin+` WHERE o.object_key=ANY($1::text[]) ORDER BY o.object_key FOR UPDATE OF o`, keys)
	if e != nil {
		return nil, storage(ctx)
	}
	current := make(map[string]object, len(refs))
	for rows.Next() {
		o, scanErr := scanObject(rows)
		if scanErr != nil {
			rows.Close()
			return nil, storage(ctx)
		}
		current[o.Receipt.Identity.ObjectKey] = o
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, storage(ctx)
	}
	type publication struct {
		source, generation               int64
		object, owner, key, stage, state string
	}
	publications := make(map[string]publication, len(refs))
	rows, e = tx.QueryContext(ctx, `SELECT source_id,object_key,publication_generation,owner_key,receipt_key,staging_ref,state FROM space.content_publications WHERE receipt_key=ANY($1::text[]) ORDER BY receipt_key FOR UPDATE`, receipts)
	if e != nil {
		return nil, storage(ctx)
	}
	for rows.Next() {
		var p publication
		if e = rows.Scan(&p.source, &p.object, &p.generation, &p.owner, &p.key, &p.stage, &p.state); e != nil {
			rows.Close()
			return nil, storage(ctx)
		}
		publications[p.key] = p
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, storage(ctx)
	}
	protection := make(map[string]bool, len(refs))
	rows, e = tx.QueryContext(ctx, `SELECT o.object_key,
 EXISTS(SELECT 1 FROM space.content_publications p WHERE p.object_key=o.object_key AND p.state IN ('staged','published','sql_unknown'))
 OR EXISTS(SELECT 1 FROM space.intake_batches b WHERE b.source_id=o.source_id AND b.state='prepared')
 FROM space.content_objects o WHERE o.object_key=ANY($1::text[])`, keys)
	if e != nil {
		return nil, storage(ctx)
	}
	for rows.Next() {
		var key string
		var yes bool
		if e = rows.Scan(&key, &yes); e != nil {
			rows.Close()
			return nil, storage(ctx)
		}
		protection[key] = yes
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, storage(ctx)
	}
	proofs := make([]error, len(refs))
	for i, ref := range refs {
		r := ref.Receipt
		o, exists := current[r.Identity.ObjectKey]
		p, published := publications[r.ReceiptKey]
		switch {
		case !exists || o.SourceID != ref.SourceID:
			proofs[i] = ErrStale
		case !published || p.source != ref.SourceID || p.object != r.Identity.ObjectKey || p.generation != r.Identity.Generation || p.state != "committed" || p.owner != r.Identity.OwnerKey || p.key != r.ReceiptKey || p.stage != r.StagingRef:
			proofs[i] = ErrProtected
		case o.Receipt.Version != r.Version || o.Receipt.ByteSize != r.ByteSize || o.Receipt.SHA256 != r.SHA256:
			proofs[i] = ErrEvidence
		case o.Receipt.Identity.Generation < r.Identity.Generation:
			proofs[i] = ErrStale
		case o.Receipt.Identity.Generation == r.Identity.Generation && o.State != "evicted", protection[r.Identity.ObjectKey]:
			proofs[i] = ErrProtected
		}
	}
	// Even a read-only proof transaction is acknowledged before physical work.
	// Its error is not collection authority; the caller may independently retry
	// this proof but never compensates by removing files after an unknown write.
	if e = tx.Commit(); e != nil {
		return nil, ErrUnknown
	}
	return proofs, nil
}
func (s *Service) collectHeld(ctx context.Context, ref Reference) (bool, error) {
	if e := s.proveCollection(ctx, ref); e != nil {
		return false, e
	}
	return s.collectProven(ctx, ref)
}

func (s *Service) collectProven(ctx context.Context, ref Reference) (bool, error) {
	collected, e := s.files.CollectVerified(ctx, ref.Receipt)
	if e != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, ErrEvidence
	}
	return collected, nil
}

// Independent generations in this already-proven page may finish in any
// physical order. Join every started file operation before the caller releases
// the source guard; cancellation never leaves a collector running behind it.
func (s *Service) collectProvenPage(ctx context.Context, refs []Reference, proofs []error) ([]bool, []error) {
	collected := make([]bool, len(refs))
	results := append([]error(nil), proofs...)
	eligible := 0
	for _, proof := range proofs {
		if proof == nil {
			eligible++
		}
	}
	if eligible == 0 {
		return collected, results
	}
	work := make(chan int)
	var workers sync.WaitGroup
	for range min(8, eligible) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range work {
				if err := ctx.Err(); err != nil {
					results[i] = err
					continue
				}
				collected[i], results[i] = s.collectProven(ctx, refs[i])
			}
		}()
	}
	for i, proof := range proofs {
		if proof != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			results[i] = err
			continue
		}
		select {
		case work <- i:
		case <-ctx.Done():
			results[i] = ctx.Err()
		}
	}
	close(work)
	workers.Wait()
	return collected, results
}

// Group only this bounded page. Each source lease remains held after the SQL
// proof commits until its exact file generations have been processed.
func (s *Service) collectPage(ctx context.Context, refs []Reference) (Result, error) {
	var result Result
	groups := make(map[int64][]Reference)
	for _, ref := range refs {
		if !validReference(ref) {
			result.Unresolved++
			continue
		}
		groups[ref.SourceID] = append(groups[ref.SourceID], ref)
	}
	for _, source := range sourceIDs(refs) {
		page := groups[source]
		if len(page) == 0 {
			continue
		}
		guard, e := s.pageGuard(ctx, source)
		if errors.Is(e, ErrBusy) {
			result.Protected += len(page)
			continue
		}
		if e != nil {
			return result, e
		}
		e = func() error {
			defer guard.Close()
			proofs, e := s.proveCollectionPage(ctx, page)
			if errors.Is(e, ErrProtected) || errors.Is(e, ErrStale) {
				result.Protected += len(page)
				return nil
			}
			if e != nil {
				return e
			}
			collected, results := s.collectProvenPage(ctx, page, proofs)
			var firstError error
			for i, e := range results {
				switch {
				case e == nil:
					if collected[i] {
						result.Collected++
					}
				case errors.Is(e, ErrProtected) || errors.Is(e, ErrStale):
					result.Protected++
				case errors.Is(e, ErrEvidence):
					result.Unresolved++
				default:
					if firstError == nil {
						firstError = e
					}
				}
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return firstError
		}()
		if e != nil {
			return result, e
		}
	}
	return result, nil
}
func (s *Service) recoverPage(ctx context.Context, result *Result) error {
	rows, e := s.db.QueryContext(ctx, `SELECT o.source_id,p.object_key,o.manifest_version,o.byte_size,encode(o.sha256,'hex'),p.publication_generation,p.owner_key,p.receipt_key,p.staging_ref
 FROM space.content_publications p JOIN space.content_objects o ON o.source_id=p.source_id AND o.object_key=p.object_key
 WHERE p.state='committed' AND (p.publication_generation<o.publication_generation OR p.publication_generation=o.publication_generation AND o.state='evicted')
 AND p.receipt_key>$1 ORDER BY p.receipt_key LIMIT $2`, s.collectAfter, s.options.BatchSize)
	if e != nil {
		return storage(ctx)
	}
	var refs []Reference
	for rows.Next() {
		var ref Reference
		r := &ref.Receipt
		if e = rows.Scan(&ref.SourceID, &r.Identity.ObjectKey, &r.Version, &r.ByteSize, &r.SHA256, &r.Identity.Generation, &r.Identity.OwnerKey, &r.ReceiptKey, &r.StagingRef); e != nil {
			rows.Close()
			return storage(ctx)
		}
		described, de := blobstore.Describe(r.Identity)
		if de != nil {
			rows.Close()
			return ErrEvidence
		}
		r.StorageRef = described.StorageRef
		refs = append(refs, ref)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return storage(ctx)
	}
	if len(refs) < s.options.BatchSize {
		s.collectAfter = ""
	} else {
		s.collectAfter = refs[len(refs)-1].Receipt.ReceiptKey
	}
	collected, e := s.collectPage(ctx, refs)
	result.Collected += collected.Collected
	result.Protected += collected.Protected
	result.Unresolved += collected.Unresolved
	return e
}
