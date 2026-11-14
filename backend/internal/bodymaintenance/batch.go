package bodymaintenance

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"icloudspace/internal/sourceguard"
)

const pageGuardWait = 5 * time.Millisecond
const fifoPageSQL = `SELECT ` + objectColumns + objectJoin + ` WHERE ` + eligibleFIFO + ` ORDER BY o.retention_order_at,o.object_key LIMIT $1`

type rowsQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func fifoPage(ctx context.Context, db rowsQuery, limit int) ([]Reference, error) {
	rows, e := db.QueryContext(ctx, fifoPageSQL, limit)
	if e != nil {
		return nil, batchError(ctx, e)
	}
	defer rows.Close()
	var refs []Reference
	for rows.Next() {
		o, e := scanObject(rows)
		if e != nil {
			return nil, storage(ctx)
		}
		if !validReference(o.Reference) {
			return nil, ErrEvidence
		}
		refs = append(refs, o.Reference)
	}
	if rows.Err() != nil {
		return nil, storage(ctx)
	}
	return refs, nil
}

func batchError(ctx context.Context, e error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var pg *pgconn.PgError
	if errors.As(e, &pg) && (pg.Code == "55P03" || pg.Code == "57014" || pg.Code == "40P01") {
		return ErrBusy
	}
	return ErrStorage
}

// Background pages give a busy source one short admission attempt per Step.
// The acquired lease outlives this timeout and is explicitly closed by its
// caller; canceling admission never releases active work behind its owner.
func (s *Service) pageGuard(ctx context.Context, id int64) (*sourceguard.Lease, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if s.pageBusy == nil {
		s.pageBusy = make(map[int64]bool)
	}
	if s.pageBusy[id] {
		return nil, ErrBusy
	}
	wait, cancel := context.WithTimeout(ctx, pageGuardWait)
	guard, e := s.guards.Acquire(wait, id)
	cancel()
	if e != nil && ctx.Err() == nil && errors.Is(e, context.DeadlineExceeded) {
		s.pageBusy[id] = true
		return nil, ErrBusy
	}
	return guard, e
}

func sourceIDs(refs []Reference) []int64 {
	set := map[int64]bool{}
	for _, r := range refs {
		set[r.SourceID] = true
	}
	ids := make([]int64, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (s *Service) pageGuards(ctx context.Context, refs []Reference) (func(), error) {
	var guards []*sourceguard.Lease
	close := func() {
		for i := len(guards) - 1; i >= 0; i-- {
			guards[i].Close()
		}
	}
	for _, id := range sourceIDs(refs) {
		guard, e := s.pageGuard(ctx, id)
		if e != nil {
			close()
			return nil, e
		}
		guards = append(guards, guard)
	}
	return close, nil
}

// All source guards are already owned before entering SQL. The table lock
// freezes global accounting only for this bounded transaction: no source
// admission, network work, file IO, or recovery proof runs while it is held.
func (s *Service) markEvicted(ctx context.Context, refs []Reference) (marked []Reference, recovered bool, err error) {
	if len(refs) == 0 {
		return nil, false, nil
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	defer func() {
		if err != nil && !errors.Is(err, ErrUnknown) && parent.Err() == nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = ErrBusy
		}
	}()
	now := s.options.Clock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, false, storage(ctx)
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SET LOCAL lock_timeout='50ms'; SET LOCAL statement_timeout='2s'`); e != nil {
		return nil, false, batchError(ctx, e)
	}
	for _, id := range sourceIDs(refs) {
		var actual int64
		if e = tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, id).Scan(&actual); e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				return nil, false, ErrStale
			}
			return nil, false, batchError(ctx, e)
		}
	}
	if e = s.writable(ctx, tx); e != nil {
		return nil, false, e
	}
	if _, e = tx.ExecContext(ctx, `LOCK TABLE space.content_objects IN SHARE ROW EXCLUSIVE MODE`); e != nil {
		return nil, false, batchError(ctx, e)
	}
	var size string
	if e = tx.QueryRowContext(ctx, `SELECT coalesce(sum(byte_size),0)::text FROM space.content_objects WHERE state='available'`).Scan(&size); e != nil {
		return nil, false, batchError(ctx, e)
	}
	remaining, ok := new(big.Int).SetString(size, 10)
	if !ok || remaining.Sign() < 0 {
		return nil, false, ErrStorage
	}
	capacity := big.NewInt(s.options.CapacityBytes)
	if remaining.Cmp(capacity) <= 0 {
		return nil, false, nil
	}
	fresh, e := fifoPage(ctx, tx, len(refs))
	if e != nil {
		return nil, false, e
	}
	for i, r := range fresh {
		if !same(r, refs[i]) {
			return nil, false, ErrStale
		}
		if remaining.Cmp(capacity) <= 0 {
			break
		}
		marked = append(marked, r)
		remaining.Sub(remaining, big.NewInt(r.Receipt.ByteSize))
	}
	if len(marked) == 0 {
		return nil, false, nil
	}
	keys := make([]string, len(marked))
	for i, r := range marked {
		keys[i] = r.Receipt.Identity.ObjectKey
	}
	res, e := tx.ExecContext(ctx, `UPDATE space.content_objects SET state='evicted',evicted_at=$2 WHERE object_key=ANY($1::text[]) AND state='available'`, keys, now)
	if e != nil {
		return nil, false, batchError(ctx, e)
	}
	if n, e := res.RowsAffected(); e != nil || n != int64(len(marked)) {
		return nil, false, ErrStale
	}
	if e = s.commit(tx); e != nil {
		// Never replay the update. Retain every file unless fresh SQL proves
		// each original exact-generation collection fact after releasing locks.
		tx.Rollback()
		for _, ref := range marked {
			if e = s.proveCollection(ctx, ref); e != nil {
				return nil, false, ErrUnknown
			}
		}
		recovered = true
	}
	return marked, recovered, nil
}
