package addresses

import (
	"context"
	"database/sql"
	"encoding/json"
)

// ExportSelection checks the complete explicit ID set before emitting metadata.
// It deliberately does not use the normal tombstone-hiding list predicate: a
// missing, archived, candidate or deleted requested row fails the whole export.
// Only metadata is streamed; the caller owns a credential RevealScope and must
// keep it through the complete sensitive response. Order is ascending ID.
func (s *Service) ExportSelection(ctx context.Context, ids []int64, emit func(Metadata) error) error {
	if s == nil || len(ids) < 1 || len(ids) > MaximumLimit || emit == nil {
		return &FieldError{"selection"}
	}
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if id < 1 || seen[id] {
			return &FieldError{"selection"}
		}
		seen[id] = true
	}
	doc, e := json.Marshal(ids)
	if e != nil {
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	selection := ` FROM space.private_addresses a WHERE a.id IN (SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb))`
	var count int
	var eligible bool
	e = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(bool_and(a.lifecycle='confirmed' AND a.deleted_at IS NULL),false)`+selection, string(doc)).Scan(&count, &eligible)
	if e != nil {
		return e
	}
	if count != len(ids) {
		return ErrNotFound
	}
	if !eligible {
		return ErrIneligible
	}
	rows, e := tx.QueryContext(ctx, metadataQuery(selection), string(doc))
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		item, e := scan(rows)
		if e != nil {
			return e
		}
		if e = emit(item); e != nil {
			return e
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	rows.Close()
	return tx.Commit()
}
