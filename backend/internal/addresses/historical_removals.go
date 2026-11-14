package addresses

import (
	"context"
	"database/sql"
)

// HistoricalRemoval contains only enough identity metadata to explicitly clean
// an old locally hidden address. It is not an active address projection.
type HistoricalRemoval struct {
	ID, SourceID, Revision, DeletedAt int64
	Address, SourceLabel, Kind        string
}
type HistoricalRemovalPage struct {
	Items []HistoricalRemoval
	Total int64
}

const historicalRemovalPredicate = ` FROM space.private_addresses a JOIN space.mail_sources s ON s.id=a.source_id
 WHERE a.deleted_at IS NOT NULL AND a.kind IN ('manual','random') AND s.retired_at IS NULL
 AND ($1::bigint IS NULL OR a.source_id=$1) AND ($2::text='' OR strpos(lower(a.email),$2)>0 OR strpos(lower(a.label),$2)>0)
 AND NOT EXISTS(SELECT 1 FROM space.local_cleanup_operations c WHERE c.source_id=a.source_id AND (c.kind='source_delete' OR c.address_id=a.id))`

// HistoricalRemovals never reveals keys/bodies, revives a tombstone, or starts
// cleanup. Already owned cleanup work stays with its original receipt.
func (s *Service) HistoricalRemovals(ctx context.Context, source *int64, query string, page Page) (HistoricalRemovalPage, error) {
	f, p, err := normalizeFilter(Filter{SourceID: source, Query: query}, page)
	if err != nil {
		return HistoricalRemovalPage{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return HistoricalRemovalPage{}, err
	}
	defer tx.Rollback()
	out := HistoricalRemovalPage{Items: []HistoricalRemoval{}}
	if err = tx.QueryRowContext(ctx, `SELECT count(*)`+historicalRemovalPredicate, f.SourceID, f.Query).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.id,a.source_id,a.email,coalesce(nullif(s.display_name,''),s.address_namespace),a.kind,a.revision,a.deleted_at`+historicalRemovalPredicate+` ORDER BY a.id LIMIT $3 OFFSET $4`, f.SourceID, f.Query, p.Limit, p.Offset)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var item HistoricalRemoval
		if err = rows.Scan(&item.ID, &item.SourceID, &item.Address, &item.SourceLabel, &item.Kind, &item.Revision, &item.DeletedAt); err != nil {
			rows.Close()
			return out, err
		}
		out.Items = append(out.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
}
