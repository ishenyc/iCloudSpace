package addresses

import (
	"context"
	"database/sql"
)

// Pending candidates reserve one local slot even before confirmation creates
// their address row. UNION and the enabled anti-join prevent double counting a
// row and its operation, or two receipts for the same candidate.
func occupiedCapacity(ctx context.Context, tx *sql.Tx, sourceID int64, excludingOperation string) (int64, error) {
	var occupied int64
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM space.private_addresses WHERE source_id=$1 AND enabled AND deleted_at IS NULL)
 + (SELECT count(*) FROM (
   SELECT normalized_email AS email FROM space.private_addresses WHERE source_id=$1 AND NOT enabled AND lifecycle='pending' AND deleted_at IS NULL
   UNION
   SELECT lower(candidate_email) FROM space.address_operations WHERE source_id=$1 AND kind='create' AND state NOT IN ('confirmed','failed') AND candidate_email IS NOT NULL AND operation_key<>$2
 ) candidates WHERE NOT EXISTS(SELECT 1 FROM space.private_addresses a WHERE a.source_id=$1 AND a.normalized_email=candidates.email AND a.enabled AND a.deleted_at IS NULL))`, sourceID, excludingOperation).Scan(&occupied)
	return occupied, err
}

func (s *Service) capacityExcept(ctx context.Context, tx *sql.Tx, src source, extra int64, excludingOperation string) error {
	if src.Kind == "custom" || s.LocalAppleCapacity == 0 || extra < 1 {
		return nil
	}
	n, err := occupiedCapacity(ctx, tx, src.ID, excludingOperation)
	if err != nil {
		return err
	}
	if n+extra > s.LocalAppleCapacity {
		return ErrCapacity
	}
	return nil
}
