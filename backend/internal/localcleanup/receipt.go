package localcleanup

import (
	"context"
	"database/sql"
	"errors"
)

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const retainedUnknown = `(SELECT count(*) FROM space.send_submissions WHERE source_id=c.source_id AND (c.address_id IS NULL OR address_id=c.address_id) AND outcome='unknown')+
 (SELECT count(*) FROM space.compose_contexts WHERE source_id=c.source_id AND (c.address_id IS NULL OR address_id=c.address_id) AND state IN ('reserved','preparing','candidate_unknown','candidate_confirmed','draft_ready','seed_unknown'))+
 (SELECT count(*) FROM space.address_operations WHERE source_id=c.source_id AND (c.address_id IS NULL OR address_id=c.address_id) AND state NOT IN ('confirmed','failed'))+
 (SELECT count(*) FROM space.intake_batches WHERE source_id=c.source_id AND state='prepared')+
 (SELECT count(*) FROM space.seen_jobs WHERE source_id=c.source_id AND state='claimed')+
 (SELECT count(*) FROM space.creation_attempts WHERE source_id=c.source_id AND state IN ('claimed','unknown'))+
 (SELECT count(*) FROM space.apple_challenges WHERE source_id=c.source_id AND state IN ('password','mfa'))`

func readReceipt(ctx context.Context, q queryer, operation, owner string) (Receipt, error) {
	var r Receipt
	e := q.QueryRowContext(ctx, `SELECT c.operation_key,c.kind,c.source_id,c.address_id,c.state,c.payload_scrubbed,c.inventory_complete,c.last_error_code,
 (SELECT count(*) FROM space.local_cleanup_objects WHERE operation_key=c.operation_key),
 (SELECT count(*) FROM space.local_cleanup_objects WHERE operation_key=c.operation_key AND state='collected'),
 (SELECT count(*) FROM space.local_cleanup_objects WHERE operation_key=c.operation_key AND state='absent'),
 (SELECT count(*) FROM space.local_cleanup_objects WHERE operation_key=c.operation_key AND state='shared'),
 (SELECT count(*) FROM space.local_cleanup_objects WHERE operation_key=c.operation_key AND state='protected'),
 (SELECT count(*) FROM space.local_cleanup_objects WHERE operation_key=c.operation_key AND state='needs_review'),
 (SELECT count(*) FROM space.pending_reveals WHERE source_id=c.source_id AND (c.address_id IS NULL OR address_id=c.address_id) AND acknowledged_at IS NULL),
 `+retainedUnknown+` FROM space.local_cleanup_operations c WHERE operation_key=$1 AND owner_key=$2`, operation, owner).Scan(&r.OperationKey, &r.Kind, &r.SourceID, &r.AddressID, &r.State, &r.PayloadScrubbed, &r.InventoryComplete, &r.LastErrorCode, &r.Objects, &r.Collected, &r.Absent, &r.Shared, &r.Protected, &r.NeedsReview, &r.Unacknowledged, &r.UnresolvedOperations)
	if errors.Is(e, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if e != nil {
		return r, sqlFailure(ctx, e, "receipt-read")
	}
	return r, nil
}
