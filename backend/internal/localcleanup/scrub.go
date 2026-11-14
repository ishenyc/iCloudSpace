package localcleanup

import (
	"context"
	"database/sql"
)

// An archived/disabled address still owns history. Only explicit tombstones
// relinquish ownership. A source-message row alone is a UID fact, not a live
// mailbox owner; shared global views likewise do not invent an address owner.
const liveMessage = `EXISTS(SELECT 1 FROM space.mailbox_entries e JOIN space.private_addresses a ON a.source_id=e.source_id AND a.id=e.address_id WHERE e.source_id=m.source_id AND e.message_id=m.id AND a.deleted_at IS NULL)
 OR EXISTS(SELECT 1 FROM space.address_snapshots ss JOIN space.private_addresses a ON a.source_id=ss.source_id AND a.id=ss.address_id WHERE ss.source_id=m.source_id AND ss.message_id=m.id AND a.deleted_at IS NULL)
 OR EXISTS(SELECT 1 FROM space.message_views v JOIN space.private_addresses a ON a.source_id=v.source_id AND a.id=v.address_id WHERE v.source_id=m.source_id AND v.message_id=m.id AND a.deleted_at IS NULL)`
const scrubMessage = targetMessages + ` AND $3::text<>'' AND NOT (` + liveMessage + `)`

func (s *Service) scrub(ctx context.Context, tx *sql.Tx, r request, now int64) error {
	for _, q := range []string{
		`DELETE FROM space.address_credential_bundles WHERE source_id=$1 AND ($2::bigint=0 OR address_id=$2)`,
		`DELETE FROM space.pending_reveals WHERE source_id=$1 AND ($2::bigint=0 OR address_id=$2) AND acknowledged_at IS NOT NULL`,
		`UPDATE space.mailbox_entries SET retained_code=NULL WHERE source_id=$1 AND ($2::bigint=0 OR address_id=$2)`,
	} {
		if _, e := tx.ExecContext(ctx, q, r.SourceID, r.AddressID); e != nil {
			return sqlFailure(ctx, e, "credential-payload")
		}
	}
	for _, q := range []string{
		`DELETE FROM space.message_codes c USING space.source_messages m WHERE c.message_id=m.id AND ` + scrubMessage,
		`DELETE FROM space.message_recipients c USING space.source_messages m WHERE c.message_id=m.id AND ` + scrubMessage,
		`UPDATE space.source_messages m SET rfc_message_id='',subject='',sender_address='',sender_name='',sender_descriptors='[]'::jsonb,raw_header=decode('','hex'),raw_header_complete=false,preview_text='',content_state='metadata_only' WHERE ` + scrubMessage,
	} {
		if _, e := tx.ExecContext(ctx, q, r.SourceID, r.AddressID, r.Key); e != nil {
			return sqlFailure(ctx, e, "message-payload")
		}
	}
	// Snapshots with no entry/object are still authoritative target ownership.
	// Remove these links only after their source-message payload was scrubbed.
	if _, e := tx.ExecContext(ctx, `WITH targets AS MATERIALIZED (SELECT m.id FROM space.source_messages m WHERE `+scrubMessage+`),removed_snapshots AS (DELETE FROM space.address_snapshots WHERE source_id=$1 AND ($2::bigint=0 OR address_id=$2) RETURNING message_id) DELETE FROM space.message_views v USING targets m WHERE v.source_id=$1 AND v.message_id=m.id`, r.SourceID, r.AddressID, r.Key); e != nil {
		return sqlFailure(ctx, e, "snapshot-view-payload")
	}
	for _, q := range []string{
		`DELETE FROM space.message_views WHERE source_id=$1 AND address_id IS NOT NULL AND ($2::bigint=0 OR address_id=$2)`,
	} {
		if _, e := tx.ExecContext(ctx, q, r.SourceID, r.AddressID); e != nil {
			return storage(ctx)
		}
	}
	// Keep the original encrypted provider material only when a persisted
	// uncertain owner may still require a read-only reconciliation. Normal
	// retirement erases it immediately; it never remains an active credential.
	if r.Kind == "source_delete" {
		if e := s.scrubSourceSecrets(ctx, tx, r.SourceID); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `UPDATE space.creation_policies SET enabled=false,revision=revision+1,updated_at=greatest(updated_at+1,$2) WHERE source_id=$1`, r.SourceID, now); e != nil {
			return storage(ctx)
		}
	}
	if _, e := tx.ExecContext(ctx, `UPDATE space.local_cleanup_operations SET payload_scrubbed=true,updated_at=greatest(updated_at+1,$2) WHERE operation_key=$1`, r.Key, now); e != nil {
		return storage(ctx)
	}
	return nil
}
func (s *Service) scrubSourceSecrets(ctx context.Context, tx *sql.Tx, source int64) error {
	var hold bool
	q := `SELECT (` + retainedUnknown + `)>0 FROM space.local_cleanup_operations c WHERE c.source_id=$1 AND c.kind='source_delete' ORDER BY c.created_at LIMIT 1`
	if tx.QueryRowContext(ctx, q, source).Scan(&hold) != nil {
		return storage(ctx)
	}
	if hold {
		return nil
	}
	if _, e := tx.ExecContext(ctx, `UPDATE space.mail_sources SET credentials_envelope=NULL WHERE id=$1 AND retired_at IS NOT NULL`, source); e != nil {
		return storage(ctx)
	}
	for _, q := range []string{`DELETE FROM space.apple_sessions WHERE source_id=$1`, `DELETE FROM space.apple_challenges WHERE source_id=$1`} {
		if _, e := tx.ExecContext(ctx, q, source); e != nil {
			return storage(ctx)
		}
	}
	return nil
}
