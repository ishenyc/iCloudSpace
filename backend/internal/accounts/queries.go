package accounts

import (
	"database/sql"
	"strings"
)

const metadataColumns = `s.id,s.kind,s.display_name,s.address_namespace,
s.imap_host,s.imap_port,s.imap_username,s.address_suffix,s.enabled,
s.revision,s.source_generation,s.credential_generation,
s.automatic_sync_after,s.last_terminal_sync_at,s.last_sync_state,CASE WHEN octet_length(s.last_sync_error)<=96 THEN s.last_sync_error ELSE 'historical_sync_failure' END,s.last_synced_at,s.created_at,s.updated_at,
p.apple_id,p.region,p.dsid,p.revision,
(SELECT count(*) FROM space.private_addresses a WHERE a.source_id=s.id AND a.deleted_at IS NULL)`

const sourceJoin = ` FROM space.mail_sources s LEFT JOIN space.apple_principals p ON p.source_id=s.id `

// strpos gives Query literal substring semantics, including '%' and '_'. Every
// caller uses this same fixed filter and the same parameter order.
const sourceFilter = ` WHERE s.retired_at IS NULL AND ($1='' OR strpos(lower(s.display_name),lower($1))>0
 OR strpos(lower(s.address_namespace),lower($1))>0
 OR strpos(lower(s.imap_username),lower($1))>0
 OR strpos(lower(coalesce(p.apple_id,'')),lower($1))>0)
 AND ($2='' OR s.kind=$2) AND ($3::boolean IS NULL OR s.enabled=$3)`

const sourceOrder = ` ORDER BY s.created_at DESC,s.id DESC `

type rowScanner interface{ Scan(...any) error }

func scanSource(row rowScanner, envelopeRequested bool) (Metadata, []byte, error) {
	var source Metadata
	var automatic, terminal, synced sql.NullInt64
	var appleID, region, dsid sql.NullString
	var principalRevision sql.NullInt64
	var envelope []byte
	fields := []any{&source.ID, &source.Kind, &source.DisplayName, &source.AddressNamespace,
		&source.Endpoint.Host, &source.Endpoint.Port, &source.Endpoint.Username,
		&source.AddressSuffix, &source.Enabled, &source.Revision, &source.SourceGeneration,
		&source.CredentialGeneration, &automatic, &terminal, &source.LastSyncState, &source.LastSyncError, &synced, &source.CreatedAt, &source.UpdatedAt,
		&appleID, &region, &dsid, &principalRevision, &source.AddressCount}
	if envelopeRequested {
		fields = append(fields, &envelope)
	}
	if err := row.Scan(fields...); err != nil {
		return Metadata{}, nil, err
	}
	if automatic.Valid {
		source.AutomaticSyncAfter = &automatic.Int64
	}
	if terminal.Valid {
		source.LastTerminalSyncAt = &terminal.Int64
	}
	if synced.Valid {
		source.LastSyncedAt = &synced.Int64
	}
	source.LastSyncState = SafeSyncState(source.LastSyncState)
	source.LastSyncError = SafeSyncErrorCode(source.LastSyncError)
	if appleID.Valid {
		source.Apple = &ApplePrincipal{AppleID: appleID.String, Region: region.String, Revision: principalRevision.Int64}
		if dsid.Valid {
			source.Apple.DSID = &dsid.String
		}
	}
	return source, envelope, nil
}

// These finite namespaces are controlled executor diagnostics. A historical
// token-shaped password is not made public merely because a regexp accepts it.
func SafeSyncErrorCode(value string) string {
	switch value {
	case "", "historical_sync_failure", "login_required", "session_binding", "read_only", "source_changed", "invalid_step", "invalid_admission", "directory_not_applicable", "directory_checkpoint_failed", "mail_snapshot_changed", "mail_frontier_changed", "mail_frontier_unknown", "backfill_changed", "invalid_backfill_continuation", "intake_recovery_required", "backfill_prepare_unknown", "invalid_counters", "invalid_frontier", "step_failed", "step_timeout", "executor_panic", "round_budget_exhausted", "terminal_persistence_unknown", "terminal_clock_not_advanced", "terminal_timestamp_range", "source_gate_failed", "slot_wait_timeout":
		return value
	}
	phases := []string{"directory", "source_metadata", "source_credentials", "intake_receipt", "intake_snapshot", "mail", "mail_frontier", "backfill_prepare", "backfill_catalog", "backfill_snapshot", "imap"}
	for _, phase := range phases {
		kind, ok := strings.CutPrefix(value, phase+"_")
		if !ok {
			continue
		}
		switch kind {
		case "invalid", "canceled", "cancelled", "dns", "connect", "tls", "timeout", "transport", "redirect", "response_budget", "malformed_response", "authentication_required", "auth_required", "rate_limited", "apple_rejected", "second_factor_required", "auth", "command", "protocol", "timestamp_range", "uid_exhausted", "source_bytes_changed", "session_unknown", "unavailable", "failed":
			return value
		}
	}
	return "historical_sync_failure"
}
func SafeSyncState(value string) string {
	switch value {
	case "", "ok", "error", "succeeded", "degraded", "failed", "cancelled", "superseded", "unknown", "mail_succeeded", "mail_degraded", "mail_failed", "mail_cancelled", "mail_superseded", "mail_unknown":
		return value
	}
	return "unknown"
}

func filterArgs(filter Filter) []any { return []any{filter.Query, string(filter.Kind), filter.Enabled} }

// Empty-source deletion deliberately refuses dependent state rather than
// hiding file cleanup, unacknowledged secrets, or unknown submissions behind
// CASCADE. Addresses cover their grants, pending reveals, mail entries and
// outbound facts; the remaining direct children are checked explicitly.
const dependentStateSQL = `SELECT EXISTS(
 SELECT 1 FROM space.private_addresses WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.content_objects WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.source_messages WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.mailbox_cursors WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.intake_batches WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.seen_jobs WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.address_operations WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.creation_policies WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.apple_sessions WHERE source_id=$1
 UNION ALL SELECT 1 FROM space.apple_challenges WHERE source_id=$1
)`
