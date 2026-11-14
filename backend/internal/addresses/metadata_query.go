package addresses

import "icloudspace/internal/addressauth"

// The selected page is materialized before opening its grant forest. Metadata
// and exports share one set projection; no row independently compiles or walks
// a correlated recursive ancestry expression.
func metadataQuery(selection string) string {
	return `WITH RECURSIVE selected_addresses AS MATERIALIZED (SELECT a.*` + selection + `),
 ` + addressauth.CurrentGrantSetMetadataSQL() + `,
 -- The schema has seven purposes. The low seven bits retain their set, the
 -- next seven retain API purposes, and bits 14..17 retain the four root facts.
 grant_purposes AS (
 SELECT g.address_id,g.authenticator_kind,g.authenticator_hash,g.parent_grant_id,p.purpose_bit
 FROM current_grants g JOIN (VALUES ('imap_login',1),('latest_read',2),('mail_consume',4),
 ('mail_read',8),('oauth_client',16),('oauth_refresh',32),('raw_read',64)) p(purpose,purpose_bit) ON p.purpose=g.purpose
 ),
 grant_flags AS (
 SELECT address_id,
 count(DISTINCT authenticator_hash) FILTER(WHERE authenticator_kind='api_key' AND purpose_bit&78<>0) AS api_hashes,
 bit_or(purpose_bit
 | CASE WHEN authenticator_kind='api_key' THEN purpose_bit<<7 ELSE 0 END
 | CASE WHEN parent_grant_id IS NULL THEN CASE
 WHEN authenticator_kind='api_key' AND purpose_bit&78<>0 THEN 1<<14
 WHEN authenticator_kind='imap_password' AND purpose_bit=1 THEN 1<<15
 WHEN authenticator_kind='client_id' AND purpose_bit=16 THEN 1<<16
 WHEN authenticator_kind='refresh_token' AND purpose_bit=32 THEN 1<<17
 ELSE 0 END ELSE 0 END) AS flags
 FROM grant_purposes GROUP BY address_id
 ),
 grant_metadata AS (
 SELECT address_id,api_hashes,
 flags&(1<<14)<>0 AS root_api,flags&(1<<15)<>0 AS root_imap,
 flags&(1<<16)<>0 AS root_client,flags&(1<<17)<>0 AS root_refresh,
 flags&(72<<7)<>0 AS api_read,flags&(2<<7)<>0 AS latest_read,
 to_jsonb(array_remove(ARRAY[
 CASE WHEN flags&1<>0 THEN 'imap_login' END,
 CASE WHEN flags&2<>0 THEN 'latest_read' END,
 CASE WHEN flags&4<>0 THEN 'mail_consume' END,
 CASE WHEN flags&8<>0 THEN 'mail_read' END,
 CASE WHEN flags&16<>0 THEN 'oauth_client' END,
 CASE WHEN flags&32<>0 THEN 'oauth_refresh' END,
 CASE WHEN flags&64<>0 THEN 'raw_read' END],NULL)) AS capabilities
 FROM grant_flags
 )
 SELECT ` + identityColumns + `,(a.latest_received_at IS NOT NULL),a.created_at,a.updated_at,
 CASE WHEN a.enabled AND a.lifecycle='confirmed' AND a.deleted_at IS NULL AND s.enabled THEN coalesce(g.capabilities,'[]'::jsonb) ELSE '[]'::jsonb END,
 ` + syncColumns + `,
 CASE WHEN a.lifecycle='confirmed' AND a.deleted_at IS NULL AND g.api_hashes=1 AND (
 b.address_id IS NOT NULL
 OR EXISTS(SELECT 1 FROM space.pending_reveals p WHERE p.source_id=a.source_id AND p.address_id=a.id AND p.auth_generation=a.auth_generation AND p.owner_key<>''))
 THEN CASE WHEN g.root_api AND g.root_imap AND g.root_client AND g.root_refresh AND b.address_id IS NOT NULL THEN 'mailbox'
 WHEN g.api_read THEN 'api_key_only' WHEN g.latest_read THEN 'legacy_latest' ELSE 'unavailable' END ELSE 'unavailable' END,
 e.detected_at,a.latest_received_at,coalesce(nullif(s.display_name,''),s.address_namespace),s.kind
 FROM selected_addresses a JOIN space.mail_sources s ON s.id=a.source_id
 LEFT JOIN grant_metadata g ON g.address_id=a.id
 LEFT JOIN space.address_credential_bundles b ON b.source_id=a.source_id AND b.address_id=a.id AND b.auth_generation=a.auth_generation
 LEFT JOIN space.address_evidence e ON e.source_id=a.source_id AND e.address_id=a.id AND e.evidence_kind='trusted_ban'
 ORDER BY a.id`
}
