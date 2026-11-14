package httpapi

// managementAccountSchemas describes the current management wire DTOs. Identity
// and version values stay decimal strings, and omitted fields remain distinct
// from explicitly nullable fields.
func managementAccountSchemas() openObject {
	str, boolean := openString(), openObject{"type": "boolean"}
	id, count, at := openRef("Identifier"), openRef("Count"), openRef("Instant")
	kind := openObject{"type": "string", "enum": []string{"custom", "apple_direct", "apple_forwarded"}}
	format := openObject{"type": "string", "enum": []string{"csv", "jsonl"}}
	key := openObject{"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$", "description": "Retain the exact original operation or delivery key after an unknown result; query it before another command."}
	purgeKey := openObject{"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"}
	digest := openObject{"type": "string", "pattern": "^[0-9a-f]{64}$"}
	secret := openObject{"type": "string", "minLength": 1, "maxLength": 4096, "description": "Sensitive exact UTF-8 value, at most 4096 bytes. Preserve whitespace and case; never log, store in browser storage, or put in a URL."}
	pageNumber := openObject{"type": "integer", "minimum": 1, "maximum": 2147483647}
	pageSize := openObject{"type": "integer", "minimum": 1, "maximum": 1000}
	total := openObject{"type": "integer", "minimum": 0, "maximum": 9007199254740991}
	uidValidity := openObject{"type": "string", "pattern": "^[1-9][0-9]{0,9}$", "description": "Exact decimal in 1..4294967295; remains a string."}
	uidNext := openObject{"type": "string", "pattern": "^[1-9][0-9]{0,9}$", "description": "Exact high-water decimal in 1..4294967296, including the exhausted-UID sentinel; remains a string."}
	apiPurposes := openObject{"type": "array", "items": openObject{"type": "string", "enum": []string{"latest_read", "mail_read", "mail_consume", "raw_read"}}, "minItems": 1, "maxItems": 4, "uniqueItems": true}
	capabilities := openObject{"type": "array", "items": openObject{"type": "string", "enum": []string{"latest_read", "mail_read", "mail_consume", "raw_read", "imap_login", "oauth_client", "oauth_refresh"}}, "uniqueItems": true, "description": "Effective capabilities. Disabled addresses have no capabilities."}
	profile := openObject{"type": "string", "enum": []string{"api_key_only", "mailbox"}}
	endpoint := openRecord(openObject{"host": str, "port": openObject{"type": "integer", "minimum": 1, "maximum": 65535}, "username": str}, "host", "port", "username")
	region := openObject{"type": "string", "enum": []string{"global", "china"}}
	appleInput := openRecord(openObject{"apple_id": str, "region": region}, "apple_id", "region")
	apple := openRecord(openObject{"apple_id": str, "region": region, "dsid": str, "revision": id}, "apple_id", "region", "revision")
	accountCredentials := openRecord(openObject{"version": openObject{"const": 1}, "imap_password": openObject{"type": "string", "minLength": 1, "description": "Exact source-mailbox password. Only an explicit reveal or sensitive account export returns it."}}, "version", "imap_password")
	account := openRecord(openObject{
		"id": id, "kind": kind, "display_name": str, "address_namespace": str, "endpoint": openRef("MAccountEndpoint"),
		"address_suffix": str, "enabled": boolean, "address_count": count, "revision": id, "source_generation": id, "credential_generation": id,
		"automatic_sync_after": at, "last_terminal_sync_at": at,
		"last_sync_state": openObject{"type": "string", "enum": []string{"", "ok", "error", "succeeded", "degraded", "failed", "cancelled", "superseded", "unknown", "mail_succeeded", "mail_degraded", "mail_failed", "mail_cancelled", "mail_superseded", "mail_unknown"}},
		"last_sync_error": openObject{"type": "string", "pattern": "^(|historical_sync_failure|login_required|session_binding|read_only|source_changed|invalid_step|invalid_admission|directory_not_applicable|directory_checkpoint_failed|mail_snapshot_changed|mail_frontier_changed|mail_frontier_unknown|backfill_changed|invalid_backfill_continuation|intake_recovery_required|backfill_prepare_unknown|invalid_counters|invalid_frontier|step_failed|step_timeout|executor_panic|round_budget_exhausted|terminal_persistence_unknown|terminal_clock_not_advanced|terminal_timestamp_range|source_gate_failed|slot_wait_timeout|(directory|source_metadata|source_credentials|intake_receipt|intake_snapshot|mail|mail_frontier|backfill_prepare|backfill_catalog|backfill_snapshot|imap)_(invalid|canceled|cancelled|dns|connect|tls|timeout|transport|redirect|response_budget|malformed_response|authentication_required|auth_required|rate_limited|apple_rejected|second_factor_required|auth|command|protocol|timestamp_range|uid_exhausted|source_bytes_changed|session_unknown|unavailable|failed))$", "description": "Safe persisted diagnostic code; historical unverified detail is represented by historical_sync_failure, never raw provider data."},
		"last_synced_at":  openNullable(at), "created_at": at, "updated_at": at, "apple": openRef("MAccountAppleIdentity"),
	}, "id", "kind", "display_name", "address_namespace", "endpoint", "address_suffix", "enabled", "address_count", "revision", "source_generation", "credential_generation", "last_sync_state", "last_sync_error", "last_synced_at", "created_at", "updated_at")
	account["description"] = "Metadata only: no credentials. automatic_sync_after, last_terminal_sync_at and apple are omitted when unavailable; last_synced_at is explicitly null when unknown. Receiving address_namespace and source endpoint.username need not equal the Apple principal."
	account["allOf"] = []any{openObject{
		"if":   openObject{"properties": openObject{"kind": openObject{"const": "custom"}}, "required": []string{"kind"}},
		"then": openObject{"not": openObject{"required": []string{"apple"}}},
		"else": openObject{"required": []string{"apple"}},
	}}
	accountFilter := openRecord(openObject{"query": str, "kind": kind, "enabled": boolean})
	accountCreate := openRecord(openObject{
		"kind": kind, "display_name": str, "address_namespace": str, "endpoint": openRef("MAccountEndpoint"), "address_suffix": str,
		"enabled": boolean, "credentials": openRef("MAccountCredentials"), "apple": openRef("MAccountAppleInput"),
	}, "kind", "display_name", "address_namespace", "endpoint", "address_suffix", "enabled", "credentials")
	accountCreate["allOf"] = []any{openObject{
		"if":   openObject{"properties": openObject{"kind": openObject{"const": "custom"}}, "required": []string{"kind"}},
		"then": openObject{"not": openObject{"required": []string{"apple"}}},
		"else": openObject{"required": []string{"apple"}},
	}}
	accountPatch := openRecord(openObject{
		"expected_revision": id, "require_source_change": boolean, "kind": kind, "display_name": str, "address_namespace": str,
		"endpoint": openRef("MAccountEndpoint"), "address_suffix": str, "enabled": boolean, "credentials": openRef("MAccountCredentials"), "apple": openRef("MAccountAppleInput"),
	}, "expected_revision")
	accountPatch["description"] = "CAS against the exact current revision. Changes to the receiving source require explicit require_source_change=true. An identity already used by addresses can remain locked; refresh metadata after conflict. Omitted fields retain their values."
	accountPatch["not"] = openObject{"properties": openObject{"kind": openObject{"const": "custom"}}, "required": []string{"kind", "apple"}}
	accountDeleteKey := openObject{"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._~-]{0,511}$"}
	accountReveal := openRecord(openObject{"source": openRef("MAccount"), "credentials": openRef("MAccountCredentials")}, "source", "credentials")
	addressFilter := openRecord(openObject{
		"source_id": id, "group_id": id, "ungrouped": boolean, "query": str, "enabled": boolean, "has_mail": boolean,
		"archive": openObject{"type": "string", "enum": []string{"all", "archived", "unarchived"}},
	})
	addressFilter["not"] = openObject{"properties": openObject{"ungrouped": openObject{"const": true}}, "required": []string{"group_id", "ungrouped"}}
	addressFilter["description"] = "All supplied filters are combined. group_id and ungrouped=true are mutually exclusive. No filter implicitly reveals credentials or consumes mail."
	address := openRecord(openObject{
		"id": id, "source_id": id, "source_label": str, "source_kind": openObject{"type": "string", "enum": []string{"apple_direct", "apple_forwarded", "custom"}}, "address": str, "kind": openObject{"type": "string", "enum": []string{"apple", "manual", "random"}},
		"label": str, "group_id": openNullable(id), "lifecycle": openObject{"type": "string", "enum": []string{"pending", "confirmed", "deletion_pending", "archived"}},
		"enabled": boolean, "revision": id, "auth_generation": id, "uid_validity": uidValidity, "uid_next": uidNext, "has_mail": boolean,
		"credential_profile":  openObject{"type": "string", "enum": []string{"mailbox", "api_key_only", "legacy_latest", "unavailable"}},
		"registration_banned": boolean, "registration_banned_at": openNullable(at), "latest_received_at": openNullable(at),
		"capabilities": capabilities, "archive_notice": openNullable(openRef("MAddressArchiveNotice")), "last_sync_state": str, "last_sync_error": str,
		"last_synced_at": openNullable(at), "last_accessed_at": openNullable(at), "created_at": at, "updated_at": at,
	}, "id", "source_id", "source_label", "source_kind", "address", "kind", "label", "group_id", "lifecycle", "enabled", "revision", "auth_generation", "uid_validity", "uid_next", "has_mail", "credential_profile", "registration_banned", "registration_banned_at", "latest_received_at", "capabilities", "archive_notice", "last_sync_state", "last_sync_error", "last_synced_at", "last_accessed_at", "created_at", "updated_at")
	address["description"] = "Address metadata without secret material. All nullable properties are present. Only confirmed addresses may be enabled. archive_notice is non-null exactly for archived addresses; registration_banned is true exactly when registration_banned_at is non-null."
	addressPatch := openRecord(openObject{"expected_revision": id, "label": str, "enabled": boolean, "group_id": openNullable(id)}, "expected_revision")
	addressPatch["description"] = "CAS patch. An omitted group_id leaves membership unchanged; group_id:null explicitly removes membership. Re-enabling schedules canonical backfill; metadata reads do not trigger it."
	selection := openObject{"type": "array", "items": openRef("MAddressSelection"), "minItems": 1, "maxItems": 1000, "description": "Distinct address IDs with their individual current revisions; the move is atomic."}
	apiMaterial := openRecord(openObject{"key": secret, "purposes": apiPurposes}, "key", "purposes")
	rotationItem := openRecord(openObject{
		"source_id": id, "address_id": id, "previous_generation": id, "generation": id, "delivery_key": key,
		"previous_uid_validity": uidValidity, "uid_validity": uidValidity, "upgraded": boolean,
	}, "source_id", "address_id", "previous_generation", "generation", "delivery_key", "previous_uid_validity", "uid_validity", "upgraded")
	rotation := openRecord(openObject{
		"operation_key": key, "kind": openObject{"type": "string", "enum": []string{"api_key", "bundle", "all"}},
		"state": openObject{"type": "string", "enum": []string{"prepared", "committed", "cancelled"}}, "scope_digest": digest,
		"items": openArray(openRef("MCredentialRotationItem")),
	}, "operation_key", "kind", "state", "scope_digest", "items")
	rotation["allOf"] = []any{
		openObject{"if": openObject{"properties": openObject{"state": openObject{"enum": []string{"prepared", "cancelled"}}}, "required": []string{"state"}}, "then": openObject{"properties": openObject{"items": openObject{"maxItems": 0}}}},
		openObject{"if": openObject{"properties": openObject{"state": openObject{"const": "committed"}, "kind": openObject{"enum": []string{"api_key", "bundle"}}}, "required": []string{"state", "kind"}}, "then": openObject{"properties": openObject{"items": openObject{"minItems": 1, "maxItems": 1}}}},
	}
	rotation["description"] = "Metadata receipt without secret material. prepared/cancelled have no items; a committed one-address rotation has exactly one item. API-key rotation retains generation and UIDVALIDITY; a bundle rotation advances generation. A full upgrade can also change UIDVALIDITY; use the observed receipt, never invented values."
	rotateKey := openRecord(openObject{"kind": openObject{"const": "api_key"}, "operation_key": key, "expected_generation": id, "expected_scope_digest": digest}, "kind", "operation_key", "expected_generation", "expected_scope_digest")
	rotateBundle := openRecord(openObject{"kind": openObject{"const": "bundle"}, "operation_key": key, "expected_generation": id, "expected_scope_digest": digest}, "kind", "operation_key", "expected_generation")
	exportKind := openObject{"type": "string", "enum": []string{"api_key", "mailbox"}}
	exportSelection := openObject{"type": "array", "items": id, "minItems": 1, "maxItems": 1000, "uniqueItems": true}
	exportFilterInput := openRecord(openObject{"kind": exportKind, "format": format, "filter": openRef("MAddressFilter")}, "kind", "format", "filter")
	exportSelectionInput := openRecord(openObject{"kind": exportKind, "format": format, "selected_ids": exportSelection}, "kind", "format", "selected_ids")
	credentialExportAPI := openRecord(openObject{
		"type": openObject{"const": "credential"}, "version": openObject{"const": 1}, "kind": openObject{"const": "api_key"},
		"address_id": id, "source_id": id, "address": str, "generation": id, "api": openRef("MCredentialAPIKeyMaterial"),
	}, "type", "version", "kind", "address_id", "source_id", "address", "generation", "api")
	credentialExportMailbox := openRecord(openObject{
		"type": openObject{"const": "credential"}, "version": openObject{"const": 1}, "kind": openObject{"const": "mailbox"},
		"address_id": id, "source_id": id, "address": str, "generation": id, "bundle": openRef("CredentialBundle"),
	}, "type", "version", "kind", "address_id", "source_id", "address", "generation", "bundle")
	return openObject{
		"MAccountEndpoint": endpoint, "MAccountAppleInput": appleInput, "MAccountAppleIdentity": apple, "MAccountCredentials": accountCredentials, "MAccount": account,
		"MAccountFilter": accountFilter, "MAccountCreate": accountCreate, "MAccountPatch": accountPatch,
		"MAccountPage":    openRecord(openObject{"items": openArray(openRef("MAccount")), "total": total, "page": pageNumber, "page_size": pageSize}, "items", "total", "page", "page_size"),
		"MAccountChange":  openRecord(openObject{"source": openRef("MAccount"), "source_changed": boolean, "credentials_changed": boolean, "previous_source_generation": count}, "source", "source_changed", "credentials_changed", "previous_source_generation"),
		"MAccountReveal":  accountReveal,
		"MAccountDelete":  openRecord(openObject{"expected_revision": id, "operation_key": accountDeleteKey}, "expected_revision", "operation_key"),
		"MAccountDeleted": openRecord(openObject{"operation_key": accountDeleteKey, "source_id": id, "deleted": boolean}, "operation_key", "source_id", "deleted"),
		"MAccountExport":  openRecord(openObject{"format": format, "filter": openRef("MAccountFilter")}, "format", "filter"),
		"MAddress":        address, "MAddressFilter": addressFilter,
		"MAddressArchiveNotice":          openRecord(openObject{"reason": openObject{"type": "string", "enum": []string{"remote_missing", "historical"}}, "archived_at": at}, "reason", "archived_at"),
		"MAddressPage":                   openRecord(openObject{"items": openArray(openRef("MAddress")), "total": total, "page": pageNumber, "page_size": pageSize}, "items", "total", "page", "page_size"),
		"MAddressCreate":                 openRecord(openObject{"source_id": id, "address": str, "label": str, "group_id": openNullable(id), "enabled": boolean, "credential_profile": profile}, "source_id", "address", "label", "group_id", "enabled", "credential_profile"),
		"MAddressRandomCreate":           openRecord(openObject{"source_id": id, "count": openObject{"type": "integer", "minimum": 1, "maximum": 1000}, "label": str, "group_id": openNullable(id), "credential_profile": profile}, "source_id", "count", "label", "group_id", "credential_profile"),
		"MAddressPatch":                  addressPatch,
		"MAddressDelete":                 openRecord(openObject{"expected_revision": id, "confirm_address": str}, "expected_revision", "confirm_address"),
		"MAddressDeleted":                openRecord(openObject{"id": id, "deleted": openObject{"const": true}}, "id", "deleted"),
		"MAddressArchived":               openRecord(openObject{"id": id, "archived": openObject{"const": true}}, "id", "archived"),
		"MHistoricalRemoval":             openRecord(openObject{"id": id, "source_id": id, "source_label": str, "address": str, "kind": openObject{"type": "string", "enum": []string{"manual", "random"}}, "revision": id, "deleted_at": at}, "id", "source_id", "source_label", "address", "kind", "revision", "deleted_at"),
		"MHistoricalRemovalPage":         openRecord(openObject{"items": openArray(openRef("MHistoricalRemoval")), "total": total, "page": pageNumber, "page_size": pageSize}, "items", "total", "page", "page_size"),
		"MAddressSelection":              openRecord(openObject{"id": id, "expected_revision": id}, "id", "expected_revision"),
		"MAddressMove":                   openRecord(openObject{"selection": selection, "group_id": openNullable(id)}, "selection", "group_id"),
		"MAddressList":                   openArray(openRef("MAddress")),
		"MAddressPurge":                  openRecord(openObject{"expected_revision": id, "confirm_address": str, "operation_key": purgeKey}, "expected_revision", "confirm_address", "operation_key"),
		"MAddressOperation":              openRecord(openObject{"operation_key": purgeKey, "source_id": id, "address_id": openNullable(id), "kind": openObject{"type": "string", "enum": []string{"create", "delete", "purge"}}, "state": str, "error_code": str, "query_only": boolean, "created_at": at, "updated_at": at}, "operation_key", "source_id", "address_id", "kind", "state", "error_code", "query_only", "created_at", "updated_at"),
		"MAddressExport":                 openRecord(openObject{"format": format, "filter": openRef("MAddressFilter")}, "format", "filter"),
		"MAddressGroup":                  openRecord(openObject{"id": id, "name": str, "revision": id, "address_count": count}, "id", "name", "revision", "address_count"),
		"MAddressGroupList":              openArray(openRef("MAddressGroup")),
		"MAddressGroupCreate":            openRecord(openObject{"name": str}, "name"),
		"MAddressGroupPatch":             openRecord(openObject{"expected_revision": id, "name": str}, "expected_revision", "name"),
		"MCredentialAPIKeyMaterial":      apiMaterial,
		"MCredentialAPIKeyReveal":        openRecord(openObject{"address_id": id, "api": openRef("MCredentialAPIKeyMaterial")}, "address_id", "api"),
		"MCredentialBundleReveal":        openRecord(openObject{"address_id": id, "bundle": openRef("CredentialBundle")}, "address_id", "bundle"),
		"MCredentialScope":               openRecord(openObject{"digest": digest, "address_count": count, "eligible_count": count}, "digest", "address_count", "eligible_count"),
		"MCredentialDelivery":            openRecord(openObject{"id": id, "source_id": id, "address_id": id, "generation": id, "delivery_key": key, "created_at": at, "acknowledged_at": openNullable(at), "address": str, "label": str, "source_label": str, "lifecycle": str, "deleted": boolean, "enabled": boolean, "current": boolean, "bundle_available": boolean}, "id", "source_id", "address_id", "generation", "delivery_key", "created_at", "acknowledged_at", "address", "label", "source_label", "lifecycle", "deleted", "enabled", "current", "bundle_available"),
		"MCredentialDeliveryPage":        openRecord(openObject{"items": openObject{"type": "array", "items": openRef("MCredentialDelivery"), "maxItems": 1000}, "next_after_id": openNullable(id)}, "items", "next_after_id"),
		"MCredentialDeliveryLinks":       openNullable(openRecord(openObject{"otp": secret, "recent": secret, "raw": secret}, "otp", "recent", "raw")),
		"MCredentialPendingBundleReveal": openRecord(openObject{"delivery": openRef("MCredentialDelivery"), "bundle": openRef("CredentialBundle"), "links": openRef("MCredentialDeliveryLinks")}, "delivery", "bundle", "links"),
		"MCredentialPendingReveal":       openRecord(openObject{"delivery": openRef("MCredentialDelivery"), "revoked": boolean, "links": openRef("MCredentialDeliveryLinks"), "secret": openRecord(openObject{"version": openObject{"const": 1}, "api_key": secret}, "version", "api_key")}, "delivery", "revoked", "secret", "links"),
		"MCredentialCompleteMailbox":     openRecord(openObject{"expected_generation": id}, "expected_generation"),
		"MCredentialAcknowledge":         openRecord(openObject{"delivery_keys": openObject{"type": "array", "items": key, "minItems": 1, "maxItems": 1000, "uniqueItems": true}}, "delivery_keys"),
		"MCredentialRotationItem":        rotationItem, "MCredentialRotation": rotation,
		"MCredentialRotateOne":           openObject{"oneOf": []any{rotateKey, rotateBundle}},
		"MCredentialRotateAll":           openRecord(openObject{"operation_key": key, "expected_scope_digest": digest, "confirmation": openObject{"const": "rotate-all-address-credentials"}, "current_password": openObject{"type": "string", "minLength": 1, "description": "Exact current management password; used only for this explicit fresh authorization."}}, "operation_key", "expected_scope_digest", "confirmation", "current_password"),
		"MCredentialExport":              openObject{"oneOf": []any{exportFilterInput, exportSelectionInput}, "description": "Exactly one explicit selector: filter or selected_ids. Never both. Every selected address must exist, be confirmed and have no deletion; no missing secret is regenerated by export."},
		"MCredentialExportAPIRecord":     credentialExportAPI,
		"MCredentialExportMailboxRecord": credentialExportMailbox,
		"MCredentialExportComplete":      openRecord(openObject{"type": openObject{"const": "complete"}, "version": openObject{"const": 1}, "kind": exportKind, "count": count}, "type", "version", "kind", "count"),
		"MCredentialExportRecord":        openObject{"oneOf": []any{openRef("MCredentialExportAPIRecord"), openRef("MCredentialExportMailboxRecord"), openRef("MCredentialExportComplete")}},
	}
}

func managementAccountRoutes() []managementOperation {
	str := openString()
	boolean := openObject{"type": "boolean"}
	page := openParameter("page", "query", openObject{"type": "integer", "minimum": 1, "maximum": 2147483647, "default": 1}, false)
	pageSize := openParameter("page_size", "query", openObject{"type": "integer", "minimum": 1, "maximum": 1000, "default": 20}, false)
	accountQuery := []any{
		openParameter("query", "query", str, false),
		openParameter("kind", "query", openObject{"type": "string", "enum": []string{"custom", "apple_direct", "apple_forwarded"}}, false),
		openParameter("enabled", "query", boolean, false), page, pageSize,
	}
	addressQuery := []any{
		openParameter("source_id", "query", openRef("Identifier"), false), openParameter("group_id", "query", openRef("Identifier"), false),
		openParameter("ungrouped", "query", boolean, false), openParameter("query", "query", str, false),
		openParameter("enabled", "query", boolean, false), openParameter("has_mail", "query", boolean, false),
		openParameter("archive", "query", openObject{"type": "string", "enum": []string{"all", "archived", "unarchived"}}, false), page, pageSize,
	}
	// Exports bypass the normal JSON envelope. Each CSV cell is serialized JSON,
	// and JSONL records are independently typed; a stream error is never replaced
	// by a JSON problem appended to a successful download.
	exportResponse := func(record, csvDescription, jsonlDescription string, columns []any, credential bool) openObject {
		headers := openObject{
			"Cache-Control":          openObject{"schema": openObject{"type": "string", "const": "no-store"}},
			"X-Content-Type-Options": openObject{"schema": openObject{"type": "string", "const": "nosniff"}},
			"Content-Disposition":    openObject{"schema": str, "description": "attachment with the fixed accounts, addresses or address-credentials filename and requested csv/jsonl extension."},
		}
		if credential {
			headers["X-Space-Credential-Export"] = openObject{"schema": openObject{"type": "string", "const": "1"}}
		}
		responses := openObject{
			"200": openObject{"description": "Streaming export without an envelope. Read the entire stream; HTTP 200 alone is not proof of a complete download.", "headers": headers, "content": openObject{
				"text/csv":             openObject{"schema": openObject{"type": "string", "description": csvDescription, "x-csv-columns": columns}},
				"application/x-ndjson": openObject{"schema": openObject{"type": "string", "description": jsonlDescription, "x-jsonl-record-schema": openRef(record)}},
			}},
			"400": openResponse("Invalid format, filter or explicit selection.", openRef("Failure")),
			"401": openResponse("Management session missing, expired or revoked.", openRef("Failure")),
			"403": openResponse("Same-origin or CSRF validation failed.", openRef("Failure")),
			"409": openResponse("Selection, revision or original secret material is unavailable.", openRef("Failure")),
			"500": openResponse("Controlled export failure before streaming starts. After streaming starts the connection aborts instead.", openRef("Failure")),
		}
		if !credential {
			responses["503"] = openResponse("Read admission or installation is unavailable; do not automatically repeat the request.", openRef("Failure"))
		}
		return responses
	}
	accountExport := exportResponse("MAccountReveal", "UTF-8 CSV header: source_json,credentials_json. Each cell is one complete JSON object matching MAccount and MAccountCredentials respectively, with standard CSV quoting; exact secret bytes are not trimmed or spreadsheet-prefixed.", "One MAccountReveal JSON object per LF-terminated line, without an envelope or terminal record. A read failure aborts the stream.", []any{openObject{"name": "source_json", "schema": openRef("MAccount")}, openObject{"name": "credentials_json", "schema": openRef("MAccountCredentials")}}, false)
	addressExport := exportResponse("MAddress", "UTF-8 CSV with the single header address_json. Every following cell is one complete MAddress JSON object with standard CSV quoting; metadata only.", "One MAddress metadata JSON object per LF-terminated line, without an envelope or terminal record. No credentials or mailbox consumption.", []any{openObject{"name": "address_json", "schema": openRef("MAddress")}}, false)
	credentialExport := exportResponse("MCredentialExportRecord", "UTF-8 CSV with the single header credential_record_json. Each cell is a JSON MCredentialExportRecord with standard CSV quoting. The last row must be type=complete, version=1 and the same kind, with count equal to the number of credential rows.", "LF-terminated MCredentialExportRecord JSON objects. Credential rows are strictly increasing by address_id, with the selected kind and only its api or bundle material. The final record is MCredentialExportComplete with the exact row count. Require this terminal record and successful EOF; truncated HTTP 200 is incomplete.", []any{openObject{"name": "credential_record_json", "schema": openRef("MCredentialExportRecord")}}, true)
	return []managementOperation{
		{Method: "GET", Path: "/accounts", ID: "management.accounts.list", Summary: "List source metadata with exact pagination", Response: "MAccountPage", Query: accountQuery, Description: "Metadata only. Query keys must be unique and recognized. Listing does not reveal credentials, wake synchronization or consume mail."},
		{Method: "POST", Path: "/accounts", ID: "management.accounts.create", Summary: "Create one explicitly configured mail source", Request: "MAccountCreate", Response: "MAccount", Status: 201, RequestRequired: true, Sensitive: true, Description: "Stores the explicitly supplied source credentials without returning them. If persistence is unknown, preserve the returned candidate account resource and query GET /accounts/{source_id}; never automatically recreate the account."},
		{Method: "GET", Path: "/accounts/{source_id}", ID: "management.accounts.get", Summary: "Read one source metadata record", Response: "MAccount", Description: "Reads the actual candidate resource, including after a prior unknown command. No reveal or synchronization is implicit."},
		{Method: "PATCH", Path: "/accounts/{source_id}", ID: "management.accounts.patch", Summary: "Patch one source using its exact revision", Request: "MAccountPatch", Response: "MAccountChange", RequestRequired: true, Sensitive: true, Description: "Source changes require explicit confirmation and may be rejected while identity is in use. Preserve a candidate resource after unknown persistence, query it and compare actual revision/generation; do not replay the patch."},
		{Method: "DELETE", Path: "/accounts/{source_id}", ID: "management.accounts.delete", Summary: "Delete an empty source with revision and operation key", Request: "MAccountDelete", Response: "MAccountDeleted", RequestRequired: true, Description: "Only the empty-source path is available here. Dependent state returns ACCOUNT_HAS_DEPENDENT_STATE (409); use explicit retirement instead. Retain the original operation_key and resource after an unknown result; no automatic repeated DELETE."},
		{Method: "POST", Path: "/accounts/{source_id}/reveal", ID: "management.accounts.reveal", Summary: "Explicitly reveal source-mailbox credentials", Request: "MEmpty", Response: "MAccountReveal", RequestRequired: true, Sensitive: true, Description: "Requires an explicit empty JSON command. Session is checked again after credential-read admission. Do not cache or persist the returned password."},
		{Method: "POST", Path: "/accounts/export", ID: "management.accounts.export", Summary: "Explicitly stream selected source metadata and credentials", Request: "MAccountExport", RequestRequired: true, Sensitive: true, Stream: "csv/jsonl", Responses: accountExport, Description: "Sensitive export over all matching sources, independent of list pagination. CSV contains source_json and credentials_json cells; JSONL contains MAccountReveal records. Preserve stream failures and never silently fetch again."},
		{Method: "GET", Path: "/addresses", ID: "management.addresses.list", Summary: "List address metadata with pagination and filters", Response: "MAddressPage", Query: addressQuery, Description: "Unique recognized query keys only. group_id and ungrouped=true are mutually exclusive. Includes nullable archive and registration evidence, with no credential reveal or mail consumption."},
		{Method: "POST", Path: "/addresses", ID: "management.addresses.create", Summary: "Create one explicit local address", Request: "MAddressCreate", Response: "MAddress", Status: 201, RequestRequired: true, Description: "Creates a local address and selected credential profile. Returned data is metadata; use the separate source-scoped pending credential delivery flow. An unknown result is queried by its actual resource, never recreated automatically."},
		{Method: "POST", Path: "/addresses/random", ID: "management.addresses.random", Summary: "Create a bounded batch of local random addresses", Request: "MAddressRandomCreate", Response: "MAddressList", Status: 201, RequestRequired: true, Description: "Explicit bounded local generation only, without an Apple lifecycle call. Credential values are delivered separately. Do not repeat an uncertain batch automatically."},
		{Method: "POST", Path: "/addresses/export", ID: "management.addresses.export", Summary: "Stream all matching address metadata", Request: "MAddressExport", RequestRequired: true, Stream: "csv/jsonl", Responses: addressExport, Description: "Export is independent of page_size. CSV has one address_json cell per row; JSONL has MAddress objects. Does not reveal credentials, consume mail or write Seen."},
		{Method: "POST", Path: "/addresses/move", ID: "management.addresses.move", Summary: "Atomically move selected address revisions to a group", Request: "MAddressMove", Response: "MAddressList", RequestRequired: true, Description: "Every selected address has a distinct ID and exact expected_revision. group_id:null removes group membership. A conflict rejects the atomic move; an unknown result requires reading the original addresses, not replaying."},
		{Method: "GET", Path: "/addresses/{address_id}", ID: "management.addresses.get", Summary: "Read one address metadata record", Response: "MAddress", Description: "Read-only resource query, also used to inspect a prior uncertain mutation. Never reveals credential material or consumes mail."},
		{Method: "PATCH", Path: "/addresses/{address_id}", ID: "management.addresses.patch", Summary: "Patch address metadata using its current revision", Request: "MAddressPatch", Response: "MAddress", RequestRequired: true, Description: "Omitted group_id leaves membership unchanged; explicit null removes it. Preserve any unknown resource and query it before another edit."},
		{Method: "DELETE", Path: "/addresses/{address_id}", ID: "management.addresses.delete", Summary: "Archive and disable one local address", Request: "MAddressDelete", Response: "MAddressArchived", RequestRequired: true, Description: "Requires exact expected_revision and confirm_address. Archives manual/random addresses, revokes public access and retains history until a separate explicit local purge. Does not invoke Apple deletion. Unknown persistence is queried on the original address."},
		{Method: "GET", Path: "/addresses/historical-removals", ID: "management.addresses.historicalRemovals", Summary: "Read historical local removals eligible for explicit cleanup", Response: "MHistoricalRemovalPage", Query: []any{openParameter("source_id", "query", openRef("Identifier"), false), openParameter("query", "query", openString(), false), openParameter("page", "query", openObject{"type": "integer", "minimum": 1}, false), openParameter("page_size", "query", openObject{"type": "integer", "minimum": 1, "maximum": 100}, false)}, Description: "Only undeleted sources' historical manual/random tombstones without an existing source/address cleanup operation. Metadata only; never restores, reveals, enables or automatically purges an address."},
		{Method: "POST", Path: "/addresses/{address_id}/purge", ID: "management.addresses.purge", Summary: "Purge an archived address under its original operation key", Request: "MAddressPurge", Response: "MAddressOperation", RequestRequired: true, Description: "Explicit archived-address purge, revision and address confirmation. Keep the exact operation_key on an unknown result, then query GET /addresses/{address_id}/purges/{operation_key}; do not issue another purge."},
		{Method: "GET", Path: "/addresses/{address_id}/purges/{operation_key}", ID: "management.addresses.queryPurge", Summary: "Query the original archived-address purge receipt", Response: "MAddressOperation", Description: "Read-only receipt query bound to address, original key and authenticated management owner; it remains the recovery path after local resource removal and does not repeat a purge."},
		{Method: "GET", Path: "/address-groups", ID: "management.addressGroups.list", Summary: "Read all address groups with exact metadata counts", Response: "MAddressGroupList"},
		{Method: "POST", Path: "/address-groups", ID: "management.addressGroups.create", Summary: "Create an address group", Request: "MAddressGroupCreate", Response: "MAddressGroup", Status: 201, RequestRequired: true, Description: "An uncertain result may include the actual address_group resource. Read group metadata before another command; never automatically create a duplicate."},
		{Method: "PATCH", Path: "/address-groups/{group_id}", ID: "management.addressGroups.patch", Summary: "Rename a group using its exact revision", Request: "MAddressGroupPatch", Response: "MAddressGroup", RequestRequired: true, Description: "CAS rename. Read the original group list after unknown persistence rather than replaying the mutation."},
		{Method: "DELETE", Path: "/address-groups/{group_id}", ID: "management.addressGroups.delete", Summary: "Delete an address group using its exact revision", Request: "MRevision", Response: "MAddressDeleted", RequestRequired: true, Description: "Returns the deleted group ID, without deleting its member addresses. An unknown result requires querying the original group metadata."},
		{Method: "POST", Path: "/addresses/{address_id}/credential-bundle/reveal", ID: "management.credentials.revealBundle", Summary: "Explicitly reveal the current mailbox credential bundle", Request: "MEmpty", Response: "MCredentialBundleReveal", RequestRequired: true, Sensitive: true, Description: "Requires explicit reveal and a fresh session after reveal admission. Original current material must be available; no replacement bundle is generated by reading."},
		{Method: "POST", Path: "/addresses/{address_id}/api-key/reveal", ID: "management.credentials.revealAPIKey", Summary: "Explicitly reveal the current API key and effective purposes", Request: "MEmpty", Response: "MCredentialAPIKeyReveal", RequestRequired: true, Sensitive: true, Description: "Exact key and its effective purposes. Never extend scopes or replace unavailable current material. Session is rechecked after admission."},
		{Method: "GET", Path: "/addresses/{address_id}/credential-scope", ID: "management.credentials.addressScope", Summary: "Read one address credential CAS scope", Response: "MCredentialScope", Description: "Metadata digest only; no secrets. address_count is exactly 1. Use this observed scope for a subsequent explicit rotation."},
		{Method: "POST", Path: "/addresses/{address_id}/credential-rotations", ID: "management.credentials.rotateOne", Summary: "Rotate one address API key or mailbox bundle", Request: "MCredentialRotateOne", Response: "MCredentialRotation", RequestRequired: true, Sensitive: true, Description: "API-key rotation requires expected_scope_digest; bundle rotation may omit it. Both require the original operation_key and expected_generation. Secret material is available only through the resulting delivery. On unknown, query GET /credential-rotations/{operation_key}; never rotate again automatically."},
		{Method: "GET", Path: "/credential-rotation-scope", ID: "management.credentials.scope", Summary: "Read the installation credential rotation scope", Response: "MCredentialScope", Description: "Exact digest plus decimal-string address and eligible counts. This read neither rotates nor reveals credentials."},
		{Method: "POST", Path: "/credential-rotations", ID: "management.credentials.rotateAll", Summary: "Explicitly rotate all eligible address credentials", Request: "MCredentialRotateAll", Response: "MCredentialRotation", RequestRequired: true, Sensitive: true, Description: "Fresh current management password and exact confirmation are required. Successful rotation revokes management sessions and clears cookies. Throttled attempts return 429 with Retry-After. On unknown retain the original key; sign in again and query its receipt, without replaying the rotation."},
		{Method: "GET", Path: "/credential-rotations/{operation_key}", ID: "management.credentials.queryRotation", Summary: "Read the original credential rotation receipt", Response: "MCredentialRotation", Description: "Read-only query using the unchanged operation_key. Prepared, committed and cancelled are distinct durable states; a query never performs a rotation."},
		{Method: "POST", Path: "/credential-rotations/{operation_key}/cancel", ID: "management.credentials.cancelRotation", Summary: "Explicitly cancel an uncommitted credential rotation", Request: "MEmpty", Response: "MCredentialRotation", RequestRequired: true, Description: "Uses the original operation key. A committed receipt remains committed; cancellation never reverses an already committed rotation. Unknown cancellation is resolved by querying the same receipt."},
		{Method: "GET", Path: "/accounts/{source_id}/credential-deliveries", ID: "management.credentials.pending", Summary: "Page pending credential delivery metadata", Response: "MCredentialDeliveryPage", Query: []any{openParameter("after_id", "query", openRef("Identifier"), false), openParameter("limit", "query", openObject{"type": "integer", "minimum": 1, "maximum": 1000, "default": 20}, false)}, Description: "Source-scoped ascending ID cursor over unacknowledged deliveries, with no reveal. after_id is exclusive. next_after_id is null unless the returned page is full, in which case it is the final ID; a following page can be empty."},
		{Method: "GET", Path: "/accounts/{source_id}/credential-deliveries/{delivery_key}", ID: "management.credentials.delivery", Summary: "Read an original source-scoped delivery reference", Response: "MCredentialDelivery", Description: "Binds the source and exact original delivery_key; acknowledged_at is explicitly null or an observed timestamp. This query never reveals, completes or acknowledges the delivery."},
		{Method: "POST", Path: "/accounts/{source_id}/credential-deliveries/{delivery_key}/reveal", ID: "management.credentials.revealPending", Summary: "Explicitly reveal the original pending API secret", Request: "MEmpty", Response: "MCredentialPendingReveal", RequestRequired: true, Sensitive: true, Description: "Reveals the exact original pending secret and revoked status; this does not acknowledge delivery. Session is rechecked after reveal admission. Use a separate bundle reveal after explicit mailbox completion."},
		{Method: "POST", Path: "/accounts/{source_id}/credential-deliveries/{delivery_key}/reveal-bundle", ID: "management.credentials.revealPendingBundle", Summary: "Read the existing current bundle bound to an explicit delivery", Request: "MEmpty", Response: "MCredentialPendingBundleReveal", RequestRequired: true, Sensitive: true, Description: "Requires the same source, address, current generation, delivery owner and API key; permits undeleted pending/archived addresses without enabling public access. Does not issue, supplement or acknowledge credentials. Historical deliveries never reveal the current bundle."},
		{Method: "POST", Path: "/accounts/{source_id}/credential-deliveries/{delivery_key}/complete-mailbox", ID: "management.credentials.completeMailbox", Summary: "Explicitly supplement a pending delivery with mailbox credentials", Request: "MCredentialCompleteMailbox", Response: "MCredentialDelivery", RequestRequired: true, Description: "Requires the exact source, original delivery_key and expected_generation. Returns only the original delivery metadata; the resulting tuple still needs explicit reveal. On unknown query the same delivery, never silently substitute a new key."},
		{Method: "DELETE", Path: "/accounts/{source_id}/credential-deliveries", ID: "management.credentials.acknowledge", Summary: "Atomically acknowledge an explicit source-scoped delivery selection", Request: "MCredentialAcknowledge", Response: "MNull", RequestRequired: true, Description: "Distinct original delivery_keys only, all bound to this source. JSON success has result:null. Unknown ACK is resolved by querying the same deliveries and their acknowledged_at values; never infer delivery from a download or reveal."},
		{Method: "POST", Path: "/addresses/credential-exports", ID: "management.credentials.export", Summary: "Explicitly stream original current API keys or mailbox bundles", Request: "MCredentialExport", RequestRequired: true, Sensitive: true, Stream: "csv/jsonl", Responses: credentialExport, Description: "Exactly one explicit filter or selected_ids. Source rows are ascending by address_id; all selected IDs must be eligible. API-key records contain only api; mailbox records contain only bundle. Require X-Space-Credential-Export:1, the final complete record with exact count, and successful EOF. Do not cache, log, synthesize missing credentials or retry an aborted download."},
	}
}
