package httpapi

func managementWorkflowSchemas() openObject {
	str, boolean := openString(), openObject{"type": "boolean"}
	key := openObject{"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$", "description": "New provider mutation key. Retained imported query keys additionally allow colon and a leading punctuation character."}
	token := openObject{"type": "string", "pattern": "^[0-9a-f]{64}$"}
	request := func(properties openObject, required ...string) openObject { return openRecord(properties, required...) }
	schemas := openObject{
		"MLogin":             request(openObject{"username": str, "password": openObject{"type": "string", "writeOnly": true}}, "username", "password"),
		"MPasswordChange":    request(openObject{"current_password": openObject{"type": "string", "writeOnly": true}, "new_password": openObject{"type": "string", "writeOnly": true, "description": "Exact UTF8 password,12..72 bytes, never trimmed."}, "confirmation": str}, "current_password", "new_password", "confirmation"),
		"MProviderLogin":     request(openObject{"request_key": key, "password": openObject{"type": "string", "writeOnly": true}}, "request_key", "password"),
		"MProviderQuery":     request(openObject{"request_key": openObject{"type": "string", "pattern": "^[A-Za-z0-9._:-]{8,128}$"}, "challenge_token": token}, "request_key"),
		"MProviderRequest":   request(openObject{"request_key": key}, "request_key"),
		"MProviderRestore":   request(openObject{"request_key": key, "document": openRef("MAppleSessionDocument"), "document_json": openObject{"type": "string", "writeOnly": true, "description": "Exact canonical capsule JSON text,<=1MiB decoded, preferred to preserve signed int64 nanoseconds. Outer escaped JSON limit6MiB+4096."}}, "request_key"),
		"MHMECreate":         request(openObject{"operation_key": str, "expected_revision": openRef("Identifier"), "label": str, "group_id": openNullable(openRef("Identifier")), "credential_profile": openObject{"type": "string", "enum": []string{"api_key_only", "mailbox"}}}, "operation_key", "expected_revision", "credential_profile"),
		"MHMEDelete":         request(openObject{"operation_key": str, "expected_revision": openRef("Identifier"), "confirm_address": str}, "operation_key", "expected_revision", "confirm_address"),
		"MHMEReconcile":      request(openObject{"expected_revision": openRef("Identifier"), "credential_profile": openObject{"type": "string", "enum": []string{"api_key_only", "mailbox"}}}, "expected_revision", "credential_profile"),
		"MHMEReconciliation": openRecord(openObject{"imported": openObject{"type": "integer", "minimum": 0}, "existing": openObject{"type": "integer", "minimum": 0}, "archived": openObject{"type": "integer", "minimum": 0}, "rediscovered": openObject{"type": "integer", "minimum": 0}, "active": openObject{"type": "integer", "minimum": 0}, "inactive": openObject{"type": "integer", "minimum": 0}, "skipped_forward": openObject{"type": "integer", "minimum": 0}, "conflicts": openObject{"type": "integer", "minimum": 0}, "pending": openObject{"type": "integer", "minimum": 0}}, "imported", "existing", "archived", "rediscovered", "active", "inactive", "skipped_forward", "conflicts", "pending"),
		"MCreationSettings":  request(openObject{"expected_revision": openRef("Count"), "maximum_addresses": openObject{"type": "integer", "minimum": 0, "maximum": 2147483647}, "attempts_per_round": openObject{"type": "integer", "minimum": 1, "maximum": 5}}, "expected_revision", "maximum_addresses", "attempts_per_round"),
		"MCreationRevision":  request(openObject{"expected_revision": openRef("Count")}, "expected_revision"),
		"MAuditPage":         openRecord(openObject{"items": openArray(openRef("MAuditRecord")), "total": openObject{"type": "integer", "minimum": 0}, "page": openObject{"type": "integer", "minimum": 1}, "page_size": openObject{"type": "integer", "minimum": 1, "maximum": 100}}, "items", "total", "page", "page_size"),
		"MLocalRetirement":   request(openObject{"operation_key": openObject{"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"}, "expected_revision": openRef("Identifier"), "confirmation": openObject{"type": "string", "minLength": 1, "maxLength": 1024, "description": "Exact current source namespace; no NUL/CR/LF."}}, "operation_key", "expected_revision", "confirmation"),
		"MLocalPurge":        request(openObject{"source_id": openRef("Identifier"), "operation_key": openObject{"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"}, "expected_revision": openRef("Identifier"), "confirmation": openObject{"type": "string", "minLength": 1, "maxLength": 1024, "description": "Exact current address; no NUL/CR/LF."}}, "source_id", "operation_key", "expected_revision", "confirmation"),
		"MMailSend":          request(openObject{"request_key": openObject{"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"}, "draft": openRef("MMailDraft")}, "request_key", "draft"),
		"MMailQuery":         request(openObject{"request_key": openObject{"type": "string", "minLength": 1, "description": "Exact original key; imported opaque keys are not rewritten into the new mutation-key syntax."}}, "request_key"),
		"MComposePrepare":    request(openObject{"context_key": str, "recipient": str, "authorize_bootstrap": boolean}, "context_key", "recipient"),
		"MComposeQuery":      request(openObject{"context_key": str}, "context_key"),
	}
	schemas["MProviderRestore"].(openObject)["oneOf"] = []any{openObject{"required": []string{"document"}, "not": openObject{"required": []string{"document_json"}}}, openObject{"required": []string{"document_json"}, "not": openObject{"required": []string{"document"}}}}
	documentText := schemas["MProviderRestore"].(openObject)["properties"].(openObject)["document_json"].(openObject)
	documentText["contentMediaType"] = "application/json"
	documentText["contentSchema"] = openRef("MAppleSessionDocument")
	documentText["x-maxUtf8Bytes"] = 1048576
	var actionBranches []any
	for _, action := range []string{"load_challenge", "send_device_code", "verify_device_code", "send_sms", "verify_sms", "verify_security_key", "trust_browser", "exchange_token", "validate_session"} {
		properties := openObject{"request_key": key, "challenge_token": token, "action": openObject{"const": action}, "code": str, "phone_id": str, "mode": openObject{"type": "string", "enum": []string{"sms", "voice"}}, "assertion": openRef("MAppleSecurityKeyAssertion")}
		required := []string{"request_key", "challenge_token", "action"}
		if action == "verify_device_code" || action == "verify_sms" {
			properties["code"] = openObject{"type": "string", "pattern": "^[0-9]{6}$"}
			required = append(required, "code")
		}
		if action == "send_sms" || action == "verify_sms" {
			required = append(required, "phone_id", "mode")
		}
		if action == "verify_security_key" {
			required = append(required, "assertion")
		}
		actionBranches = append(actionBranches, openRecord(properties, required...))
	}
	schemas["MProviderAction"] = openObject{"oneOf": actionBranches, "description": "Exact action-specific required inputs. Backend assertion support does not prove a completed public Apple-origin hardware browser handoff."}
	return schemas
}

func managementWorkflowRoutes() []managementOperation {
	const queryOnly = "Original resource/key only. This POST queries durable state or read-only provider proof and never automatically replays its mutation."
	const json4K = "One JSON object,4096-byte boundary. "
	var ops []managementOperation
	add := func(method, path, id, summary, request, response string, status int, description string) {
		ops = append(ops, managementOperation{Method: method, Path: path, ID: "m." + id, Summary: summary, Request: request, Response: response, Status: status, RequestRequired: request != "", Description: description})
	}
	add("GET", "/session", "auth.readSession", "Discover existing operator session", "", "MSession", 200, "Same-origin safe read; absent/invalid session returns authenticated:false. Does not silently mint a replacement CSRF.")
	add("POST", "/session", "auth.createSession", "Explicit operator sign-in", "MLogin", "MSession", 201, "8KiB JSON; same Origin required, no previous session/CSRF required. Cookies are HttpOnly, SameSite=Strict, Path=M; Secure on validated TLS or explicit force_secure_cookies.")
	add("DELETE", "/session", "auth.deleteSession", "Revoke current management session", "", "MNull", 200, "Same session/Origin/CSRF required; no body.")
	add("PUT", "/password", "auth.changePassword", "Change operator password and revoke sessions", "MPasswordChange", "MNull", 200, "8KiB JSON; exact current/new password bytes and confirmation; all operator sessions revoked after committed change.")
	p := "/accounts/{source_id}/provider-session"
	add("GET", p, "provider_sessions.status", "Saved provider session metadata", "", "MProviderSession", 200, "Non-secret session metadata; no Apple authentication or capsule export.")
	for _, e := range []struct{ suffix, id, input, description string }{{"login", "login", "MProviderLogin", "Explicit password action; save same Client snapshot even when provider fails or outcome is unknown."}, {"actions", "action", "MProviderAction", "Source/operator/challenge-bound explicit action; conditional required fields, no silent MFA retries."}, {"query", "query", "MProviderQuery", queryOnly}, {"restore", "restore", "MProviderRestore", "Exactly one canonical document/document_json. Revalidate binding; do not trust imported validated_at.6MiB+4096 outer JSON limit."}, {"validate", "validate", "MProviderRequest", "Explicit revalidation under the same source identity and persisted jar."}, {"clear", "clear", "MProviderRequest", "Explicit clear; query original request after uncertainty."}} {
		add("POST", p+"/"+e.suffix, "provider_sessions."+e.id, "Provider "+e.suffix, e.input, "MProviderAuth", 200, e.description)
	}
	p = "/accounts/{source_id}/hme"
	for _, e := range []struct{ suffix, id, input, response, description string }{{"/creations", "create", "MHMECreate", "MHMEOperation", "Authoritative selected forwarding must match before generate/reserve. Empty directory permits one fenced target initialization/readback; unknown initialization only queries. Successful original readback may continue; later query-confirmed init requires a new explicit create."}, {"/creations/query", "queryCreate", "MOperationKey", "MHMEOperation", queryOnly}, {"/directory/reconcile", "reconcile", "MHMEReconcile", "MHMEReconciliation", "Explicit authoritative directory read/reconcile. Per-row expected forwarding, preserve existing enabled choice; new active import shares750 enabled+pending local capacity."}, {"/addresses/{address_id}/deletion", "delete", "MHMEDelete", "MHMEOperation", "Explicit remote deletion authorization. Preserve archive/UID/consume/unknown facts."}, {"/addresses/{address_id}/deletion/query", "queryDelete", "MOperationKey", "MHMEOperation", queryOnly}} {
		add("POST", p+e.suffix, "hme."+e.id, "HME "+e.id, e.input, e.response, 200, json4K+e.description)
	}
	p = "/accounts/{source_id}/creation-policy"
	add("GET", p, "creation.get", "Read policy and original pending attempt", "", "MCreationPolicy", 200, "404 when no policy exists; read does not create/enable a policy.")
	add("PUT", p, "creation.set", "CAS policy settings", "MCreationSettings", "MCreationPolicy", 200, json4K+"expected_revision=0 permits initial policy. Finite attempts1..5; no aggregate retries from unknown.")
	for _, action := range []string{"enable", "disable"} {
		add("POST", p+"/"+action, "creation."+action, "Explicit policy "+action, "MCreationRevision", "MCreationPolicy", 200, json4K+"CAS change; complete minimum5min pacing starts at terminal settlement, not pre-COMMIT claim time.")
	}
	add("GET", p+"/attempts", "creation.attempts", "Bounded original attempt history", "", "MCreationAttemptPage", 200, "Unknown attempt pauses further creation; no new RPC from a metadata read.")
	ops[len(ops)-1].Query = []any{openParameter("after_id", "query", openRef("Count"), false), openParameter("limit", "query", openObject{"type": "integer", "minimum": 1, "maximum": 100, "default": 50}, false)}
	add("GET", p+"/attempts/{attempt_id}", "creation.attempt", "Read exact original attempt", "", "MCreationAttempt", 200, queryOnly)
	add("POST", p+"/attempts/{attempt_id}/resolve", "creation.resolve", "Query original uncertain HME attempt", "MEmpty", "MCreationAttempt", 200, json4K+queryOnly)
	p = "/accounts/{source_id}/synchronization"
	add("POST", p, "synchronization.wake", "Queue or coalesce manual synchronization", "MEmpty", "MSyncWake", 202, "Does not wait for the round. Disabled/unknown source rejected; does not rewrite automatic cooldown or implicitly trigger from GET.")
	add("GET", p, "synchronization.get", "Current progress or explicit null", "", "MSyncView", 200, "No wake. Final automatic rest begins after the last live/backfill segment, including retry continuations.")
	add("GET", p+"/events", "synchronization.events", "Bounded round/attempt event metadata", "", "MSyncEvents", 200, "Attempt failure and recovered are not terminal failure. Sequence/lost counters preserve exact decimal strings.")
	ops[len(ops)-1].Query = []any{openParameter("after_sequence", "query", openRef("Count"), false), openParameter("round_id", "query", strSchema(), false)}
	add("GET", "/synchronization-statistics", "synchronization.statistics", "Fair scheduler metadata", "", "MSyncStatistics", 200, "Memory metadata only; no wake, network or source query per item.")
	add("GET", "/synchronization/progress", "synchronization.batchProgress", "Requested-order batch progress", "", "MSyncBatch", 200, "1..1000 unique explicit source IDs, requested order. Unknown IDs yield progress:null. No per-source SQL or wake.")
	ids := openParameter("source_id", "query", openObject{"type": "array", "items": openRef("Identifier"), "minItems": 1, "maxItems": 1000, "uniqueItems": true}, true)
	ids["style"] = "form"
	ids["explode"] = true
	ops[len(ops)-1].Query = []any{ids}
	add("GET", "/runtime-events", "events.runtime", "Structured live/history runtime metadata", "", "MRuntimeEvents", 200, "Bounded ring/history with generation/evicted/loss metadata. Level and attempt scope do not imply terminal round status.")
	ops[len(ops)-1].Query = []any{openParameter("stream", "query", openObject{"type": "string", "enum": []string{"live", "history"}, "default": "live"}, false), openParameter("before_id", "query", openRef("Identifier"), false), openParameter("after_id", "query", openRef("Identifier"), false), openParameter("limit", "query", openObject{"type": "integer", "minimum": 1, "maximum": 200, "default": 100}, false), openParameter("level", "query", openObject{"type": "string", "enum": []string{"debug", "info", "warn", "error"}}, false), openParameter("query", "query", strSchema(), false), openParameter("source_id", "query", openRef("Identifier"), false), openParameter("round_key", "query", strSchema(), false)}
	add("GET", "/audit-records", "events.audits", "Durable controlled audit page", "", "MAuditPage", 200, "Controlled fields only; query cannot expose provider/SQL/secret bodies.")
	ops[len(ops)-1].Query = []any{openParameter("page", "query", openObject{"type": "integer", "minimum": 1, "default": 1}, false), openParameter("page_size", "query", openObject{"type": "integer", "minimum": 1, "maximum": 100, "default": 50}, false), openParameter("query", "query", strSchema(), false), openParameter("source_id", "query", openRef("Identifier"), false), openParameter("action", "query", strSchema(), false), openParameter("outcome", "query", strSchema(), false)}
	for _, e := range []struct{ path, id, input, description string }{{"/accounts/{source_id}/retirements", "retire", "MLocalRetirement", "Explicit source retirement, source guard then Authority EX drains active sensitive responses. Exact namespace confirmation."}, {"/addresses/{address_id}/local-purges", "purge", "MLocalPurge", "Explicit local payload purge; exact source/address/revision/confirmation. Retain proof rows and protected/shared/unacknowledged/unknown facts."}, {"/accounts/{source_id}/local-cleanups/query", "query", "MOperationKey", "Original receipt query may progress only already-authorized local collection, never remote mutation or new command."}} {
		add("POST", e.path, "local_cleanup."+e.id, "Local cleanup "+e.id, e.input, "MLocalCleanup", 200, json4K+e.description+" Complete requires inventory_complete/payload_scrubbed plus zero pending/protected/needs_review counts.")
	}
	p = "/addresses/{address_id}"
	add("POST", p+"/mail-preview", "mailout.preview", "Independent body preview", "MMailBodyPreview", "MMailPreview", 200, "Only body is required; recipient/subject/attachments may be supplied by older clients but do not gate rendering. Body100KiB/render512KiB; no network, upload or bootstrap.")
	add("POST", p+"/send-submissions", "mailout.send", "One request prepares and submits mail", "MMailSend", "MMailSubmission", 200, "20MiB HTTP body. The original request owns at most one necessary APPEND/seed and route registration before one final submission. Repeated keys only query. accepted/rejected/not_sent/unknown and durable are independent; accepted is not delivery. Only explicit retryable permits a fresh request retaining the draft; unknown is never replayed.")
	add("POST", p+"/send-submissions/query", "mailout.query", "Query original final submission", "MMailQuery", "MMailSubmission", 200, json4K+queryOnly)
	ops = append(ops, managementOperation{Method: "POST", Path: p + "/compose-contexts", ID: "mailout.prepareContext", Summary: "Retired manual preparation entry", Request: "MComposePrepare", RequestRequired: true, Responses: openObject{"410": openResponse("MAIL_PREPARATION_RETIRED; not_sent. Use a fresh send request for normal composition; retained contexts remain query-only.", openRef("Failure"))}})
	for _, e := range []struct{ suffix, id, input, description string }{{"/query", "queryContext", "MComposeQuery", queryOnly}, {"/refresh", "refreshContext", "MComposeQuery", "Read-only live reference proof; no APPEND, seed, upload or send. Preserve original unknown context facts."}} {
		add("POST", p+"/compose-contexts"+e.suffix, "mailout."+e.id, "Compose context "+e.id, e.input, "MComposeContext", 200, json4K+e.description)
	}
	return ops
}

func strSchema() openObject { return openString() }
