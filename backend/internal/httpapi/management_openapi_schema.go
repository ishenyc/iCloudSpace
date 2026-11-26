package httpapi

import (
	"reflect"
	"strings"

	"icloudspace/internal/mailout"
	"icloudspace/internal/provider/apple"
)

// Only these canonical wire DTOs are admitted. This is a documentation adapter,
// not a runtime decoder or a general API/type-registration platform.
func managementCommonSchemas() openObject {
	schemas := openObject{
		"MEmpty":              openRecord(openObject{}),
		"MNull":               openObject{"type": "null"},
		"MRevision":           openRecord(openObject{"expected_revision": openRef("Identifier")}, "expected_revision"),
		"MOperationKey":       openRecord(openObject{"operation_key": openString()}, "operation_key"),
		"MRequestKey":         openRecord(openObject{"request_key": openString()}, "request_key"),
		"MCount":              openRef("Count"),
		"MOutcome":            openObject{"type": "string", "enum": []string{"accepted", "rejected", "not_sent", "unknown"}},
		"MDecimalNanoseconds": openObject{"type": "string", "pattern": "^(0|[1-9][0-9]*)$", "description": "Exact non-negative duration in nanoseconds; preserve as a string."},
		"MMailCodes":          openArray(openRef("MailCode")),
		"MMailRender":         openRecord(openObject{"html": openString()}, "html"),
	}
	names := map[reflect.Type]string{
		reflect.TypeOf(sessionView{}): "MSession", reflect.TypeOf(operatorView{}): "MOperator",
		reflect.TypeOf(providerSessionView{}): "MProviderSession", reflect.TypeOf(providerReceiptView{}): "MProviderReceipt", reflect.TypeOf(providerAuthView{}): "MProviderAuth",
		reflect.TypeOf(hmeOperationView{}): "MHMEOperation", reflect.TypeOf(providerFailureView{}): "MProviderFailure",
		reflect.TypeOf(addressOperationView{}): "MAddressOperation", // authored with the account/address group
		reflect.TypeOf(creationPolicyView{}):   "MCreationPolicy", reflect.TypeOf(creationSlotView{}): "MCreationSlot", reflect.TypeOf(creationAttemptView{}): "MCreationAttempt", reflect.TypeOf(creationAttemptPage{}): "MCreationAttemptPage",
		reflect.TypeOf(synchronizationScope{}): "MSyncScope", reflect.TypeOf(synchronizationBackfill{}): "MSyncBackfill", reflect.TypeOf(synchronizationFrontier{}): "MSyncFrontier", reflect.TypeOf(synchronizationCounters{}): "MSyncCounters", reflect.TypeOf(synchronizationProgress{}): "MSyncProgress", reflect.TypeOf(synchronizationView{}): "MSyncView", reflect.TypeOf(synchronizationWake{}): "MSyncWake", reflect.TypeOf(synchronizationStatistics{}): "MSyncStatistics", reflect.TypeOf(synchronizationBatchItem{}): "MSyncBatchItem", reflect.TypeOf(synchronizationBatch{}): "MSyncBatch", reflect.TypeOf(synchronizationEvent{}): "MSyncEvent", reflect.TypeOf(synchronizationEvents{}): "MSyncEvents",
		reflect.TypeOf(runtimeEventView{}): "MRuntimeEvent", reflect.TypeOf(runtimeEventPageView{}): "MRuntimeEvents", reflect.TypeOf(auditRecordView{}): "MAuditRecord",
		reflect.TypeOf(localCleanupView{}): "MLocalCleanup", reflect.TypeOf(localCleanupCounts{}): "MLocalCleanupCounts",
		reflect.TypeOf(mailout.Result{}): "MMailSubmission", reflect.TypeOf(mailout.Preview{}): "MMailPreview", reflect.TypeOf(composeContextView{}): "MComposeContext", reflect.TypeOf(mailDraftInput{}): "MMailDraft",
		reflect.TypeOf(mailout.Diagnostic{}): "MMailDiagnostic",
		reflect.TypeOf(apple.AuthOptions{}):  "MAppleAuthOptions", reflect.TypeOf(apple.TrustedPhone{}): "MAppleTrustedPhone", reflect.TypeOf(apple.SecurityKeyChallenge{}): "MAppleSecurityKeyChallenge", reflect.TypeOf(apple.SecurityKeyAssertion{}): "MAppleSecurityKeyAssertion",
		reflect.TypeOf(apple.SessionDocument{}): "MAppleSessionDocument", reflect.TypeOf(apple.Principal{}): "MApplePrincipal", reflect.TypeOf(apple.Browser{}): "MAppleBrowser", reflect.TypeOf(apple.Authentication{}): "MAppleAuthentication", reflect.TypeOf(apple.Services{}): "MAppleServices", reflect.TypeOf(apple.Assurance{}): "MAppleAssurance", reflect.TypeOf(apple.Cookie{}): "MAppleCookie", reflect.TypeOf(apple.AuthFlow{}): "MAppleAuthFlow",
		reflect.TypeOf(Problem{}): "Problem",
	}
	external := map[string]bool{"Problem": true, "MAddressOperation": true}
	var schema func(reflect.Type) any
	var record func(reflect.Type) openObject
	schema = func(t reflect.Type) any {
		if t.Kind() == reflect.Pointer {
			return openNullable(schema(t.Elem()))
		}
		if name, ok := names[t]; ok {
			if _, exists := schemas[name]; !exists && !external[name] {
				schemas[name] = openObject{"type": "object"} // reserved only during recursive construction
				schemas[name] = record(t)
			}
			return openRef(name)
		}
		switch t.Kind() {
		case reflect.String:
			return openString()
		case reflect.Bool:
			return openObject{"type": "boolean"}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint32:
			return openObject{"type": "integer", "format": "int64"}
		case reflect.Slice:
			if t.Elem().Kind() == reflect.Uint8 {
				return openNullable(openObject{"type": "string", "contentEncoding": "base64", "description": "Original bytes encoded as base64; null or omission is an empty attachment under the decoder."})
			}
			return openArray(schema(t.Elem()))
		case reflect.Map:
			if t.Key().Kind() == reflect.String && t.Elem().Kind() == reflect.String {
				return openNullable(openObject{"type": "object", "additionalProperties": openString()})
			}
		case reflect.Struct:
			return record(t)
		}
		panic("httpapi: unmanaged OpenAPI DTO type " + t.String())
	}
	record = func(t reflect.Type) openObject {
		properties := openObject{}
		var required []string
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if len(tag) == 0 || tag[0] == "" || tag[0] == "-" {
				continue
			}
			value := schema(field.Type)
			omitted := strings.Contains(field.Tag.Get("json"), ",omitempty")
			if omitted && field.Type.Kind() == reflect.Pointer {
				value = schema(field.Type.Elem())
			}
			if strings.Contains(field.Tag.Get("json"), ",string") {
				value = openRef("Identifier")
			} else if field.Type.Kind() == reflect.String || field.Type.Kind() == reflect.Pointer && field.Type.Elem().Kind() == reflect.String {
				if typed := managementStringField(t, field.Name); typed != nil {
					value = typed
					if field.Type.Kind() == reflect.Pointer && !omitted {
						value = openNullable(typed)
					}
				}
			}
			properties[tag[0]] = value
			if !strings.Contains(field.Tag.Get("json"), ",omitempty") {
				required = append(required, tag[0])
			}
		}
		return openRecord(properties, required...)
	}
	for t, name := range names {
		if !external[name] {
			schema(t)
		}
	}
	// AuthFlow deliberately retains nil option slices on the wire. Other list
	// presenters explicitly allocate [] and their result arrays stay non-null.
	props := schemas["MAppleAuthOptions"].(openObject)["properties"].(openObject)
	props["phones"] = openNullable(openArray(openRef("MAppleTrustedPhone")))
	props["security_keys"] = openNullable(openArray(openRef("MAppleSecurityKeyChallenge")))
	for name, fields := range map[string]map[string][]string{
		"MProviderAuth":    {"state": {"password", "mfa", "complete", "failed", "expired"}, "next_action": {"", "login", "load_challenge", "send_device_code", "verify_device_code", "send_sms", "verify_sms", "verify_security_key", "trust_browser", "decline_trust", "exchange_token", "validate_session", "restore_session", "clear_authentication"}},
		"MProviderReceipt": {"action": {"login", "load_challenge", "send_device_code", "verify_device_code", "send_sms", "verify_sms", "verify_security_key", "trust_browser", "decline_trust", "exchange_token", "validate_session", "restore_session", "clear_authentication"}},
		"MSyncProgress":    {"trigger": {"automatic", "manual", "public"}, "phase": {"directory", "mail", "finalize", "resolve"}, "state": {"queued", "running", "waiting", "finished"}},
		"MSyncWake":        {"disposition": {"queued", "coalesced"}},
		"MCreationPolicy":  {"schedule_kind": {"scheduled", "interval"}},
		"MCreationSlot":    {"state": {"scheduled", "claimed", "finished", "cancelled", "unknown"}},
		"MCreationAttempt": {"state": {"scheduled", "claimed", "confirmed", "not_created", "unknown", "cancelled"}},
		"MMailSubmission":  {"state": {"reserved", "preparing", "submitting", "finished"}},
		"MComposeContext":  {"state": {"reserved", "preparing", "candidate_unknown", "candidate_confirmed", "draft_ready", "seed_unknown", "ready", "failed"}},
		"MLocalCleanup":    {"kind": {"source_delete", "address_purge"}, "state": {"retired", "cleaning", "blocked", "complete"}},
		"MRuntimeEvent":    {"level": {"debug", "info", "warn", "error"}},
		"MRuntimeEvents":   {"stream": {"live", "history"}},
		"MAuditRecord":     {"actor_kind": {"operator", "address", "system", "historical"}, "outcome": {"success", "rejected", "unknown", "failure"}},
	} {
		p := schemas[name].(openObject)["properties"].(openObject)
		for field, values := range fields {
			p[field] = openObject{"type": "string", "enum": values}
		}
	}
	schemas["MCreationAttempt"].(openObject)["properties"].(openObject)["query_only"] = openObject{"const": true}
	schemas["MSession"].(openObject)["oneOf"] = []any{
		openObject{"properties": openObject{"authenticated": openObject{"const": false}}, "not": openObject{"anyOf": []any{openObject{"required": []string{"operator"}}, openObject{"required": []string{"csrf_token"}}, openObject{"required": []string{"expires_at"}}}}},
		openObject{"properties": openObject{"authenticated": openObject{"const": true}}, "required": []string{"operator", "csrf_token", "expires_at"}},
	}
	schemas["MMailSubmission"].(openObject)["dependentRequired"] = openObject{"reference_id": []string{"reference_kind"}, "reference_kind": []string{"reference_id"}}
	schemas["MMailSubmission"].(openObject)["allOf"] = []any{
		openObject{"if": openObject{"properties": openObject{"outcome": openObject{"const": "unknown"}}, "required": []string{"outcome"}}, "then": openObject{"properties": openObject{"query_only": openObject{"const": true}}}},
		openObject{"if": openObject{"properties": openObject{"state": openObject{"enum": []string{"reserved", "preparing", "submitting"}}}, "required": []string{"state"}}, "then": openObject{"properties": openObject{"outcome": openObject{"const": "unknown"}}}},
	}
	schemas["MComposeContext"].(openObject)["allOf"] = []any{openObject{"if": openObject{"properties": openObject{"state": openObject{"enum": []string{"preparing", "candidate_unknown", "seed_unknown"}}}, "required": []string{"state"}}, "then": openObject{"properties": openObject{"query_only": openObject{"const": true}}}}}
	schemas["MProviderReceipt"].(openObject)["allOf"] = []any{openObject{"if": openObject{"properties": openObject{"prepared": openObject{"const": true}}, "required": []string{"prepared"}}, "then": openObject{"properties": openObject{"outcome": openObject{"const": "unknown"}}}}}
	draft := schemas["MMailDraft"].(openObject)
	// Preview accepts old draft-shaped requests, but only body is validated by
	// the content owner. Never share the mutable sending properties map.
	schemas["MMailBodyPreview"] = openRecord(openObject{
		"body": draft["properties"].(openObject)["body"], "recipient": openString(), "subject": openString(),
		"attachments": openArray(openRecord(openObject{"filename": openString(), "media_type": openString(), "content_id": openString(), "inline": openObject{"type": "boolean"}, "bytes": openNullable(openObject{"type": "string", "contentEncoding": "base64"})})),
	}, "body")
	diagnostic := schemas["MMailDiagnostic"].(openObject)["properties"].(openObject)
	for _, field := range []string{"stage", "kind", "provider_code", "operation", "transport_phase", "transport_reason"} {
		diagnostic[field] = openObject{"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"}
	}
	diagnostic["http_status"] = openObject{"type": "integer", "minimum": 100, "maximum": 599}
	diagnostic["attempts"] = openObject{"type": "integer", "minimum": 1, "maximum": 3}
	draft["required"] = []string{"recipient", "subject", "body"}
	draftProps := draft["properties"].(openObject)
	draftProps["subject"] = openObject{"type": "string", "minLength": 1, "maxLength": 998, "x-maxUtf8Bytes": 998, "description": "Trim leading/trailing whitespace; nonempty subject and no control characters. Sending requires nonempty rendered body text or at least one attachment, including a valid empty attachment."}
	body := draftProps["body"].(openObject)
	body["required"] = []string{"format"}
	bodyProps := body["properties"].(openObject)
	bodyProps["format"] = openObject{"type": "string", "enum": []string{"text", "markdown", "html"}}
	bodyProps["source"] = openObject{"type": "string", "maxLength": 102400, "x-maxUtf8Bytes": 102400}
	attachments := draftProps["attachments"].(openObject)
	attachments["maxItems"] = 10
	attachment := attachments["items"].(openObject)
	attachment["required"] = []string{"filename", "media_type"}
	draftProps["attachments"] = openNullable(attachments)
	draft["description"] = "20MiB outer HTTP JSON; at most10 attachments and10MiB total decoded attachment bytes, validated CID/media/filename. Rendered output<=512KiB. Defaults for omitted optional source/attachments are empty values; inline=true requires a validated matching image CID."
	schemas["MAppleSessionDocument"].(openObject)["description"] = "Secret provider capsule input only, validated strictly by DecodeSession. Its signed int64 Unix-nanosecond field is an exact JSON integer; use document_json to avoid JavaScript Number rounding. Prior validation timestamps are not trusted."
	schemas["MAppleSessionDocument"].(openObject)["writeOnly"] = true
	return schemas
}

func managementStringField(t reflect.Type, field string) any {
	if t.PkgPath() == "icloudspace/internal/provider/apple" {
		if field == "Region" {
			return openObject{"type": "string", "enum": []string{"global", "china"}}
		}
		if field == "Mode" {
			return openObject{"type": "string", "enum": []string{"sms", "voice"}}
		}
		return nil
	}
	if strings.HasPrefix(t.Name(), "synchronization") && field == "Outcome" {
		return openObject{"type": "string", "enum": []string{"succeeded", "degraded", "failed", "cancelled", "superseded", "unknown"}}
	}
	if t == reflect.TypeOf(runtimeEventPageView{}) && field == "Generation" {
		return openString()
	}
	if field == "Outcome" && t != reflect.TypeOf(runtimeEventView{}) && t != reflect.TypeOf(auditRecordView{}) || field == "AppendOutcome" || field == "SeedOutcome" || field == "RouteOutcome" {
		return openRef("MOutcome")
	}
	if field == "ActiveNanoseconds" {
		return openRef("MDecimalNanoseconds")
	}
	if field == "ID" || field == "SourceID" || field == "AddressID" || field == "PrincipalRevision" || field == "ChallengeRevision" || field == "PolicyRevision" || field == "Revision" || field == "Generation" || field == "CredentialGeneration" || field == "ConfigurationRevision" || field == "ScanEpoch" || field == "CandidateUIDValidity" {
		return openRef("Identifier")
	}
	if strings.HasPrefix(t.Name(), "synchronization") && (field == "UIDValidity" || field == "CapturedUpper" || field == "Committed" || field == "Attempts" || field == "FailedAttempts" || field == "Segments" || field == "Retries" || field == "AdmissionWaits" || field == "AdmissionErrors" || field == "Sources" || field == "Ready" || field == "InFlight" || field == "Slots" || field == "CatalogErrors" || field == "CatalogReloads" || field == "Sequence" || field == "After" || field == "LastSequence" || field == "Lost" || field == "Discovered" || field == "Archived" || field == "Links" || field == "Bytes") {
		return openRef("Count")
	}
	if t == reflect.TypeOf(localCleanupCounts{}) || field == "AfterID" {
		return openRef("Count")
	}
	if field == "BeforeID" || field == "NextBeforeID" || field == "EarliestID" || field == "LatestID" || field == "NextAfterID" || field == "IntervalMilliseconds" {
		return openRef("Identifier")
	}
	if strings.HasSuffix(field, "At") || field == "At" || field == "ScheduledFor" || field == "AutomaticAfter" || field == "CooldownUntil" {
		return openRef("Instant")
	}
	if field == "ReferenceKind" {
		return openObject{"type": "string", "enum": []string{"incoming", "bootstrap_seed", "hme_route"}}
	}
	return nil
}
