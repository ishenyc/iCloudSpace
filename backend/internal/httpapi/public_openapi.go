package httpapi

import "strings"

type openObject = map[string]any

func openRef(name string) openObject { return openObject{"$ref": "#/components/schemas/" + name} }
func openString() openObject         { return openObject{"type": "string"} }
func openArray(item any) openObject  { return openObject{"type": "array", "items": item} }
func openRecord(properties openObject, required ...string) openObject {
	value := openObject{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		value["required"] = required
	}
	return value
}
func openNullable(value any) openObject {
	return openObject{"anyOf": []any{value, openObject{"type": "null"}}}
}
func openEnvelope(value any) openObject {
	return openRecord(openObject{"result": value, "meta": openRef("Meta")}, "result", "meta")
}
func openJSON(value any) openObject {
	return openObject{"application/json": openObject{"schema": value}}
}
func openResponse(description string, value any) openObject {
	return openObject{"description": description, "content": openJSON(value), "headers": openObject{"Cache-Control": openObject{"schema": openObject{"type": "string", "const": "no-store"}}}}
}
func openParameter(name, location string, schema any, required bool) openObject {
	return openObject{"name": name, "in": location, "required": required, "schema": schema}
}

func externalRegistrationSchema() openObject {
	str := openString()
	nullable := openNullable(str)
	boolean := openObject{"type": "boolean"}
	return openRecord(openObject{"operation_key": str, "source_id": openRef("Identifier"), "address": str, "state": openObject{"enum": []string{"prepared", "committed", "cancelled"}}, "address_id": openNullable(openRef("Identifier")), "generation": openNullable(openRef("Identifier")), "delivery_key": nullable, "query_only": boolean, "available": boolean, "unavailable_reason": nullable, "effective_enabled": boolean, "bundle": openRef("CredentialBundle")}, "operation_key", "source_id", "address", "state", "address_id", "generation", "delivery_key", "query_only", "available", "unavailable_reason", "effective_enabled")
}

func publicSchemas() openObject {
	str := openString()
	boolean := openObject{"type": "boolean"}
	uid := openObject{"type": "integer", "minimum": 1, "maximum": 4294967295}
	identifier := openObject{"type": "string", "pattern": "^[1-9][0-9]*$", "description": "Exact positive signed-int64 decimal; never convert through a JavaScript Number."}
	count := openObject{"type": "string", "pattern": "^(0|[1-9][0-9]*)$"}
	instant := openObject{"type": "string", "format": "date-time", "description": "UTC RFC3339Nano, up to nine fractional digits, signed Unix nanosecond range."}
	mailbox := openRecord(openObject{"name": str, "address": str}, "address")
	remote := openRecord(openObject{"source_generation": identifier, "mailbox": str, "uid_validity": uid, "uid": uid}, "source_generation", "mailbox", "uid_validity", "uid")
	metadata := openRecord(openObject{"entry_id": openNullable(identifier), "message_id": identifier, "uid": openNullable(uid), "remote": openRef("MailRemote"), "rfc_message_id": str, "subject": str, "from": openArray(mailbox), "to": openArray(mailbox), "cc": openArray(mailbox), "sent_at": openNullable(instant), "received_at": instant, "visible_at": openNullable(instant), "seen": boolean, "content_state": openObject{"enum": []string{"complete", "metadata_only", "over_budget", "malformed"}}, "raw_state": openObject{"enum": []string{"staged", "available", "evicted", "missing", "corrupt", "over_budget", "metadata_only"}}, "declared_body_size": count, "declared_body_truncated": boolean, "preview": str}, "entry_id", "message_id", "uid", "remote", "rfc_message_id", "subject", "from", "to", "cc", "sent_at", "received_at", "visible_at", "seen", "content_state", "raw_state", "declared_body_size", "declared_body_truncated", "preview")
	attachment := openRecord(openObject{"part": str, "filename": str, "media_type": str, "disposition": str, "content_id": str, "inline": boolean, "byte_size": count, "complete": boolean}, "part", "filename", "media_type", "disposition", "content_id", "inline", "byte_size", "complete")
	message := openRecord(openObject{"metadata": openRef("MailMetadata"), "text": str, "html": str, "attachments": openArray(openRef("MailAttachment")), "body_complete": boolean}, "metadata", "text", "html", "attachments", "body_complete")
	reference := openRecord(openObject{"auth_generation": identifier, "message_id": identifier, "entry_id": openNullable(identifier), "uid": openNullable(uid), "uid_validity": identifier, "view_key": str, "view_scope_address_id": openNullable(identifier), "selected_at": instant, "remote": openRef("MailRemote")}, "auth_generation", "message_id", "entry_id", "uid", "uid_validity", "view_key", "view_scope_address_id", "selected_at", "remote")
	purpose := openObject{"enum": []string{"latest_read", "mail_read", "mail_consume", "raw_read", "imap_login"}}
	apiSecret := openRecord(openObject{"key": str}, "key")
	imapSecret := openRecord(openObject{"password": str}, "password")
	oauthSecret := openRecord(openObject{"client_id": str, "refresh_token": str}, "client_id", "refresh_token")
	problem := openRecord(openObject{"kind": str, "code": str, "message": str, "submission_key": str, "outcome": openObject{"enum": []string{"accepted", "rejected", "not_sent", "unknown"}}, "resource": openRecord(openObject{"kind": openObject{"enum": []string{"account", "address", "address_group"}}, "id": str}, "kind", "id")}, "kind", "code", "message")
	return openObject{
		"Identifier": identifier, "Count": count, "Instant": instant, "UID": uid, "Meta": openRecord(openObject{"request_id": str}), "Problem": problem, "Failure": openRecord(openObject{"error": openRef("Problem"), "meta": openRef("Meta")}, "error", "meta"),
		"Mailbox": mailbox, "MailRemote": remote, "MailMetadata": metadata, "MailAttachment": attachment, "MailMessage": message, "MailReference": reference,
		"MailPage":       openRecord(openObject{"items": openArray(openRef("MailMetadata")), "more": boolean, "next_time": openNullable(instant), "next_id": openNullable(identifier)}, "items", "more", "next_time", "next_id"),
		"MailSnapshot":   openRecord(openObject{"reference": openRef("MailReference"), "message": openRef("MailMessage"), "consumed": boolean}, "reference", "message", "consumed"),
		"MailCode":       openRecord(openObject{"code": openObject{"type": "string", "pattern": "^[0-9]{6}$"}, "entry_id": identifier, "uid": uid, "received_at": instant}, "code", "entry_id", "uid", "received_at"),
		"MailClaimInput": openRecord(openObject{"claim_key": openObject{"type": "string", "minLength": 1, "maxLength": 128}, "reference": openRef("MailReference")}, "claim_key", "reference"),
		"MailClaim":      openRecord(openObject{"claim_key": str, "committed": openObject{"const": true}, "remote": openRef("MailRemote"), "claimed_at": instant, "snippet": str}, "claim_key", "committed", "remote", "claimed_at"),
		"MailPurpose":    purpose, "MailAccess": openRecord(openObject{"access_token": str, "token_type": openObject{"const": "Bearer"}, "expires_at": instant, "address_id": identifier, "purposes": openArray(purpose)}, "access_token", "token_type", "expires_at", "address_id", "purposes"),
		"MailDerive":                openRecord(openObject{"purpose": openObject{"enum": []string{"latest_read", "mail_read", "mail_consume", "raw_read"}}, "lifetime_seconds": openObject{"type": "integer", "minimum": 1, "maximum": 3600}}, "purpose", "lifetime_seconds"),
		"MailRefresh":               openRecord(openObject{"client_id": str, "refresh_token": str, "purposes": openArray(purpose)}, "client_id", "refresh_token", "purposes"),
		"CredentialBundle":          openRecord(openObject{"version": openObject{"const": 1}, "api": apiSecret, "imap": imapSecret, "oauth": oauthSecret}, "version", "api", "imap", "oauth"),
		"ExternalRegistrationInput": openRecord(openObject{"source_id": identifier, "address": str, "operation_key": openObject{"type": "string", "minLength": 1, "maxLength": 128}}, "source_id", "address", "operation_key"),
		"ExternalRegistrationQuery": openRecord(openObject{"source_id": identifier, "operation_key": str}, "source_id", "operation_key"),
		"ExternalRegistration":      externalRegistrationSchema(),
		"OAuthToken":                openRecord(openObject{"access_token": str, "token_type": openObject{"const": "Bearer"}, "expires_in": openObject{"type": "integer", "const": 3600}, "scope": str}, "access_token", "token_type", "expires_in", "scope"),
		"OAuthError":                openRecord(openObject{"error": openObject{"enum": []string{"invalid_request", "unsupported_grant_type", "invalid_scope", "invalid_grant", "server_error", "temporarily_unavailable"}}, "error_description": str}, "error", "error_description"),
		"ViewerBootstrap":           openRecord(openObject{"version": openObject{"const": 1}, "address_id": identifier, "public_mail_path": openObject{"const": PublicMailBase}}, "version", "address_id", "public_mail_path"),
	}
}

func publicOpenAPI() openObject {
	paths := openObject{}
	add := func(method, path, id, summary, purpose string, schema any) {
		responses := openObject{"200": openResponse("Success; a GET never consumes or writes Seen.", openEnvelope(schema)), "400": openResponse("Invalid exact input.", openRef("Failure")), "401": openResponse("Missing, expired, revoked or wrong credential.", openRef("Failure")), "403": openResponse("Purpose or mailbox denied.", openRef("Failure")), "404": openResponse("No matching resource.", openRef("Failure")), "410": openResponse("Original unavailable; no invented complete MIME.", openRef("Failure")), "422": openResponse("Stored content cannot be presented safely.", openRef("Failure")), "500": openResponse("Controlled storage failure.", openRef("Failure")), "503": openResponse("Temporarily unavailable; unknown commands must not be replayed.", openRef("Failure"))}
		op := openObject{"operationId": id, "summary": summary, "responses": responses, "security": []any{openObject{"MailboxAPIKey": []string{}}, openObject{"OpaqueBearer": []string{}}}, "x-required-purpose": purpose}
		var parameters []any
		if strings.Contains(path, "{address_id}") {
			parameters = append(parameters, openParameter("address_id", "path", openRef("Identifier"), true))
		}
		if strings.Contains(path, "{uid}") {
			parameters = append(parameters, openParameter("uid", "path", openRef("UID"), true))
		}
		if strings.Contains(path, "{part}") {
			parameters = append(parameters, openParameter("part", "path", openObject{"type": "string", "pattern": "^(root|[1-9][0-9]*(\\.[1-9][0-9]*)*)$"}, true))
		}
		if len(parameters) > 0 {
			op["parameters"] = parameters
		}
		item, ok := paths[path].(openObject)
		if !ok {
			item = openObject{}
			paths[path] = item
		}
		item[strings.ToLower(method)] = op
	}
	p := PublicMailBase + "/addresses/{address_id}"
	for _, e := range []struct{ suffix, id, summary, purpose, schema string }{
		{"/latest", "p.mail.latest", "Latest exact snapshot", "latest_read or mail_read", "MailSnapshot"}, {"/recent", "p.mail.recent", "Unconsumed current snapshot in [now-1h,now]", "latest_read or mail_read", "MailSnapshot"},
		{"/codes", "p.mail.codes", "At most 100 retained six-digit codes", "mail_read", "MailCode"}, {"/messages", "p.mail.list", "Metadata history page", "mail_read", "MailPage"},
		{"/messages/{uid}", "p.mail.message", "Stored parsed message view", "mail_read", "MailMessage"}, {"/raw/messages", "p.mail.rawList", "Raw candidate metadata page; not proof of available bytes", "raw_read", "MailPage"},
		{"/raw/messages/{uid}/view", "p.mail.rawMessageView", "Parsed display and attachment descriptors from verified original", "raw_read", "MailMessage"},
	} {
		schema := any(openRef(e.schema))
		if e.schema == "MailCode" {
			schema = openArray(schema)
		}
		add("GET", p+e.suffix, e.id, e.summary, e.purpose, schema)
	}
	for _, suffix := range []string{"/messages", "/raw/messages"} {
		op := paths[p+suffix].(openObject)["get"].(openObject)
		op["parameters"] = append(op["parameters"].([]any), openParameter("limit", "query", openObject{"type": "integer", "minimum": 1, "maximum": 1000, "default": 20}, false), openParameter("before_time", "query", openRef("Instant"), false), openParameter("before_id", "query", openRef("Identifier"), false))
		op["description"] = "before_time and before_id must appear together. Cursor follows visible_at DESC, entry_id DESC. Unknown/repeated query fields are rejected."
	}
	op := paths[p+"/codes"].(openObject)["get"].(openObject)
	op["parameters"] = append(op["parameters"].([]any), openParameter("limit", "query", openObject{"type": "integer", "minimum": 1, "maximum": 100, "default": 100}, false))
	add("GET", p+"/codes/latest/text", "p.mail.latestCodeText", "Latest code as exactly six ASCII bytes or empty204", "mail_read", openObject{})
	text := paths[p+"/codes/latest/text"].(openObject)["get"].(openObject)["responses"].(openObject)
	text["200"] = openObject{"description": "Exactly six ASCII digit bytes.", "content": openObject{"text/plain": openObject{"schema": openObject{"type": "string", "pattern": "^[0-9]{6}$"}}}}
	text["204"] = openObject{"description": "No retained code; no body."}
	for _, e := range []struct{ suffix, id, summary, media string }{
		{"/raw/latest", "p.mail.rawLatest", "Latest verified available MIME, skipping unavailable originals", "message/rfc822"},
		{"/messages/{uid}/raw", "p.mail.raw", "Exact original MIME download", "message/rfc822"},
		{"/messages/{uid}/attachments/{part}", "p.mail.attachment", "Decoded verified attachment download", "*/*"},
	} {
		add("GET", p+e.suffix, e.id, e.summary, "raw_read", openObject{})
		op := paths[p+e.suffix].(openObject)["get"].(openObject)
		responses := op["responses"].(openObject)
		response := openObject{"description": "Verified original bytes; incomplete stream is a failed download.", "content": openObject{e.media: openObject{"schema": openObject{"type": "string", "format": "binary"}}}}
		responses["200"] = response
		if e.media == "message/rfc822" {
			responses["206"] = response
			responses["416"] = openObject{"description": "Unsatisfiable byte Range."}
			op["parameters"] = append(op["parameters"].([]any), openParameter("Range", "header", openString(), false))
		}
	}
	add("GET", p+"/messages/{uid}/render", "p.mail.render", "Sanitized HTML fragment from verified original", "raw_read", openRecord(openObject{"html": openString()}, "html"))
	for _, e := range []struct{ suffix, id, summary string }{{"/consume", "p.mail.consume", "Consume exact snapshot once and persist Seen intent"}, {"/claims/query", "p.mail.queryClaim", "Query original claim; never consume or STORE again"}} {
		add("POST", p+e.suffix, e.id, e.summary, "mail_consume", openRef("MailClaim"))
		op := paths[p+e.suffix].(openObject)["post"].(openObject)
		op["requestBody"] = openObject{"required": true, "description": "16KiB maximum. Original claim_key and exact immutable reference are retained on unknown.", "content": openJSON(openRef("MailClaimInput"))}
		op["responses"].(openObject)["409"] = openResponse("Snapshot changed or already consumed; do not replay.", openRef("Failure"))
	}
	for _, e := range []struct{ suffix, id, summary, schema string }{{"/access/derive", "p.mail.derive", "Explicit APIKey-derived narrow opaque grant", "MailDerive"}, {"/access/refresh", "p.mail.refresh", "JSON exchange of existing client_id and refresh_token", "MailRefresh"}} {
		add("POST", p+e.suffix, e.id, e.summary, "explicit authenticator factors", openRef("MailAccess"))
		op := paths[p+e.suffix].(openObject)["post"].(openObject)
		op["requestBody"] = openObject{"required": true, "description": "Explicit exchange only; no automatic retry or long-secret rotation.", "content": openJSON(openRef(e.schema))}
		responses := op["responses"].(openObject)
		responses["201"] = responses["200"]
		delete(responses, "200")
		if e.schema == "MailDerive" {
			op["security"] = []any{openObject{"MailboxAPIKey": []string{}}}
		} else {
			op["security"] = []any{}
		}
	}
	for _, query := range []bool{false, true} {
		path := ExternalRegistrationBase
		id, summary, input := "e.external_registration.register", "Local external registration without provider actions", "ExternalRegistrationInput"
		if query {
			path += "/query"
			id, summary, input = "e.external_registration.query", "Query original registration, not a retry", "ExternalRegistrationQuery"
		}
		add("POST", path, id, summary, "separate deployment credential", openRef("ExternalRegistration"))
		op := paths[path].(openObject)["post"].(openObject)
		op["security"] = []any{openObject{"DeploymentBearer": []string{}}}
		op["requestBody"] = openObject{"required": true, "description": "Exactly known fields, all strings;4096-byte JSON maximum. Same operation_key cannot register again.", "content": openJSON(openRef(input))}
		responses := op["responses"].(openObject)
		responses["409"] = openResponse("Conflict or existing original operation requires query.", openRef("Failure"))
		if !query {
			responses["201"] = responses["200"]
			delete(responses, "200")
		}
	}
	paths[OAuthTokenPath] = openObject{"post": oauthOpenOperation()}
	paths["/healthz"] = openObject{"get": openObject{"operationId": "absolute.health.health", "summary": "Readiness without installation secrets", "security": []any{}, "responses": openObject{"200": openResponse("Ready status only; not migration or delivery evidence.", openRecord(openObject{"status": openObject{"const": "ok"}}, "status")), "503": openResponse("Unavailable.", openRecord(openObject{"status": openObject{"const": "unavailable"}}, "status"))}}}
	for _, e := range []struct{ path, id, summary, media string }{{"/docs/", "public.docs", "Public documentation", "text/html"}, {"/openapi.json", "public.openapi", "Public OpenAPI3.1 specification", "application/json"}, {"/viewer/addresses/{address_id}", "public.viewer", "Standalone raw_read viewer shell; fragment credential stays in browser", "text/html"}} {
		op := openObject{"operationId": e.id, "summary": e.summary, "security": []any{}, "responses": openObject{"200": openObject{"description": "Static public representation; no account or credential data is injected.", "content": openObject{e.media: openObject{"schema": openObject{"type": "string"}}}}}}
		if strings.Contains(e.path, "{address_id}") {
			op["parameters"] = []any{openParameter("address_id", "path", openRef("Identifier"), true)}
		}
		paths[e.path] = openObject{"get": op}
	}
	paths["/docs"] = openObject{"get": openObject{"operationId": "public.docsRedirect", "summary": "Canonical documentation navigation", "security": []any{}, "responses": openObject{"308": openObject{"description": "Navigate to /docs/."}, "400": openObject{"description": "Query parameters are not accepted."}}}}
	spec := openObject{"openapi": "3.1.1", "jsonSchemaDialect": "https://spec.openapis.org/oas/3.1/dialect/base", "info": openObject{"title": "iCloudSpace public canonical API", "version": "1", "description": "Public protocols and fixed management templates; no installation values or secrets."}, "servers": []any{openObject{"url": "/"}}, "paths": paths, "components": openObject{"schemas": publicSchemas(), "securitySchemes": openObject{"MailboxAPIKey": openObject{"type": "apiKey", "in": "header", "name": "Authorization", "description": "Exactly APIKey <original-key>, purpose-bound. Never a Bearer, Cookie or URL token."}, "OpaqueBearer": openObject{"type": "http", "scheme": "bearer", "bearerFormat": "opaque", "description": "Purpose/address/generation-bound opaque access; no management or deployment authority."}, "DeploymentBearer": openObject{"type": "http", "scheme": "bearer", "bearerFormat": "deployment", "description": "Independent optional deployment registration token. Empty installation configuration is disabled; never interchangeable with mailbox access."}}}}
	mergeManagementOpenAPI(spec)
	mergeCompatiblePublicOpenAPI(spec)
	return spec
}

func mergeCompatiblePublicOpenAPI(spec openObject) {
	components := spec["components"].(openObject)
	schemas := components["schemas"].(openObject)
	str, boolean := openString(), openObject{"type": "boolean"}
	instant := openObject{"type": "string", "format": "date-time", "description": "RFC3339; OTP/recent use the configured installation timezone, latest received_at/synced_at use UTC."}
	code := openRecord(openObject{"otp": str, "time": instant}, "otp", "time")
	failure := openRecord(openObject{"error": openRecord(openObject{"code": str, "message": str, "request_id": str}, "code", "message", "request_id")}, "error")
	mailbox := openRecord(openObject{"name": str, "email": str}, "email")
	attachment := openRecord(openObject{"filename": str, "content_type": str, "size": openObject{"type": "integer", "minimum": 0}}, "filename", "content_type", "size")
	message := openRecord(openObject{
		"id":         openObject{"type": "string", "pattern": "^[0-9]+-[0-9]+$", "description": "Remote UIDValidity-UID identifier."},
		"message_id": str, "received_at": instant, "sent_at": openNullable(instant),
		"from": openArray(mailbox), "to": openArray(mailbox), "cc": openArray(mailbox),
		"subject": str, "text": str, "html": str, "attachments": openArray(attachment), "has_attachments": boolean, "body_truncated": boolean,
	}, "id", "message_id", "received_at", "sent_at", "from", "to", "cc", "subject", "text", "html", "attachments", "has_attachments", "body_truncated")
	schemas["CompatibleOTP"] = code
	schemas["CompatiblePublicFailure"] = failure
	schemas["CompatibleLatest"] = openRecord(openObject{"data": openRecord(openObject{"alias": str, "message": message, "synced_at": instant, "stale": openObject{"const": false}}, "alias", "message", "synced_at", "stale")}, "data")
	schemas["CompatibleRecent"] = openRecord(openObject{"data": openRecord(openObject{"address": str, "subject": str, "snippet": str, "sent_at": instant}, "address", "subject", "snippet", "sent_at")}, "data")
	schemas["CompatibleOAuthToken"] = openRecord(openObject{"access_token": str, "token_type": openObject{"const": "Bearer"}, "expires_in": openObject{"type": "integer", "const": 3600}}, "access_token", "token_type", "expires_in")
	schemas["CompatibleOAuthError"] = openRecord(openObject{"error": openObject{"enum": []string{"invalid_request", "invalid_client", "temporarily_unavailable"}}, "error_description": str}, "error", "error_description")
	schemas["CompatibleAliasRegistration"] = openRecord(openObject{"data": openRecord(openObject{"alias": str, "icloud": str, "api_key": str, "mail_api_direct_link": openObject{"type": "string", "description": "Relative /api/v1/mail/recent?api_key=<recent-purpose-token>; explicit GET consumes once."}}, "alias", "icloud", "api_key", "mail_api_direct_link")}, "data")
	security := components["securitySchemes"].(openObject)
	security["CompatibleAPIKeyBearer"] = openObject{"type": "http", "scheme": "bearer", "bearerFormat": "mailbox API key", "description": "Long-lived mailbox API key in the Bearer header for /api/v1 endpoints. Permissions are checked against the current address grants."}
	security["CompatibleOTPToken"] = openObject{"type": "apiKey", "in": "query", "name": "token", "description": "OTP-purpose link token bound to current address and APIKey hash. Cannot be mixed with Authorization."}
	security["CompatibleRecentKey"] = openObject{"type": "apiKey", "in": "query", "name": "api_key", "description": "Mailbox API key or recent-purpose link token. This query alone authorizes the consuming GET; an extra Authorization header is not selected."}
	paths := spec["paths"].(openObject)
	responses := func(value any) openObject {
		return openObject{"200": openResponse("Endpoint response without a result/meta envelope.", value), "401": openResponse("Invalid credential or purpose.", openRef("CompatiblePublicFailure")), "404": openResponse("No eligible mail.", openRef("CompatiblePublicFailure")), "503": openResponse("SYNC_UNAVAILABLE or DATABASE_UNAVAILABLE; preserve request_id and query an uncertain operation, never replay it.", openRef("CompatiblePublicFailure"))}
	}
	otpResponses := responses(openObject{"anyOf": []any{openArray(openRef("CompatibleOTP")), openRef("CompatibleOTP")}})
	otpResponses["400"] = openResponse("Invalid boolean or incompatible raw_mail/otp_only/latest_only combination.", openRef("CompatiblePublicFailure"))
	otpContent := otpResponses["200"].(openObject)["content"].(openObject)
	otpContent["text/plain"] = openObject{"schema": openObject{"type": "string", "description": "OTP only when latest_only=true and otp_only=true are explicit and a code exists; empty remains JSON200 []."}}
	otpContent["text/html"] = openObject{"schema": openObject{"type": "string", "description": "raw_mail=true: direct, sandboxed HTML with bounded pagination across all readable history; no JavaScript or fragment handshake."}}
	paths["/api/v1/otp"] = openObject{"get": openObject{
		"operationId": "compatible.otp", "summary": "Read OTP as JSON/text or view raw mail as HTML", "x-consumes-mail": false,
		"description": "Use exactly one mailbox API key in the Bearer header or an OTP query token. Repeated/unknown query fields and mixed authentication are rejected. Default JSON contains up to 100 {otp,time} entries. Configured latest-only may select one object; when no code is available, the response is HTTP 200 with []. otp_only=true requires explicit latest_only=true and rejects raw_mail=true. raw_mail uses only explicit latest_only, skips unreadable messages, and never consumes or writes Seen.",
		"security":    []any{openObject{"CompatibleAPIKeyBearer": []string{}}, openObject{"CompatibleOTPToken": []string{}}},
		"parameters":  []any{openParameter("latest_only", "query", boolean, false), openParameter("otp_only", "query", boolean, false), openParameter("raw_mail", "query", boolean, false), openParameter("raw_format", "query", openObject{"type": "string", "enum": []string{"iframe", "html"}, "default": "iframe", "description": "Only with raw_mail=true; iframe isolates each body by default, html embeds sanitized body markup directly. Exactly one value; invalid combinations return400."}, false)}, "responses": otpResponses,
	}}
	paths["/api/v1/mail/latest"] = openObject{"get": openObject{
		"operationId": "compatible.mail.latest", "summary": "Read the latest mail snapshot without consumption", "x-consumes-mail": false,
		"description": "The mailbox API key identifies its address. Synchronization must be successful, nonfuture and no older than max(3*PollInterval,SyncTimeout+2*PollInterval), otherwise HTTP 503 SYNC_UNAVAILABLE. No mail returns HTTP 404 MAIL_NOT_FOUND. Does not consume or write Seen.",
		"security":    []any{openObject{"CompatibleAPIKeyBearer": []string{}}}, "responses": responses(openRef("CompatibleLatest")),
	}}
	for _, path := range []string{"/api/v1/mail/recent", "/api/v1/mail/recent/"} {
		id := "compatible.mail.recent"
		if strings.HasSuffix(path, "/") {
			id += ".slash"
		}
		r := responses(openRef("CompatibleRecent"))
		r["405"] = openResponse("HEAD does not consume; only explicit GET is accepted.", openRef("CompatiblePublicFailure"))
		paths[path] = openObject{"get": openObject{
			"operationId": id, "summary": "Consume recent mail once and queue Seen", "x-consumes-mail": true,
			"description": "The api_key query accepts a mailbox API key or a recent-purpose token; extra Authorization is ignored. Uses the current unconsumed nonfuture snapshot in [now-1h,now] and the same synchronization freshness check as latest. One request owns one durable request ID and one Consume/Seen transaction. Concurrent GETs permit one success; already consumed, absent or expired mail returns HTTP 404. A latest_read grant authorizes only this address, current snapshot and one consumption; it does not grant history, raw, OAuth or IMAPS access. The user must explicitly open this URL: no preload, hover fetch, polling or automatic retry, including unknown responses.",
			"security":    []any{openObject{"CompatibleRecentKey": []string{}}}, "responses": r,
		}}
	}
	paths[CompatibleOAuthTokenPath] = openObject{"post": openObject{
		"operationId": "compatible.oauth.token", "summary": "Exchange refresh credentials for a one-hour IMAPS token", "security": []any{},
		"requestBody": openObject{"required": true, "description": "application/x-www-form-urlencoded only,16KiB maximum; exactly one of each required field, no query or scope. Trim outer client_id whitespace; refresh_token must be nonempty with no surrounding whitespace; neither resulting value may contain space/tab/CR/LF.", "content": openObject{"application/x-www-form-urlencoded": openObject{"schema": openRecord(openObject{"grant_type": openObject{"const": "refresh_token"}, "client_id": str, "refresh_token": str}, "grant_type", "client_id", "refresh_token")}}},
		"responses":   openObject{"200": openResponse("Native three-field response; no scope/result/meta. IMAPS purpose only; do not retry an unknown issuance.", openRef("CompatibleOAuthToken")), "400": openResponse("invalid_request", openRef("CompatibleOAuthError")), "401": openResponse("invalid_client", openRef("CompatibleOAuthError")), "503": openResponse("temporarily_unavailable", openRef("CompatibleOAuthError"))},
	}}
	for _, path := range []string{"/api/v1/aliases", "/api/v1/aliases/"} {
		id := "compatible.aliases.register"
		if strings.HasSuffix(path, "/") {
			id += ".slash"
		}
		aliasResponses := openObject{"201": openResponse("Committed alias, mailbox API key and recent-purpose URL. Disclosure does not acknowledge pending credentials.", openRef("CompatibleAliasRegistration"))}
		for _, status := range []string{"400", "401", "404", "409", "413", "415", "500", "503"} {
			aliasResponses[status] = openResponse("Error response with request_id. An unknown HTTP 503 retains this operation reference; query it before taking further action and do not POST again.", openRef("CompatiblePublicFailure"))
		}
		paths[path] = openObject{"post": openObject{
			"operationId": id, "summary": "Register a local alias using the source account email",
			"security":    []any{openObject{"DeploymentBearer": []string{}}},
			"description": "Deployment Bearer is checked before parsing. Exactly add_hide_my_eamil and icloud once across form and query, combined4KiB maximum; normalize email case/outer whitespace. No Apple create call. Same address conflicts; request ID becomes the existing registration owner's operation key for an uncertain result, never replayed.",
			"parameters":  []any{openParameter("add_hide_my_eamil", "query", str, false), openParameter("icloud", "query", str, false)},
			"requestBody": openObject{"required": false, "content": openObject{"application/x-www-form-urlencoded": openObject{"schema": openRecord(openObject{"add_hide_my_eamil": str, "icloud": str})}}}, "responses": aliasResponses,
		}}
	}
}

func oauthOpenOperation() openObject {
	secret := openObject{"type": "string", "minLength": 1, "maxLength": 4096, "description": "1..4096 UTF8 bytes, preserved exactly; no NUL/CR/LF."}
	responses := openObject{"200": openResponse("Native OAuth response, never result/meta. Long-lived credentials remain unchanged.", openRef("OAuthToken"))}
	for _, status := range []string{"400", "500", "503"} {
		responses[status] = openResponse("Native fixed safe OAuth error. Unknown issuance is not automatic retry permission.", openRef("OAuthError"))
	}
	return openObject{"operationId": "absolute.oauth_token.token", "summary": "Standard one-hour opaque refresh grant", "security": []any{}, "requestBody": openObject{"required": true, "description": "16KiB form only; every field once; no query or Authorization. client_id+refresh_token must bind the same unique current mailbox.", "content": openObject{"application/x-www-form-urlencoded": openObject{"schema": openRecord(openObject{"grant_type": openObject{"const": "refresh_token"}, "client_id": secret, "refresh_token": secret, "scope": openObject{"type": "string", "description": "Optional unique space-delimited mail_read, mail_consume, raw_read, imap_login. Result is the actual retained intersection."}}, "grant_type", "client_id", "refresh_token")}}}, "responses": responses}
}
