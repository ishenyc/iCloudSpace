package httpapi

func managementMailRoutes() []managementOperation {
	p := "/addresses/{address_id}/mail"
	var operations []managementOperation
	for _, e := range []struct{ suffix, id, response string }{
		{"/latest", "latest", "MailSnapshot"}, {"/recent", "recent", "MailSnapshot"},
		{"/codes", "codes", "MMailCodes"}, {"/messages", "list", "MailPage"},
		{"/messages/{uid}", "message", "MailMessage"}, {"/raw/messages", "rawList", "MailPage"},
		{"/raw/messages/{uid}/view", "rawMessageView", "MailMessage"},
		{"/messages/{uid}/render", "render", "MMailRender"},
	} {
		d := managementOperation{Method: "GET", Path: p + e.suffix, ID: "m.mail." + e.id, Summary: "Read-only mailbox " + e.id, Response: e.response, Sensitive: true, Description: "Fresh operator authorization after sensitive-read admission; complete response lifetime participates in the read barrier. No API-key reveal, public credential, consume or Seen. Current source generation only; authorized same-generation archive remains readable."}
		if e.id == "list" || e.id == "rawList" {
			d.Query = []any{openParameter("limit", "query", openObject{"type": "integer", "minimum": 1, "maximum": 1000, "default": 20}, false), openParameter("before_time", "query", openRef("Instant"), false), openParameter("before_id", "query", openRef("Identifier"), false)}
			d.Description += " before_time/before_id must appear together; next_time/next_id follow exact visible_at/entry ordering. Raw candidates are not proof of available body bytes."
		}
		if e.id == "codes" {
			d.Query = []any{openParameter("limit", "query", openObject{"type": "integer", "minimum": 1, "maximum": 100, "default": 100}, false)}
		}
		operations = append(operations, d)
	}
	operations = append(operations, managementOperation{Method: "GET", Path: p + "/codes/latest/text", ID: "m.mail.latestCodeText", Summary: "Latest six ASCII digits or empty204", Sensitive: true, Responses: openObject{"200": openObject{"description": "Exactly six ASCII digit bytes, no LF; no-store/nosniff. GET never consumes or enqueues Seen.", "content": openObject{"text/plain": openObject{"schema": openObject{"type": "string", "pattern": "^[0-9]{6}$"}}}}, "204": openObject{"description": "No matching retained code; empty body."}}, Description: "Fresh operator mail_read scope. No query parameters, consume or Seen. Not the JSON envelope."})
	for _, e := range []struct{ suffix, id, media string }{{"/raw/latest", "rawLatest", "message/rfc822"}, {"/messages/{uid}/raw", "raw", "message/rfc822"}, {"/messages/{uid}/attachments/{part}", "attachment", "*/*"}} {
		response := openObject{"description": "Verified same-FD original MIME or decoded attachment bytes. Partial body/read failure aborts the download; no appended JSON.", "content": openObject{e.media: openObject{"schema": openObject{"type": "string", "format": "binary"}}}}
		d := managementOperation{Method: "GET", Path: p + e.suffix, ID: "m.mail." + e.id, Summary: "Read-only verified " + e.id, Sensitive: true, Responses: openObject{"200": response}, Description: "Fresh operator raw_read scope, no APIKey reveal or public token. Unavailable original is never fabricated as complete. Attachment disposition uses a sanitized filename."}
		if e.media == "message/rfc822" {
			d.Query = []any{openParameter("Range", "header", openString(), false)}
			d.Responses["206"] = response
			d.Responses["416"] = openObject{"description": "Invalid or unsatisfiable byte Range; may be an ordinary HTTP text error, not a JSON envelope."}
		}
		operations = append(operations, d)
	}
	return operations
}
