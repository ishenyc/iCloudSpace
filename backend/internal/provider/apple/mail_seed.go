package apple

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// MailSendDraft submits the already stored MIME exactly once. This endpoint is
// authorized only by mailout's explicit seed stage, never a reference lookup.
// The gateway consumes WebMail session metadata alongside the stored GUID.
func (c *Client) MailSendDraft(ctx context.Context, rpcID, guid string) (MailReceipt, error) {
	receipt := MailReceipt{RPCID: rpcID, Outcome: "not_sent"}
	folder, _, ok := MailGUID(guid)
	if !ok || folder != "Drafts" || !field(rpcID, 256, true) {
		return receipt, invalid("mail_seed")
	}
	if err := c.lock(ctx); err != nil {
		return receipt, err
	}
	defer c.unlock()
	endpoint, err := c.mailEndpoint("/mailws2/v1/draft/send", true)
	if err != nil {
		return receipt, err
	}
	body, _ := json.Marshal(map[string]any{
		"messageGuid": strings.TrimPrefix(guid, "message:"),
		"sessionHeaders": map[string]any{
			"folder": nil, "modseq": nil, "threadmodseq": nil,
			"condstore": 1, "qresync": 1, "threadmode": 1,
		},
	})
	response, err := c.exchangeLocked(ctx, "mail_seed", http.MethodPost, endpoint, body, false, true)
	if err != nil {
		var provider *Error
		if errors.As(err, &provider) && provider.Unknown {
			receipt.Outcome = "unknown"
		}
		return receipt, err
	}
	if response.status >= 400 && response.status < 500 {
		receipt.Matched = true
		receipt.Outcome = "rejected"
		kind := AppleRejected
		if response.status == 401 || response.status == 403 || response.status == 421 || response.status == 450 {
			kind = AuthenticationRequired
		} else if response.status == 429 {
			kind = RateLimited
		}
		return receipt, &Error{Kind: kind, Operation: "mail_seed", Status: response.status}
	}
	var fields map[string]json.RawMessage
	if uniqueJSON(response.body) != nil || json.Unmarshal(response.body, &fields) != nil {
		receipt.Outcome = "unknown"
		return receipt, &Error{Kind: MalformedResponse, Operation: "mail_seed", Status:response.status,Code:"SEED_ENVELOPE",Unknown: true}
	}
	if failure, ok := fields["error"]; ok && len(failure) > 0 && string(failure) != "null" {
		var explicit struct {
			Code json.Number `json:"code"`
		}
		_, hasEvents := fields["events"]
		_, hasSession := fields["sessionHeaders"]
		if json.Unmarshal(failure, &explicit) != nil || explicit.Code == "" || hasEvents || hasSession {
			receipt.Outcome = "unknown"
			return receipt, &Error{Kind: MalformedResponse, Operation: "mail_seed", Status:response.status,Code:"SEED_ERROR_SHAPE",Unknown: true}
		}
		if _, err := explicit.Code.Int64(); err != nil {
			receipt.Outcome = "unknown"
			return receipt, &Error{Kind: MalformedResponse, Operation: "mail_seed", Status:response.status,Code:"SEED_ERROR_CODE",Unknown: true}
		}
		receipt.Matched = true
		receipt.Outcome = "rejected"
		return receipt, &Error{Kind: AppleRejected, Operation: "mail_seed", Status: response.status}
	}
	if err = diagnose("mail_seed", response, true); err != nil {
		receipt.Outcome = "unknown"
		if !isUnknown(err) {
			receipt.Outcome, receipt.Matched = "rejected", true
		}
		return receipt, err
	}
	var events []json.RawMessage
	var session map[string]json.RawMessage
	if json.Unmarshal(fields["events"], &events) != nil || events == nil || json.Unmarshal(fields["sessionHeaders"], &session) != nil || session == nil {
		receipt.Outcome = "unknown"
		return receipt, &Error{Kind: MalformedResponse, Operation: "mail_seed", Status:response.status,Code:"SEED_ACK_SHAPE",Unknown: true}
	}
	receipt.Matched = true
	receipt.Outcome = "accepted"
	return receipt, nil
}
