package apple

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"icloudspace/internal/addresses"
)

// HMEMailRoute is a provider observation. It never authorizes a different HME.
type HMEMailRoute struct {
	Alias     string `json:"hme"`
	Forward   string `json:"forwardToEmail"`
	Recipient string `json:"recipientMailId"`
	Relay     string `json:"replyToAddress"`
	Active    *bool  `json:"isActive"`
}

func (c *Client) MailDirectory(ctx context.Context) (addresses.Directory, []HMEMailRoute, error) {
	if err := c.lock(ctx); err != nil {
		return addresses.Directory{}, nil, err
	}
	defer c.unlock()
	response, err := c.hmeLocked(ctx, "mail_directory", http.MethodGet, "/v2/hme/list", nil, false)
	if err != nil {
		return addresses.Directory{}, nil, err
	}
	raw, err := decodeHME("mail_directory", response, false)
	if err != nil {
		return addresses.Directory{}, nil, err
	}
	directory, err := parseDirectory(raw, response.body, c.document.Principal.DSID)
	if err != nil {
		return addresses.Directory{}, nil, err
	}
	var rows struct {
		Emails []HMEMailRoute `json:"hmeEmails"`
	}
	if json.Unmarshal(raw, &rows) != nil {
		return addresses.Directory{}, nil, invalid("mail_directory")
	}
	return directory, rows.Emails, nil
}

// MailResolveRoute performs one fetchOrRegister POST. It is a mutation, never a
// query/retry operation. The caller durably owns its exact relay before entry.
func (c *Client) MailResolveRoute(ctx context.Context, relay string) (HMEMailRoute, MailReceipt, error) {
	receipt := MailReceipt{Outcome: "not_sent", Matched: true}
	if !field(relay, 2048, true) || strings.ContainsAny(relay, "\r\n") {
		return HMEMailRoute{}, receipt, invalid("mail_route")
	}
	if err := c.lock(ctx); err != nil {
		return HMEMailRoute{}, receipt, err
	}
	defer c.unlock()
	response, err := c.hmeLocked(ctx, "mail_route", http.MethodPost, "/v1/hme/mail/fetchOrRegister", map[string]string{"recipientEmailId": relay}, true)
	if err != nil {
		if e, ok := err.(*Error); ok && e.Unknown {
			receipt.Outcome = "unknown"
			receipt.Matched = false
		}
		return HMEMailRoute{}, receipt, err
	}
	if response.status == 401 || response.status == 403 || response.status == 421 || response.status == 450 || response.status == 429 {
		kind := AuthenticationRequired
		if response.status == 429 {
			kind = RateLimited
		}
		return HMEMailRoute{}, MailReceipt{Outcome: "rejected", Matched: true}, &Error{Kind: kind, Operation: "mail_route", Status: response.status}
	}
	raw, err := decodeHME("mail_route", response, true)
	if err != nil {
		receipt.Outcome = "unknown"
		if response.status >= 400 && response.status < 500 || !isUnknown(err) {
			receipt.Outcome = "rejected"
			receipt.Matched = true
		}
		return HMEMailRoute{}, receipt, err
	}
	var value struct {
		HME *HMEMailRoute `json:"hme"`
	}
	if json.Unmarshal(raw, &value) != nil || value.HME == nil {
		return HMEMailRoute{}, MailReceipt{Outcome: "unknown"}, &Error{Kind: MalformedResponse, Operation: "mail_route", Unknown: true}
	}
	receipt.Outcome, receipt.Matched = "accepted", true
	return *value.HME, receipt, nil
}

func isUnknown(err error) bool { e, ok := err.(*Error); return ok && e.Unknown }
