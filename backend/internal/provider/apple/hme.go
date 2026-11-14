package apple

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"icloudspace/internal/addresses"
)

// HME wire shapes were independently checked against the public pyicloud
// service and minagishl/icloud-hide-my-email protocol observations. These URLs
// document wire facts, not implementation ancestry or live acceptance:
// https://github.com/timlaing/pyicloud/blob/main/pyicloud/services/hidemyemail.py
// https://github.com/minagishl/icloud-hide-my-email/blob/main/src/icloud/client.ts
// A complete directory requires more evidence than either public client checks.
var _ addresses.Provider = (*Client)(nil)

type hmeEnvelope struct {
	Success *bool           `json:"success"`
	Result  json.RawMessage `json:"result"`
	Error   struct {
		Code jsonCode `json:"errorCode"`
	} `json:"error"`
}
type hmeRow struct {
	ID      *string `json:"anonymousId"`
	Address *string `json:"hme"`
	Forward *string `json:"forwardToEmail"`
	Active  *bool   `json:"isActive"`
	Label   string  `json:"label"`
}

func hmeError(operation string, response exchangeResult, mutation bool, kind ErrorKind, code string) error {
	return &Error{Kind: kind, Operation: operation, Status: response.status, Code: safeCode(code), Unknown: mutation, RetryAfter: retryAfter(response.header.Get("Retry-After"), time.Now())}
}
func decodeHME(operation string, response exchangeResult, mutation bool) (json.RawMessage, error) {
	var envelope hmeEnvelope
	if response.status == 401 || response.status == 403 || response.status == 421 {
		return nil, hmeError(operation, response, mutation, AuthenticationRequired, "")
	}
	if response.status == 429 {
		return nil, hmeError(operation, response, mutation, RateLimited, "")
	}
	if len(response.body) == 0 || uniqueJSON(response.body) != nil || json.Unmarshal(response.body, &envelope) != nil || envelope.Success == nil {
		return nil, hmeError(operation, response, mutation, MalformedResponse, "")
	}
	if !*envelope.Success {
		return nil, hmeError(operation, response, false, AppleRejected, errorCode(envelope.Error.Code))
	}
	if response.status < 200 || response.status > 299 {
		return nil, hmeError(operation, response, mutation, AppleRejected, errorCode(envelope.Error.Code))
	}
	return envelope.Result, nil
}
func (c *Client) hmeLocked(ctx context.Context, operation, method, path string, payload any, mutation bool) (exchangeResult, error) {
	s := c.document
	if !field(s.Principal.DSID, 128, true) || !validServiceOrigin(s.Services.PremiumMail, s.Principal.Region, premiumService) || s.Assurance.HSAChallengeRequired {
		return exchangeResult{}, &Error{Kind: AuthenticationRequired, Operation: operation}
	}
	u, err := url.Parse(s.Services.PremiumMail + path)
	if err != nil {
		return exchangeResult{}, invalid(operation)
	}
	query := url.Values{"dsid": {s.Principal.DSID}, "clientId": {s.Browser.ClientID}}
	u.RawQuery = query.Encode()
	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return exchangeResult{}, invalid(operation)
		}
	}
	return c.exchangeLocked(ctx, operation, method, u.String(), body, false, mutation)
}

// rejectPartial traverses all metadata, including nested arrays. Unknown
// pagination markers are not silently ignored, and declared totals must equal
// the observed complete list. Provider errors inside metadata invalidate it.
func rejectPartial(value any, count int, subject string) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, x := range v {
			n := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
			switch n {
			case "pagination", "hasmore", "moreavailable", "next", "nextcursor", "nexttoken", "pagetoken", "continuation", "continuationtoken", "cursor":
				if x != nil && x != "" && x != false {
					return false
				}
			case "total", "totalcount", "totalrecords", "totalresults":
				number, ok := x.(json.Number)
				if !ok {
					return false
				}
				integer, err := number.Int64()
				if err != nil || integer != int64(count) {
					return false
				}
			case "partial", "incomplete":
				if x != false && x != nil {
					return false
				}
			case "dsid", "ownerid", "ownerdsid":
				if x != subject {
					return false
				}
			case "error", "errors", "serviceerrors":
				if x != nil {
					if object, ok := x.(map[string]any); !ok || len(object) != 0 {
						return false
					}
				}
			}
			if !rejectPartial(x, count, subject) {
				return false
			}
		}
	case []any:
		for _, x := range v {
			if !rejectPartial(x, count, subject) {
				return false
			}
		}
	}
	return true
}
func parseDirectory(body json.RawMessage, whole []byte, subject string) (addresses.Directory, error) {
	var result struct {
		Emails   *[]json.RawMessage `json:"hmeEmails"`
		Selected json.RawMessage    `json:"selectedForwardTo"`
		Forward  *[]string          `json:"forwardToEmails"`
	}
	if len(body) == 0 || json.Unmarshal(body, &result) != nil || result.Emails == nil || result.Forward == nil {
		return addresses.Directory{}, addresses.ErrDirectory
	}
	selected := ""
	if len(result.Selected) != 0 && (string(result.Selected) == "null" || json.Unmarshal(result.Selected, &selected) != nil) {
		return addresses.Directory{}, addresses.ErrDirectory
	}
	decoder := json.NewDecoder(bytes.NewReader(whole))
	decoder.UseNumber()
	var tree any
	if decoder.Decode(&tree) != nil || !rejectPartial(tree, len(*result.Emails), subject) {
		return addresses.Directory{}, addresses.ErrDirectory
	}
	out := addresses.Directory{Subject: subject, Complete: true, SelectedForward: selected, ForwardAddresses: *result.Forward, Entries: make([]addresses.RemoteAddress, 0, len(*result.Emails))}
	for _, raw := range *result.Emails {
		var row hmeRow
		if json.Unmarshal(raw, &row) != nil || row.ID == nil || row.Address == nil || row.Forward == nil || row.Active == nil {
			return addresses.Directory{}, addresses.ErrDirectory
		}
		out.Entries = append(out.Entries, addresses.RemoteAddress{ID: *row.ID, Address: *row.Address, Forward: *row.Forward, Active: *row.Active, Label: row.Label})
	}
	if len(out.ForwardAddresses) == 0 {
		return addresses.Directory{}, addresses.ErrDirectory
	}
	return addresses.ValidateDirectory(out, subject, out.ForwardAddresses[0])
}
func (c *Client) Directory(ctx context.Context) (addresses.Directory, error) {
	const operation = "hme_directory"
	if err := c.lock(ctx); err != nil {
		return addresses.Directory{}, err
	}
	defer c.unlock()
	response, err := c.hmeLocked(ctx, operation, http.MethodGet, "/v2/hme/list", nil, false)
	if err != nil {
		return addresses.Directory{}, err
	}
	result, err := decodeHME(operation, response, false)
	if err != nil {
		return addresses.Directory{}, err
	}
	directory, err := parseDirectory(result, response.body, c.document.Principal.DSID)
	if err != nil {
		return addresses.Directory{}, hmeError(operation, response, false, MalformedResponse, "")
	}
	return directory, nil
}
func (c *Client) Generate(ctx context.Context) (addresses.Candidate, error) {
	const operation = "hme_generate"
	if err := c.lock(ctx); err != nil {
		return addresses.Candidate{}, err
	}
	defer c.unlock()
	response, err := c.hmeLocked(ctx, operation, http.MethodPost, "/v1/hme/generate", struct{}{}, true)
	if err != nil {
		return addresses.Candidate{}, err
	}
	result, err := decodeHME(operation, response, true)
	if err != nil {
		return addresses.Candidate{}, err
	}
	var data struct {
		Address string `json:"hme"`
	}
	if json.Unmarshal(result, &data) != nil {
		return addresses.Candidate{}, hmeError(operation, response, true, MalformedResponse, "")
	}
	address, err := addresses.NormalizeAddress(data.Address)
	if err != nil {
		return addresses.Candidate{}, hmeError(operation, response, true, MalformedResponse, "")
	}
	return addresses.Candidate{Address: address}, nil
}
func (c *Client) Reserve(ctx context.Context, candidate addresses.Candidate, label, nonce string) error {
	const operation = "hme_reserve"
	address, err := addresses.NormalizeAddress(candidate.Address)
	if err != nil || !field(label, 512, false) || !field(nonce, 128, true) {
		return invalid(operation)
	}
	if err = c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	response, err := c.hmeLocked(ctx, operation, http.MethodPost, "/v1/hme/reserve", struct {
		Address string `json:"hme"`
		Label   string `json:"label"`
		Note    string `json:"note"`
	}{address, label, nonce}, true)
	if err != nil {
		return err
	}
	result, err := decodeHME(operation, response, true)
	if err != nil {
		return err
	}
	var data struct {
		HME struct {
			Address string `json:"hme"`
		} `json:"hme"`
	}
	if json.Unmarshal(result, &data) != nil || data.HME.Address != address {
		return hmeError(operation, response, true, MalformedResponse, "")
	}
	return nil
}
func (c *Client) hmeIDMutation(ctx context.Context, id, path, operation string) error {
	if !field(id, 512, true) {
		return invalid(operation)
	}
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	response, err := c.hmeLocked(ctx, operation, http.MethodPost, path, struct {
		ID string `json:"anonymousId"`
	}{id}, true)
	if err != nil {
		return err
	}
	_, err = decodeHME(operation, response, true)
	return err
}
func (c *Client) Deactivate(ctx context.Context, id string) error {
	return c.hmeIDMutation(ctx, id, "/v1/hme/deactivate", "hme_deactivate")
}
func (c *Client) Delete(ctx context.Context, id string) error {
	return c.hmeIDMutation(ctx, id, "/v1/hme/delete", "hme_delete")
}
