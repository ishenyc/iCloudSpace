package apple

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
)

func mailReadID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(raw[:])
}
func mailFolder(folder string) bool {
	return field(folder, 1024, true) && !strings.ContainsAny(folder, "\\\x00\r\n") && !strings.Contains(folder, "..") && !strings.HasPrefix(folder, "/") && !strings.HasSuffix(folder, "/")
}
func MailGUID(raw string) (string, uint32, bool) {
	if !strings.HasPrefix(raw, "message:") {
		return "", 0, false
	}
	id := strings.TrimPrefix(raw, "message:")
	slash := strings.LastIndexByte(id, '/')
	if slash < 1 || !mailFolder(id[:slash]) {
		return "", 0, false
	}
	uid, err := strconv.ParseUint(id[slash+1:], 10, 32)
	if err != nil || uid == 0 || strconv.FormatUint(uid, 10) != id[slash+1:] {
		return "", 0, false
	}
	return id[:slash], uint32(uid), true
}
func (c *Client) mailEndpoint(path string, gateway bool) (string, error) {
	d := c.document
	origin := d.Services.Mail
	role := mailService
	if gateway {
		origin = d.Services.MailGateway
		role = gatewayService
	}
	if d.Principal.DSID == "" || d.Assurance.HSAChallengeRequired || !validServiceOrigin(origin, d.Principal.Region, role) {
		return "", &Error{Kind: AuthenticationRequired, Operation: "mail_session"}
	}
	u, err := url.Parse(origin + path)
	if err != nil {
		return "", invalid("mail_endpoint")
	}
	q := url.Values{"dsid": {d.Principal.DSID}, "clientId": {d.Browser.ClientID}, "clientBuildNumber": {MailWebBuild}, "clientMasteringNumber": {MailWebBuild}}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (c *Client) mailRPCLocked(ctx context.Context, method, id string, params any, mutation bool) (json.RawMessage, MailReceipt, error) {
	receipt := MailReceipt{RPCID: id, Outcome: "not_sent"}
	if !field(id, 256, true) {
		return nil, receipt, invalid("mail_rpc_id")
	}
	endpoint, err := c.mailEndpoint("/wm/message", false)
	if err != nil {
		return nil, receipt, err
	}
	body, err := json.Marshal(struct {
		Version string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{"2.0", id, method, params})
	if err != nil {
		return nil, receipt, invalid("mail_rpc")
	}
	response, err := c.exchangeLocked(ctx, "mail_"+method, http.MethodPost, endpoint, body, false, mutation)
	if err != nil {
		var kind *Error
		if mutation && errors.As(err, &kind) && kind.Unknown {
			receipt.Outcome = "unknown"
		}
		return nil, receipt, err
	}
	if response.status == http.StatusTooManyRequests {
		receipt.Matched, receipt.Outcome = true, "rejected"
		return nil, receipt, &Error{Kind: RateLimited, Operation: "mail_" + method, Status: response.status}
	}
	if response.status == 401 || response.status == 403 || response.status == 421 || response.status == 450 {
		receipt.Matched = true
		receipt.Outcome = "rejected"
		return nil, receipt, &Error{Kind: AuthenticationRequired, Operation: "mail_" + method, Status: response.status}
	}
	var fields map[string]json.RawMessage
	if uniqueJSON(response.body) != nil || json.Unmarshal(response.body, &fields) != nil {
		return nil, MailReceipt{RPCID: id, Outcome: "unknown"}, &Error{Kind: MalformedResponse, Operation: "mail_" + method, Status: response.status, Unknown: mutation}
	}
	var version, gotID string
	if code := responseCode(response.body); code != "" && code != "0" && response.status < 500 {
		receipt.Matched, receipt.Outcome = true, "rejected"
		return nil, receipt, &Error{Kind: AppleRejected, Operation: "mail_" + method, Status: response.status, Code: code}
	}
	if json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" || json.Unmarshal(fields["id"], &gotID) != nil || gotID != id {
		return nil, MailReceipt{RPCID: id, Outcome: "unknown"}, &Error{Kind: MalformedResponse, Operation: "mail_" + method, Status: response.status, Code: "RPC_ID", Unknown: mutation}
	}
	result, hasResult := fields["result"]
	failure, hasError := fields["error"]
	if hasResult == hasError {
		return nil, MailReceipt{RPCID: id, Outcome: "unknown"}, &Error{Kind: MalformedResponse, Operation: "mail_" + method, Status: response.status, Unknown: mutation}
	}
	if hasError {
		var e struct {
			Code json.Number `json:"code"`
		}
		if json.Unmarshal(failure, &e) != nil || e.Code == "" {
			return nil, MailReceipt{RPCID: id, Outcome: "unknown"}, &Error{Kind: MalformedResponse, Operation: "mail_" + method, Unknown: mutation}
		}
		if _, err := e.Code.Int64(); err != nil {
			return nil, MailReceipt{RPCID: id, Outcome: "unknown"}, &Error{Kind: MalformedResponse, Operation: "mail_" + method, Unknown: mutation}
		}
		receipt.Matched = true
		receipt.Outcome = "rejected"
		return nil, receipt, &Error{Kind: AppleRejected, Operation: "mail_" + method, Status: response.status, Code: safeCode(e.Code.String())}
	}
	if err = diagnose("mail_"+method, response, mutation); err != nil {
		receipt.Outcome = "unknown"
		if !isUnknown(err) {
			receipt.Outcome, receipt.Matched = "rejected", true
		}
		return nil, receipt, err
	}
	receipt.Matched = true
	receipt.Outcome = "accepted"
	return result, receipt, nil
}

func (c *Client) MailSearch(ctx context.Context, folder, needle string, limit int) ([]MailMessage, error) {
	if !mailFolder(folder) || !field(needle, 256, true) || limit < 1 || limit > 100 {
		return nil, invalid("mail_search")
	}
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	params := map[string]any{"guid": "folder:" + folder, "sorttype": "Date", "sortorder": "descending", "searchtype": "anyfield", "searchtext": needle, "requesttype": "index", "responsetype": "hybrid", "selected": 1, "count": limit, "rollbackslot": "0.0"}
	raw, _, err := c.mailRPCLocked(ctx, "list", mailReadID(), params, false)
	if err != nil {
		return nil, err
	}
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) < 1 || len(rows) > limit+1 {
		return nil, &Error{Kind: MalformedResponse, Operation: "mail_list"}
	}
	var status struct {
		Type  string          `json:"type"`
		Total json.RawMessage `json:"totalmessages"`
	}
	if json.Unmarshal(rows[0], &status) != nil || status.Type == "" || len(status.Total) == 0 {
		return nil, &Error{Kind: MalformedResponse, Operation: "mail_list"}
	}
	out := make([]MailMessage, 0, len(rows)-1)
	seen := map[string]bool{}
	for _, row := range rows[1:] {
		var m MailMessage
		if json.Unmarshal(row, &m) != nil {
			return nil, &Error{Kind: MalformedResponse, Operation: "mail_list"}
		}
		got, uid, ok := MailGUID(m.GUID)
		if !ok || got != folder || (m.Folder != folder && m.Folder != "folder:"+folder) || m.UID != strconv.FormatUint(uint64(uid), 10) || seen[m.GUID] {
			return nil, &Error{Kind: MalformedResponse, Operation: "mail_list"}
		}
		seen[m.GUID] = true
		out = append(out, m)
	}
	return out, nil
}
func (c *Client) MailGet(ctx context.Context, guid string) (MailMessage, error) {
	return c.MailGetParts(ctx, guid, nil)
}
func (c *Client) MailGetParts(ctx context.Context, guid string, parts []string) (MailMessage, error) {
	if _, _, ok := MailGUID(guid); !ok {
		return MailMessage{}, invalid("mail_get")
	}
	if len(parts) > 16 {
		return MailMessage{}, invalid("mail_get")
	}
	for _, part := range parts {
		if !field(part, 2048, true) {
			return MailMessage{}, invalid("mail_get")
		}
	}
	if err := c.lock(ctx); err != nil {
		return MailMessage{}, err
	}
	defer c.unlock()
	if parts == nil {
		parts = []string{}
	}
	raw, _, err := c.mailRPCLocked(ctx, "get", mailReadID(), map[string]any{"guid": guid, "parts": parts, "dontMarkAsRead": true}, false)
	if err != nil {
		return MailMessage{}, err
	}
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) == 0 {
		return MailMessage{}, &Error{Kind: MalformedResponse, Operation: "mail_get"}
	}
	var message MailMessage
	found := false
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		var record struct {
			Type  string `json:"recordType"`
			GUID  string `json:"guid"`
			Email string `json:"email"`
		}
		if json.Unmarshal(row, &record) != nil || !field(record.GUID, 2048, true) || seen[record.GUID] {
			return MailMessage{}, &Error{Kind: MalformedResponse, Operation: "mail_get"}
		}
		seen[record.GUID] = true
		switch record.Type {
		case "CoreMail.EmailAddress":
			address, err := mail.ParseAddress(record.Email)
			_, _, messageGUID := MailGUID(record.GUID)
			if err != nil || address.Address != record.Email || messageGUID {
				return MailMessage{}, &Error{Kind: MalformedResponse, Operation: "mail_get"}
			}
			continue
		case "CoreMail.MessageDetail":
		case "", "message":
			// Retain the existing standalone detail response as well as hybrid.
			if len(rows) != 1 {
				return MailMessage{}, &Error{Kind: MalformedResponse, Operation: "mail_get"}
			}
		default:
			return MailMessage{}, &Error{Kind: MalformedResponse, Operation: "mail_get"}
		}
		if found || record.GUID != guid || json.Unmarshal(row, &message) != nil || len(message.LongHeader) > 64<<10 {
			return MailMessage{}, &Error{Kind: MalformedResponse, Operation: "mail_get"}
		}
		found = true
	}
	if !found {
		return MailMessage{}, &Error{Kind: MalformedResponse, Operation: "mail_get"}
	}
	return message, nil
}
func (c *Client) MailUIDValidity(ctx context.Context, folder string) (uint32, error) {
	if !mailFolder(folder) {
		return 0, invalid("mail_mailbox")
	}
	if err := c.lock(ctx); err != nil {
		return 0, err
	}
	defer c.unlock()
	endpoint, err := c.mailEndpoint("/mailws2/v1/geqs/query", true)
	if err != nil {
		return 0, err
	}
	u, _ := url.Parse(endpoint)
	q := u.Query()
	q.Set("clientIntent", "fetchMailboxQuery")
	u.RawQuery = q.Encode()
	body, _ := json.Marshal(map[string]any{"domain": "mailbox", "predicate": map[string]any{"type": "eq", "expression": map[string]string{"type": "property", "property": "isMboxDeleted"}, "value": false, "and": []any{map[string]any{"type": "in", "expression": map[string]string{"property": "name"}, "value": []string{folder}}}}, "properties": []string{"identifier", "name", "uidValidity"}})
	response, err := c.exchangeLocked(ctx, "mail_mailbox", http.MethodPost, u.String(), body, false, false)
	if err != nil {
		return 0, err
	}
	if err = diagnose("mail_mailbox", response, false); err != nil {
		return 0, err
	}
	var result struct {
		Objects []struct {
			ID       string `json:"identifier"`
			Name     string `json:"name"`
			Validity uint32 `json:"uidValidity"`
		} `json:"domainObjects"`
	}
	if uniqueJSON(response.body) != nil || json.Unmarshal(response.body, &result) != nil || len(result.Objects) != 1 || result.Objects[0].ID == "" || result.Objects[0].Name != folder || result.Objects[0].Validity == 0 {
		return 0, &Error{Kind: MalformedResponse, Operation: "mail_mailbox"}
	}
	return result.Objects[0].Validity, nil
}
func validMailSend(p MailSend) bool {
	from, err := mail.ParseAddress(p.From)
	if err != nil || from.Address == "" {
		return false
	}
	to, err := mail.ParseAddressList(p.To)
	if err != nil || len(to) != 1 || !field(p.Subject, 2048, false) || len(p.Text)+len(p.HTML) > 768<<10 || len(p.Attachments) > 10 {
		return false
	}
	if p.MessageGUID != "" {
		if _, _, ok := MailGUID(p.MessageGUID); !ok {
			return false
		}
	}
	if p.DraftGUID != "" {
		if _, _, ok := MailGUID(p.DraftGUID); !ok {
			return false
		}
	}
	if p.Mode != "" && p.Mode != "reply" && p.Mode != "replyAll" && p.Mode != "forward" {
		return false
	}
	return true
}
func (c *Client) MailSubmit(ctx context.Context, id string, params MailSend) (MailReceipt, error) {
	if !validMailSend(params) {
		return MailReceipt{RPCID: id, Outcome: "not_sent"}, invalid("mail_send")
	}
	if err := c.lock(ctx); err != nil {
		return MailReceipt{RPCID: id, Outcome: "not_sent"}, err
	}
	defer c.unlock()
	raw, receipt, err := c.mailRPCLocked(ctx, "send", id, params, true)
	if receipt.Matched && receipt.Outcome == "accepted" {
		var guid string
		if json.Unmarshal(raw, &guid) != nil {
			var object map[string]json.RawMessage
			if json.Unmarshal(raw, &object) == nil {
				for _, key := range []string{"sentMessageGUID", "messageGuid", "messageGUID", "guid"} {
					if json.Unmarshal(object[key], &guid) == nil && guid != "" {
						break
					}
				}
			}
		}
		if field(guid, 512, false) {
			receipt.UpstreamID = guid
		}
	}
	return receipt, err
}
func (c *Client) MailSaveDraft(ctx context.Context, id string, params MailSend) (MailMessage, MailReceipt, error) {
	if !validMailSend(params) {
		return MailMessage{}, MailReceipt{RPCID: id, Outcome: "not_sent"}, invalid("mail_savedraft")
	}
	if err := c.lock(ctx); err != nil {
		return MailMessage{}, MailReceipt{RPCID: id, Outcome: "not_sent"}, err
	}
	defer c.unlock()
	raw, receipt, err := c.mailRPCLocked(ctx, "saveDraft", id, params, true)
	if err != nil {
		return MailMessage{}, receipt, err
	}
	var d MailMessage
	if json.Unmarshal(raw, &d) != nil {
		receipt.Matched = false
		receipt.Outcome = "unknown"
		return d, receipt, &Error{Kind: MalformedResponse, Operation: "mail_savedraft", Unknown: true}
	}
	folder, uid, ok := MailGUID(d.GUID)
	if !ok || folder != "Drafts" || d.UID != strconv.FormatUint(uint64(uid), 10) {
		receipt.Matched = false
		receipt.Outcome = "unknown"
		return d, receipt, &Error{Kind: MalformedResponse, Operation: "mail_savedraft", Unknown: true}
	}
	d.Folder = folder
	return d, receipt, nil
}
