package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/content"
	"icloudspace/internal/mailview"
)

func (a *MailAccess) registerPublicCompatibility(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/otp", a.compatibilityOTP)
	mux.HandleFunc("GET /api/v1/mail/latest", a.compatibilityLatest)
	mux.HandleFunc("GET /api/v1/mail/recent", a.compatibilityRecent)
	mux.HandleFunc("GET /api/v1/mail/recent/{$}", a.compatibilityRecent)
}

func compatibilityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
func compatibilityJSON(w http.ResponseWriter, status int, value any) {
	compatibilityHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func compatibilityProblem(w http.ResponseWriter, status int, code, message string) {
	compatibilityJSON(w, status, struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}{Error: struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}{code, message, currentMeta(w).RequestID}})
}
func compatibilityMailError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, addressauth.ErrUnauthenticated), errors.Is(err, mailview.ErrDenied):
		compatibilityProblem(w, 401, "INVALID_API_KEY", "API Key 无效")
	case errors.Is(err, mailview.ErrSyncUnavailable):
		compatibilityProblem(w, 503, "SYNC_UNAVAILABLE", "邮箱同步暂不可用")
	case errors.Is(err, mailview.ErrNotFound), errors.Is(err, mailview.ErrStale), errors.Is(err, mailview.ErrConsumed):
		compatibilityProblem(w, 404, "MAIL_NOT_FOUND", "最近一小时内没有邮件")
	default:
		compatibilityProblem(w, 503, "DATABASE_UNAVAILABLE", "数据库暂不可用")
	}
}

func compatibilityBearer(r *http.Request, trim bool) (string, bool) {
	raw := r.Header.Get("Authorization")
	if trim {
		raw = strings.TrimSpace(raw)
	}
	scheme, key, ok := strings.Cut(raw, " ")
	return key, ok && strings.EqualFold(scheme, "Bearer") && key != "" && !strings.ContainsAny(key, " \r\n\x00")
}
func (a *MailAccess) compatibilityKey(r *http.Request, purpose addressauth.Purpose) (*addressauth.Lease, error) {
	key, ok := compatibilityBearer(r, false)
	if !ok {
		return nil, addressauth.ErrUnauthenticated
	}
	lease, err := a.authority.Authenticate(r.Context(), addressauth.Credential{Kind: addressauth.APIKey, Raw: key}, purpose, addressauth.Selector{})
	if purpose == addressauth.MailRead && errors.Is(err, addressauth.ErrUnauthenticated) {
		return a.authority.Authenticate(r.Context(), addressauth.Credential{Kind: addressauth.APIKey, Raw: key}, addressauth.LatestRead, addressauth.Selector{})
	}
	return lease, err
}

type compatibilityOTPOptions struct {
	latest, explicitLatest, codeOnly, raw bool
	rawFormat                             string
}

func compatibilityOTPQuery(r *http.Request) (url.Values, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, addressauth.ErrUnauthenticated
	}
	for name, items := range values {
		if name == "raw_format" {
			continue // Format validation is a parameter error, not an auth error.
		}
		if len(items) != 1 || (name != "token" && name != "latest_only" && name != "otp_only" && name != "raw_mail") {
			return nil, addressauth.ErrUnauthenticated
		}
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" && values.Has("token") {
		return nil, addressauth.ErrUnauthenticated
	}
	return values, nil
}
func compatibilityOTPFlags(values url.Values, defaultLatest bool) (compatibilityOTPOptions, string) {
	out := compatibilityOTPOptions{latest: defaultLatest, rawFormat: "iframe"}
	for _, field := range []string{"latest_only", "otp_only", "raw_mail"} {
		if !values.Has(field) {
			continue
		}
		value, err := strconv.ParseBool(strings.TrimSpace(values.Get(field)))
		if err != nil {
			return out, field + " 必须是布尔值"
		}
		switch field {
		case "latest_only":
			out.latest = value
			out.explicitLatest = value
		case "otp_only":
			out.codeOnly = value
		case "raw_mail":
			out.raw = value
		}
	}
	if out.raw && out.codeOnly {
		return out, "raw_mail=true 与 otp_only=true 不能同时使用"
	}
	if out.codeOnly && !out.explicitLatest {
		return out, "otp_only=true 仅可与 latest_only=true 同时使用"
	}
	if formats, present := values["raw_format"]; present {
		if !out.raw || len(formats) != 1 || (formats[0] != "iframe" && formats[0] != "html") {
			return out, "raw_format 仅在 raw_mail=true 时使用，且必须是单个 iframe 或 html"
		}
		out.rawFormat = formats[0]
	}
	return out, ""
}
func (a *MailAccess) compatibilityOTPLease(r *http.Request, values url.Values, purpose addressauth.Purpose) (*addressauth.Lease, error) {
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		key, ok := compatibilityBearer(r, true)
		if !ok {
			return nil, addressauth.ErrUnauthenticated
		}
		return a.authority.Authenticate(r.Context(), addressauth.Credential{Kind: addressauth.APIKey, Raw: key}, purpose, addressauth.Selector{})
	}
	if !values.Has("token") {
		return nil, addressauth.ErrUnauthenticated
	}
	return a.authority.AuthenticatePublicLink(r.Context(), values.Get("token"), purpose)
}
func (a *MailAccess) compatibilityOTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := requestMeta(w); !ok {
		return
	}
	compatibilityHeaders(w)
	values, err := compatibilityOTPQuery(r)
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	lease, err := a.compatibilityOTPLease(r, values, addressauth.MailRead)
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	defer func() {
		if lease != nil {
			lease.Close()
		}
	}()
	settings, err := a.mail.PublicSettings(r.Context())
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	options, invalid := compatibilityOTPFlags(values, settings.LatestOnly)
	if invalid != "" {
		compatibilityProblem(w, 400, "VALIDATION_FAILED", invalid)
		return
	}
	if options.raw {
		lease.Close()
		lease, err = a.compatibilityOTPLease(r, values, addressauth.RawRead)
		if err != nil {
			compatibilityMailError(w, err)
			return
		}
		a.compatibilityRaw(w, r, lease, options.explicitLatest, options.rawFormat, settings)
		return
	}
	items, err := a.mail.PublicCodes(r.Context(), lease, 100)
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	location, _ := time.LoadLocation(settings.Timezone)
	type code struct {
		OTP  string `json:"otp"`
		Time string `json:"time"`
	}
	out := make([]code, 0, len(items))
	for _, item := range items {
		out = append(out, code{item.Code, time.Unix(0, item.ReceivedAt).In(location).Format(time.RFC3339)})
	}
	if options.latest && len(out) > 0 {
		if options.codeOnly {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(200)
			io.WriteString(w, out[0].OTP)
			return
		}
		compatibilityJSON(w, 200, out[0])
		return
	}
	compatibilityJSON(w, 200, out)
}

func (a *MailAccess) compatibilityLatest(w http.ResponseWriter, r *http.Request) {
	if _, ok := requestMeta(w); !ok {
		return
	}
	compatibilityHeaders(w)
	lease, err := a.compatibilityKey(r, addressauth.MailRead)
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	defer lease.Close()
	settings, err := a.mail.PublicSettings(r.Context())
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	_, err = a.mail.PublicFreshness(r.Context(), lease, settings)
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	snapshot, err := a.mail.PublicLatest(r.Context(), lease)
	if errors.Is(err, mailview.ErrNotFound) {
		compatibilityProblem(w, 404, "MAIL_NOT_FOUND", "尚未收到邮件")
		return
	}
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	compatibilityJSON(w, 200, map[string]any{"data": map[string]any{"alias": lease.Identity().Email, "message": compatibilityMessage(snapshot.Message), "synced_at": time.Unix(0, snapshot.Ref.SelectedAt).UTC().Format(time.RFC3339), "stale": false}})
}
func compatibilityMessage(message mailview.Message) map[string]any {
	m := message.Metadata
	type mailbox struct {
		Name  string `json:"name,omitempty"`
		Email string `json:"email"`
	}
	addresses := func(items []mailview.Mailbox) []mailbox {
		out := make([]mailbox, 0, len(items))
		for _, item := range items {
			out = append(out, mailbox{item.Name, item.Address})
		}
		return out
	}
	type attachment struct {
		Filename    string `json:"filename"`
		ContentType string `json:"content_type"`
		Size        int64  `json:"size"`
	}
	attachments := make([]attachment, 0, len(message.Attachments))
	for _, item := range message.Attachments {
		attachments = append(attachments, attachment{item.Filename, item.MediaType, item.ByteSize})
	}
	var sent any
	if m.SentAt != nil && *m.SentAt != 0 {
		sent = time.Unix(0, *m.SentAt).UTC().Format(time.RFC3339)
	}
	return map[string]any{"id": fmt.Sprintf("%d-%d", m.Remote.UIDValidity, m.Remote.UID), "message_id": m.RFCMessageID, "received_at": time.Unix(0, m.ReceivedAt).UTC().Format(time.RFC3339), "sent_at": sent, "from": addresses(m.From), "to": addresses(m.To), "cc": addresses(m.CC), "subject": m.Subject, "text": message.Text, "html": message.HTML, "attachments": attachments, "has_attachments": len(attachments) > 0, "body_truncated": m.DeclaredBodyTruncated || !message.BodyComplete}
}
func (a *MailAccess) compatibilityRecent(w http.ResponseWriter, r *http.Request) {
	if _, ok := requestMeta(w); !ok {
		return
	}
	// ServeMux's GET pattern also matches HEAD. A metadata probe must never
	// perform the published consuming GET operation.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		compatibilityProblem(w, 405, "METHOD_NOT_ALLOWED", "仅支持 GET")
		return
	}
	compatibilityHeaders(w)
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values["api_key"]) != 1 {
		compatibilityMailError(w, addressauth.ErrUnauthenticated)
		return
	}
	key := values.Get("api_key")
	lease, err := a.authority.AuthenticatePublicLink(r.Context(), key, addressauth.RecentConsume)
	if errors.Is(err, addressauth.ErrUnauthenticated) {
		lease, err = a.authority.AuthenticateRecent(r.Context(), key)
	}
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	defer lease.Close()
	settings, err := a.mail.PublicSettings(r.Context())
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	_, err = a.mail.PublicFreshness(r.Context(), lease, settings)
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	snapshot, err := a.mail.Recent(r.Context(), lease)
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	// The envelope's request ID is generated once per inbound request. It is
	// retained as the claim key on unknown COMMIT and never automatically replayed.
	claimKey := currentMeta(w).RequestID
	if claimKey == "" {
		compatibilityProblem(w, 503, "DATABASE_UNAVAILABLE", "请求编号暂不可用")
		return
	}
	_, err = a.mail.Consume(r.Context(), lease, mailview.ClaimRequest{Key: claimKey, Snapshot: snapshot.Ref})
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	message := snapshot.Message
	snippet := message.Text
	if strings.TrimSpace(snippet) == "" {
		snippet, _ = content.TextFromHTML(message.HTML, mailview.DefaultLimits().BodyBytes)
	}
	snippet = strings.Join(strings.Fields(snippet), " ")
	sent := message.Metadata.ReceivedAt
	if message.Metadata.SentAt != nil && *message.Metadata.SentAt != 0 {
		sent = *message.Metadata.SentAt
	}
	location, _ := time.LoadLocation(settings.Timezone)
	compatibilityJSON(w, 200, map[string]any{"data": map[string]string{"address": lease.Identity().Email, "subject": message.Metadata.Subject, "snippet": snippet, "sent_at": time.Unix(0, sent).In(location).Format(time.RFC3339)}})
}

func (a *MailAccess) compatibilityRaw(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease, latest bool, format string, settings mailview.PublicSettings) {
	page := mailview.Page{Limit: 32}
	items, err := a.mail.PublicRawCandidates(r.Context(), lease, page)
	if err != nil {
		compatibilityMailError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Trailer", "X-iCloudSpace-Stream-Status")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	io.WriteString(w, `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>邮件原文</title><style>body{font:14px system-ui;margin:24px auto;padding:0 16px;max-width:960px;color:#171717;background:#fafafa}article{background:white;border:1px solid #ddd;border-radius:10px;margin:16px 0;padding:20px}h2{font-size:18px;overflow-wrap:anywhere}iframe{width:100%;min-height:420px;border:0}small{color:#666}</style><body><h1>邮件原文</h1>`)
	count := 0
	location, _ := time.LoadLocation(settings.Timezone)
	for {
		for _, item := range items.Items {
			message, err := a.mail.RawMessage(r.Context(), lease, item.UID)
			if errors.Is(err, mailview.ErrUnavailable) || errors.Is(err, mailview.ErrNotFound) {
				continue
			}
			if err != nil {
				w.Header().Set("X-iCloudSpace-Stream-Status", "interrupted")
				io.WriteString(w, `<p role="alert">邮件读取已中断，请稍后重新打开。</p>`)
				io.WriteString(w, `</body></html>`)
				return
			}
			subject := strings.TrimSpace(message.Metadata.Subject)
			if subject == "" {
				subject = "（无主题）"
			}
			fmt.Fprintf(w, `<article><h2>%s</h2>`, html.EscapeString(subject))
			for _, field := range []struct {
				label string
				items []mailview.Mailbox
			}{{"发件人", message.Metadata.From}, {"收件人", message.Metadata.To}} {
				if len(field.items) == 0 {
					continue
				}
				values := make([]string, 0, len(field.items))
				for _, mailbox := range field.items {
					value := mailbox.Address
					if mailbox.Name != "" {
						value = mailbox.Name + " <" + value + ">"
					}
					values = append(values, value)
				}
				fmt.Fprintf(w, `<div><small>%s：%s</small></div>`, field.label, html.EscapeString(strings.Join(values, ", ")))
			}
			fmt.Fprintf(w, `<small>接收时间：%s</small>`, html.EscapeString(time.Unix(0, message.Metadata.ReceivedAt).In(location).Format(time.RFC3339)))
			if format == "html" {
				// RawMessage renders through the shared content sanitizer, including
				// escaped plain-text fallback. Never interpolate stored HTML here.
				fmt.Fprintf(w, `<div class="mail-body">%s</div>`, message.HTML)
			} else {
				fmt.Fprintf(w, `<iframe sandbox="" referrerpolicy="no-referrer" title="邮件正文" srcdoc="%s"></iframe>`, html.EscapeString(message.HTML))
			}
			if !message.BodyComplete || message.Metadata.DeclaredBodyTruncated {
				io.WriteString(w, `<p>邮件正文已按服务端大小限制截断。</p>`)
			}
			io.WriteString(w, `</article>`)
			count++
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			if latest {
				io.WriteString(w, `</body></html>`)
				w.Header().Set("X-iCloudSpace-Stream-Status", "complete")
				return
			}
		}
		if !items.More {
			break
		}
		page.BeforeTime, page.BeforeID = items.NextTime, items.NextID
		items, err = a.mail.PublicRawCandidates(r.Context(), lease, page)
		if err != nil {
			w.Header().Set("X-iCloudSpace-Stream-Status", "interrupted")
			io.WriteString(w, `<p role="alert">邮件读取已中断，请稍后重新打开。</p></body></html>`)
			return
		}
	}
	if count == 0 {
		io.WriteString(w, `<p>暂无可读邮件</p>`)
	}
	io.WriteString(w, `</body></html>`)
	w.Header().Set("X-iCloudSpace-Stream-Status", "complete")
}
