package httpapi

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/adminauth"
	"icloudspace/internal/mailview"
)

const PublicMailBase = "/api/mail/v1"

type MailAccess struct {
	authority *addressauth.Authority
	mail      *mailview.Service
}
type mailOperation func(http.ResponseWriter, *http.Request, *addressauth.Lease)

func NewMailAccess(authority *addressauth.Authority, reader *mailview.Service) (*MailAccess, error) {
	if authority == nil || reader == nil {
		return nil, errors.New("httpapi: mailbox authority and reader are required")
	}
	return &MailAccess{authority, reader}, nil
}

func (a *MailAccess) routes() []struct {
	method, path string
	purpose      addressauth.Purpose
	operation    mailOperation
} {
	return []struct {
		method, path string
		purpose      addressauth.Purpose
		operation    mailOperation
	}{
		{"GET", "/latest", addressauth.LatestRead, a.latest},
		{"GET", "/recent", addressauth.LatestRead, a.recent},
		{"GET", "/codes", addressauth.MailRead, a.codes},
		{"GET", "/codes/latest/text", addressauth.MailRead, a.latestCodeText},
		{"GET", "/messages", addressauth.MailRead, a.list},
		{"GET", "/messages/{uid}", addressauth.MailRead, a.message},
		{"GET", "/raw/messages", addressauth.RawRead, a.rawList},
		{"GET", "/raw/messages/{uid}/view", addressauth.RawRead, a.rawMessageView},
		{"GET", "/raw/latest", addressauth.RawRead, a.rawLatest},
		{"GET", "/messages/{uid}/raw", addressauth.RawRead, a.raw},
		{"GET", "/messages/{uid}/attachments/{part}", addressauth.RawRead, a.attachment},
		{"GET", "/messages/{uid}/render", addressauth.RawRead, a.render},
	}
}
func (a *MailAccess) RegisterPublic(mux *http.ServeMux) {
	a.registerPublicCompatibility(mux)
	for _, route := range a.routes() {
		mux.HandleFunc(route.method+" "+PublicMailBase+"/addresses/{address_id}"+route.path, a.public(route.purpose, route.operation))
	}
	mux.HandleFunc("POST "+PublicMailBase+"/addresses/{address_id}/consume", a.public(addressauth.MailConsume, a.consume))
	mux.HandleFunc("POST "+PublicMailBase+"/addresses/{address_id}/claims/query", a.public(addressauth.MailConsume, a.queryClaim))
	mux.HandleFunc("POST "+PublicMailBase+"/addresses/{address_id}/access/derive", a.derive)
	mux.HandleFunc("POST "+PublicMailBase+"/addresses/{address_id}/access/refresh", a.refresh)
}

// Management reads use their own fresh operator authorization. They do not
// reveal an API key or infer public authority from an encrypted bundle.
func (a *MailAccess) RegisterManagement(mux *http.ServeMux, identity *ManagementAuth) error {
	if identity == nil {
		return errors.New("httpapi: management identity is required")
	}
	for _, route := range a.routes() {
		mux.Handle(route.method+" "+identity.basePath+"/addresses/{address_id}/mail"+route.path, identity.RequireSensitiveRead(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := mailAddressID(w, r)
			if !ok {
				return
			}
			purpose := route.purpose
			if purpose == addressauth.LatestRead {
				purpose = addressauth.MailRead
			}
			lease, err := a.authority.BeginOperatorRead(r.Context(), id, purpose, func(ctx context.Context) error {
				_, err := identity.identity.Authenticate(ctx, cookieValue(r, sessionCookie))
				return err
			})
			if err != nil {
				if errors.Is(err, adminauth.ErrUnauthenticated) {
					identity.writeAuthError(w, currentMeta(w), err)
					return
				}
				a.fail(w, r, err, "")
				return
			}
			defer lease.Close()
			route.operation(w, r, lease)
		})))
	}
	return nil
}

func mailAddressID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, ok := positiveDecimal(r.PathValue("address_id"))
	if !ok {
		WriteProblem(w, 400, currentMeta(w), Problem{Kind: "invalid_request", Code: "MAIL_INPUT_INVALID", Message: "A canonical mailbox identifier is required."})
	}
	return id, ok
}

// Ambient browser cookies never authorize a public mailbox API. APIKey names
// a long-lived key; Bearer names a purpose-bound opaque access grant.
func mailboxCredential(r *http.Request) (addressauth.Credential, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return addressauth.Credential{}, addressauth.ErrUnauthenticated
	}
	scheme, raw, ok := strings.Cut(values[0], " ")
	if !ok || raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return addressauth.Credential{}, addressauth.ErrUnauthenticated
	}
	var kind addressauth.Kind
	switch {
	case strings.EqualFold(scheme, "APIKey"):
		kind = addressauth.APIKey
	case strings.EqualFold(scheme, "Bearer"):
		kind = addressauth.Access
	default:
		return addressauth.Credential{}, addressauth.ErrUnauthenticated
	}
	return addressauth.Credential{Kind: kind, Raw: raw}, nil
}

func (a *MailAccess) public(purpose addressauth.Purpose, next mailOperation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requestMeta(w); !ok {
			return
		}
		id, ok := mailAddressID(w, r)
		if !ok {
			return
		}
		credential, err := mailboxCredential(r)
		if err != nil {
			a.fail(w, r, err, "")
			return
		}
		selected := purpose
		if purpose == addressauth.LatestRead {
			selected = addressauth.MailRead
		}
		lease, err := a.authority.Authenticate(r.Context(), credential, selected, addressauth.Selector{AddressID: id})
		if purpose == addressauth.LatestRead && errors.Is(err, addressauth.ErrUnauthenticated) {
			lease, err = a.authority.Authenticate(r.Context(), credential, addressauth.LatestRead, addressauth.Selector{AddressID: id})
		}
		if err != nil {
			a.fail(w, r, err, "")
			return
		}
		defer lease.Close()
		next(w, r, lease)
	}
}
func (a *MailAccess) fail(w http.ResponseWriter, r *http.Request, err error, key string) {
	status, problem := mailErrorProblem(err, key)
	switch {
	case errors.Is(err, addressauth.ErrUnauthenticated):
		status, problem = 401, Problem{Kind: "authentication", Code: "MAIL_CREDENTIALS_INVALID", Message: "The mailbox credential does not authorize this operation."}
	case errors.Is(err, addressauth.ErrInvalid):
		status, problem = 400, Problem{Kind: "invalid_request", Code: "MAIL_INPUT_INVALID", Message: "Check the mailbox authorization request."}
	case errors.Is(err, addressauth.ErrUnavailable):
		status, problem = 404, Problem{Kind: "not_found", Code: "MAIL_NOT_FOUND", Message: "The mailbox resource is unavailable."}
	case errors.Is(err, addressauth.ErrReadOnly):
		status, problem = 503, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is currently read-only.", Outcome: NotSent}
	case errors.Is(err, addressauth.ErrOutcomeUnknown):
		status, problem = 503, Problem{Kind: "persistence", Code: "MAIL_AUTHORIZATION_UNKNOWN", Message: "The authorization change could not be confirmed.", Outcome: Unknown}
	}
	WriteProblem(w, status, currentMeta(w), problem)
}
func (a *MailAccess) latest(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	item, err := a.mail.Latest(r.Context(), lease)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), presentMailSnapshot(item))
}
func (a *MailAccess) recent(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	item, err := a.mail.Recent(r.Context(), lease)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), presentMailSnapshot(item))
}
func (a *MailAccess) codes(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	limit := 100
	for name, values := range r.URL.Query() {
		if name != "limit" || len(values) != 1 {
			a.fail(w, r, mailview.ErrInvalid, "")
			return
		}
		value, err := strconv.ParseUint(values[0], 10, 16)
		if err != nil || value < 1 || value > 100 {
			a.fail(w, r, mailview.ErrInvalid, "")
			return
		}
		limit = int(value)
	}
	items, err := a.mail.Codes(r.Context(), lease, limit)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	type codeView struct {
		Code       string `json:"code"`
		EntryID    string `json:"entry_id"`
		UID        uint32 `json:"uid"`
		ReceivedAt string `json:"received_at"`
	}
	views := make([]codeView, len(items))
	for i, item := range items {
		views[i] = codeView{item.Code, decimal(item.EntryID), item.UID, instant(item.ReceivedAt)}
	}
	WriteResult(w, 200, currentMeta(w), views)
}

// This representation is a read, with exactly the same mail_read authority as
// the code collection. An empty mailbox is 204; a code is six ASCII bytes.
func (a *MailAccess) latestCodeText(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	if r.URL.RawQuery != "" {
		a.fail(w, r, mailview.ErrInvalid, "")
		return
	}
	items, err := a.mail.Codes(r.Context(), lease, 1)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if meta := currentMeta(w); meta.RequestID != "" {
		w.Header().Set("X-Request-ID", meta.RequestID)
	}
	if len(items) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "6")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, items[0].Code)
}

func (a *MailAccess) message(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	uid, err := mailUID(r.PathValue("uid"))
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	message, err := a.mail.Message(r.Context(), lease, uid)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), presentMailMessage(message))
}
func parseMailPage(r *http.Request) (mailview.Page, error) {
	page := mailview.Page{Limit: 20}
	for name, values := range r.URL.Query() {
		if len(values) != 1 {
			return page, mailview.ErrInvalid
		}
		switch name {
		case "limit":
			value, err := strconv.ParseUint(values[0], 10, 16)
			if err != nil || value < 1 || value > 1000 {
				return page, mailview.ErrInvalid
			}
			page.Limit = int(value)
		case "before_time":
			value, err := exactInstant(values[0])
			if err != nil {
				return page, err
			}
			page.BeforeTime = &value
		case "before_id":
			value, ok := positiveDecimal(values[0])
			if !ok {
				return page, mailview.ErrInvalid
			}
			page.BeforeID = value
		default:
			return page, mailview.ErrInvalid
		}
	}
	if (page.BeforeTime == nil) != (page.BeforeID == 0) {
		return page, mailview.ErrInvalid
	}
	return page, nil
}
func writeMailPage(w http.ResponseWriter, r *http.Request, page mailview.MessagePage) {
	items := make([]mailMetadataView, len(page.Items))
	for i, item := range page.Items {
		items[i] = presentMailMetadata(item)
	}
	var nextID *string
	if page.More {
		nextID = optionalDecimal(&page.NextID)
	}
	WriteResult(w, 200, currentMeta(w), struct {
		Items    []mailMetadataView `json:"items"`
		More     bool               `json:"more"`
		NextTime *string            `json:"next_time"`
		NextID   *string            `json:"next_id"`
	}{items, page.More, optionalInstant(page.NextTime), nextID})
}
func (a *MailAccess) list(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	page, err := parseMailPage(r)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	items, err := a.mail.List(r.Context(), lease, page)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	writeMailPage(w, r, items)
}
func (a *MailAccess) rawList(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	page, err := parseMailPage(r)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	items, err := a.mail.RawCandidates(r.Context(), lease, page)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	writeMailPage(w, r, items)
}
func (a *MailAccess) raw(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	uid, err := mailUID(r.PathValue("uid"))
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	file, err := a.mail.OpenRaw(r.Context(), lease, uid)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	defer file.Close()
	serveMailOriginal(w, r, file)
}
func (a *MailAccess) rawLatest(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	_, file, err := a.mail.LatestRaw(r.Context(), lease)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	defer file.Close()
	serveMailOriginal(w, r, file)
}
func serveMailOriginal(w http.ResponseWriter, r *http.Request, file *mailview.Raw) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", `attachment; filename="message.eml"`)
	http.ServeContent(w, r, "message.eml", time.Time{}, file.Reader)
}
func (a *MailAccess) attachment(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	uid, err := mailUID(r.PathValue("uid"))
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	file, err := a.mail.Attachment(r.Context(), lease, uid, r.PathValue("part"))
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	defer file.Close()
	filename := strings.Map(func(c rune) rune {
		if c < ' ' || c == 127 {
			return '_'
		}
		return c
	}, file.Filename)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", file.MediaType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Header().Set("Content-Length", strconv.FormatInt(file.ByteSize, 10))
	if _, err := io.Copy(w, file.Reader); err != nil {
		panic(http.ErrAbortHandler)
	}
}
func (a *MailAccess) render(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	uid, err := mailUID(r.PathValue("uid"))
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	html, err := a.mail.RenderRaw(r.Context(), lease, uid)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), struct {
		HTML string `json:"html"`
	}{html})
}
func (a *MailAccess) consume(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	a.claim(w, r, lease, false)
}
func (a *MailAccess) queryClaim(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	a.claim(w, r, lease, true)
}
func (a *MailAccess) claim(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease, query bool) {
	var input mailClaimInput
	if problem := DecodeJSON(w, r, &input, 16<<10); problem != nil {
		WriteProblem(w, 400, currentMeta(w), *problem)
		return
	}
	request, err := input.request()
	if err != nil {
		a.fail(w, r, err, input.Key)
		return
	}
	var result mailview.ClaimResult
	if query {
		result, err = a.mail.QueryClaim(r.Context(), lease, request)
	} else {
		result, err = a.mail.Consume(r.Context(), lease, request)
	}
	if err != nil {
		a.fail(w, r, err, input.Key)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentClaim(result))
}
func writeAccess(w http.ResponseWriter, r *http.Request, value addressauth.IssuedAccess) {
	purposes := append([]addressauth.Purpose{}, value.Purposes...)
	WriteResult(w, 201, currentMeta(w), struct {
		Token     string                `json:"access_token"`
		Type      string                `json:"token_type"`
		ExpiresAt string                `json:"expires_at"`
		AddressID string                `json:"address_id"`
		Purposes  []addressauth.Purpose `json:"purposes"`
	}{value.Token, "Bearer", instant(value.ExpiresAt), decimal(value.Identity.AddressID), purposes})
}
func (a *MailAccess) derive(w http.ResponseWriter, r *http.Request) {
	if _, ok := requestMeta(w); !ok {
		return
	}
	id, ok := mailAddressID(w, r)
	if !ok {
		return
	}
	credential, err := mailboxCredential(r)
	if err != nil || credential.Kind != addressauth.APIKey {
		a.fail(w, r, addressauth.ErrUnauthenticated, "")
		return
	}
	var input struct {
		Purpose         addressauth.Purpose `json:"purpose"`
		LifetimeSeconds int                 `json:"lifetime_seconds"`
	}
	if problem := DecodeJSON(w, r, &input, 4096); problem != nil {
		WriteProblem(w, 400, currentMeta(w), *problem)
		return
	}
	if input.LifetimeSeconds < 1 || input.LifetimeSeconds > 3600 {
		a.fail(w, r, addressauth.ErrInvalid, "")
		return
	}
	result, err := a.authority.DeriveAccess(r.Context(), credential.Raw, input.Purpose, addressauth.Selector{AddressID: id}, time.Duration(input.LifetimeSeconds)*time.Second)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	writeAccess(w, r, result)
}
func (a *MailAccess) refresh(w http.ResponseWriter, r *http.Request) {
	if _, ok := requestMeta(w); !ok {
		return
	}
	id, ok := mailAddressID(w, r)
	if !ok {
		return
	}
	var input struct {
		ClientID     string                `json:"client_id"`
		RefreshToken string                `json:"refresh_token"`
		Purposes     []addressauth.Purpose `json:"purposes"`
	}
	if problem := DecodeJSON(w, r, &input, 16<<10); problem != nil {
		WriteProblem(w, 400, currentMeta(w), *problem)
		return
	}
	result, err := a.authority.Refresh(r.Context(), addressauth.RefreshRequest{ClientID: input.ClientID, RefreshToken: input.RefreshToken, Purposes: input.Purposes, Selector: addressauth.Selector{AddressID: id}})
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	writeAccess(w, r, result)
}
