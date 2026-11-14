package httpapi

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"icloudspace/internal/addresses"
	"icloudspace/internal/externalregistration"
)

const compatibleRegistrationLimit = 4 << 10

type compatibleRegistrationProblem struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type compatibleRegistrationData struct {
	Alias             string `json:"alias"`
	ICloud            string `json:"icloud"`
	APIKey            string `json:"api_key"`
	MailAPIDirectLink string `json:"mail_api_direct_link"`
}

func compatibleRegistrationJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func compatibleRegistrationError(w http.ResponseWriter, status int, code, message string) {
	compatibleRegistrationJSON(w, status, struct {
		Error compatibleRegistrationProblem `json:"error"`
	}{compatibleRegistrationProblem{code, message, currentMeta(w).RequestID}})
}

func compatibleRegistrationForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	remaining := int64(compatibleRegistrationLimit - len(r.URL.RawQuery))
	if remaining < 0 || r.ContentLength > remaining {
		compatibleRegistrationError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "请求参数不能超过 4 KiB")
		return nil, false
	}
	if r.Body != nil && r.Body != http.NoBody && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || !strings.EqualFold(media, "application/x-www-form-urlencoded") {
			compatibleRegistrationError(w, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "请求正文必须使用 application/x-www-form-urlencoded")
			return nil, false
		}
		r.Body = http.MaxBytesReader(w, r.Body, remaining)
	}
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			compatibleRegistrationError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "请求参数不能超过 4 KiB")
		} else {
			compatibleRegistrationError(w, http.StatusBadRequest, "INVALID_REQUEST", "URL 编码参数格式错误")
		}
		return nil, false
	}
	return r.Form, true
}

func (a *ExternalRegistration) compatibleRegister(w http.ResponseWriter, r *http.Request) {
	meta, ok := requestMeta(w)
	if !ok {
		return
	}
	// Authenticate before reading a body, preserving the public deployment
	// credential realm independently of mailbox OAuth and management sessions.
	values := r.Header.Values("Authorization")
	var access externalregistration.Access
	authenticated := false
	if len(values) == 1 {
		scheme, token, valid := strings.Cut(values[0], " ")
		if valid && strings.EqualFold(scheme, "Bearer") && token != "" && !strings.ContainsAny(token, " \t\r\n") {
			var err error
			access, err = a.owner.Authenticate(token)
			authenticated = err == nil
		}
	}
	if !authenticated {
		w.Header().Set("WWW-Authenticate", "Bearer")
		compatibleRegistrationError(w, http.StatusUnauthorized, "INVALID_OAUTH_TOKEN", "OAuth 令牌无效")
		return
	}
	fields, ok := compatibleRegistrationForm(w, r)
	if !ok {
		return
	}
	addressesField, accountsField := fields["add_hide_my_eamil"], fields["icloud"]
	if len(fields) != 2 || len(addressesField) != 1 || len(accountsField) != 1 || strings.TrimSpace(addressesField[0]) == "" || strings.TrimSpace(accountsField[0]) == "" {
		compatibleRegistrationError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求参数必须且只能包含一次 add_hide_my_eamil 和 icloud")
		return
	}
	address, addressErr := addresses.NormalizeAddress(strings.ToLower(strings.TrimSpace(addressesField[0])))
	email, emailErr := addresses.NormalizeAddress(strings.ToLower(strings.TrimSpace(accountsField[0])))
	if addressErr != nil || emailErr != nil {
		compatibleRegistrationError(w, http.StatusBadRequest, "INVALID_REQUEST", "邮箱地址格式不正确")
		return
	}
	delivery, err := a.owner.RegisterByEmail(r.Context(), access, address, email, meta.RequestID)
	if delivery != nil {
		defer delivery.Close()
	}
	if err != nil {
		switch {
		case errors.Is(err, externalregistration.ErrIdentityConflict):
			compatibleRegistrationError(w, 400, "INVALID_REQUEST", "隐私邮箱不能与已登记主号邮箱或所选主号的 IMAP 用户名相同")
		case errors.Is(err, externalregistration.ErrAddressExists), errors.Is(err, externalregistration.ErrConflict), errors.Is(err, addresses.ErrConflict):
			compatibleRegistrationError(w, 409, "ALIAS_EXISTS", "这个隐私邮箱已经登记")
		case errors.Is(err, externalregistration.ErrNotFound), errors.Is(err, addresses.ErrNotFound):
			compatibleRegistrationError(w, 404, "ACCOUNT_NOT_FOUND", "主号邮箱不存在")
		case errors.Is(err, addresses.ErrCapacity):
			compatibleRegistrationError(w, 409, "ALIAS_LIMIT_REACHED", "此主号最多启用 750 个隐私邮箱")
		case errors.Is(err, externalregistration.ErrInvalid), errors.Is(err, addresses.ErrInvalid):
			compatibleRegistrationError(w, 400, "INVALID_REQUEST", "邮箱地址格式不正确")
		default:
			// The retained request ID is the operation key. An uncertain commit
			// remains queryable through the owner; this handler never reissues it.
			compatibleRegistrationError(w, 503, "DATABASE_UNAVAILABLE", "数据库暂不可用")
		}
		return
	}
	token, err := a.owner.RecentToken(access, delivery)
	if err != nil || delivery.Bundle == nil {
		compatibleRegistrationError(w, 500, "INTERNAL_ERROR", "请求处理失败，请稍后重试")
		return
	}
	compatibleRegistrationJSON(w, http.StatusCreated, struct {
		Data compatibleRegistrationData `json:"data"`
	}{compatibleRegistrationData{delivery.Receipt.Address, email, delivery.Bundle.API.Key, "/api/v1/mail/recent?api_key=" + url.QueryEscape(token)}})
}
