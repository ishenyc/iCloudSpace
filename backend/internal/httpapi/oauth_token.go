package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"icloudspace/internal/addressauth"
)

const OAuthTokenPath = "/oauth/token"
const CompatibleOAuthTokenPath = "/oauth2/v2.0/token"
const oauthFormLimit = 16 << 10

// OAuthToken adapts only the existing two-factor refresh grant. It neither
// creates long-lived credentials nor treats a management session as authority.
type OAuthToken struct{ authority *addressauth.Authority }

func NewOAuthToken(authority *addressauth.Authority) (*OAuthToken, error) {
	if authority == nil {
		return nil, errors.New("httpapi: OAuth authority is required")
	}
	return &OAuthToken{authority: authority}, nil
}

func (a *OAuthToken) Register(mux *http.ServeMux) {
	mux.HandleFunc(OAuthTokenPath, a.token)
	mux.HandleFunc(CompatibleOAuthTokenPath, a.compatibleToken)
}

func oauthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func oauthError(w http.ResponseWriter, status int, code, description string) {
	oauthJSON(w, status, struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}{code, description})
}

func oauthPurpose(value string) (addressauth.Purpose, bool) {
	switch addressauth.Purpose(value) {
	case addressauth.MailRead, addressauth.MailConsume, addressauth.RawRead, addressauth.IMAPLogin:
		return addressauth.Purpose(value), true
	default:
		// Refresh cannot issue latest_read from a retained legacy key. Only
		// purposes actually supported by the canonical refresh owner belong here.
		return "", false
	}
}

func oauthSecret(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (a *OAuthToken) token(w http.ResponseWriter, r *http.Request) {
	invalid := func() { oauthError(w, 400, "invalid_request", "The token request is malformed.") }
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		oauthError(w, 405, "invalid_request", "The token endpoint requires POST.")
		return
	}
	// Do not merge query parameters or silently choose between authentication
	// mechanisms. Cookies and CSRF headers are irrelevant to this grant.
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Content-Type")) != 1 {
		invalid()
		return
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		invalid()
		return
	}
	for key, value := range params {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			invalid()
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, oauthFormLimit))
	if err != nil || !utf8.Valid(body) {
		invalid()
		return
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		invalid()
		return
	}
	for key, value := range values {
		if len(value) != 1 || (key != "grant_type" && key != "client_id" && key != "refresh_token" && key != "scope") {
			invalid()
			return
		}
	}
	if values.Get("grant_type") == "" || !oauthSecret(values.Get("client_id")) || !oauthSecret(values.Get("refresh_token")) {
		invalid()
		return
	}
	if values.Get("grant_type") != "refresh_token" {
		oauthError(w, 400, "unsupported_grant_type", "Only the refresh_token grant is supported.")
		return
	}
	var purposes []addressauth.Purpose
	if raw, present := values["scope"]; present {
		seen := make(map[addressauth.Purpose]bool)
		for _, item := range strings.Split(raw[0], " ") {
			purpose, ok := oauthPurpose(item)
			if !ok || seen[purpose] {
				oauthError(w, 400, "invalid_scope", "The requested scope is unsupported or malformed.")
				return
			}
			seen[purpose] = true
			purposes = append(purposes, purpose)
		}
	}
	issued, err := a.authority.Refresh(r.Context(), addressauth.RefreshRequest{
		ClientID: values.Get("client_id"), RefreshToken: values.Get("refresh_token"), Purposes: purposes,
	})
	if err != nil {
		switch {
		case errors.Is(err, addressauth.ErrUnauthenticated), errors.Is(err, addressauth.ErrInvalid):
			oauthError(w, 400, "invalid_grant", "The refresh grant is invalid or unavailable.")
		case errors.Is(err, addressauth.ErrReadOnly), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			oauthError(w, 503, "temporarily_unavailable", "Token issuance is temporarily unavailable.")
		case errors.Is(err, addressauth.ErrOutcomeUnknown):
			oauthError(w, 503, "server_error", "The token issuance outcome is unknown. Do not retry automatically.")
		default:
			oauthError(w, 500, "server_error", "Token issuance could not be completed.")
		}
		return
	}
	scopes := make([]string, len(issued.Purposes))
	for i, purpose := range issued.Purposes {
		scopes[i] = string(purpose)
	}
	// Refresh's canonical TTL is exactly one hour, measured by its own clock.
	// A wall-clock subtraction here would corrupt TTL under a fixed/test clock.
	oauthJSON(w, 200, struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}{issued.Token, "Bearer", 3600, strings.Join(scopes, " ")})
}
