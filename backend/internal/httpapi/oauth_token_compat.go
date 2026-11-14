package httpapi

import (
	"errors"
	"mime"
	"net/http"
	"strings"

	"icloudspace/internal/addressauth"
)

// compatibleToken exchanges the three refresh form fields for an IMAPS token.
// Authority owns credential validation and token issuance.
func (a *OAuthToken) compatibleToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := requestMeta(w); !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "令牌接口仅接受 POST")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "请求必须使用表单编码")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, oauthFormLimit)
	if r.ParseForm() != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "请求表单无效")
		return
	}
	clients, refreshes, grants := r.PostForm["client_id"], r.PostForm["refresh_token"], r.PostForm["grant_type"]
	if len(clients) != 1 || len(refreshes) != 1 || len(grants) != 1 || grants[0] != "refresh_token" || len(r.PostForm) != 3 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client_id、refresh_token 和 grant_type 必须各出现一次")
		return
	}
	client, refresh := strings.TrimSpace(clients[0]), refreshes[0]
	if client == "" || refresh == "" || strings.TrimSpace(refresh) != refresh || strings.ContainsAny(client+refresh, " \t\r\n") {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "客户端凭证无效")
		return
	}
	issued, err := a.authority.Refresh(r.Context(), addressauth.RefreshRequest{
		ClientID: client, RefreshToken: refresh, Purposes: []addressauth.Purpose{addressauth.IMAPLogin},
	})
	if err != nil {
		if errors.Is(err, addressauth.ErrUnauthenticated) || errors.Is(err, addressauth.ErrInvalid) || errors.Is(err, addressauth.ErrUnavailable) {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "客户端凭证无效")
		} else {
			// A lost commit acknowledgement stays unknown in the Authority. This
			// adapter performs one issuance attempt and never retries it.
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "令牌服务暂不可用")
		}
		return
	}
	oauthJSON(w, http.StatusOK, struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}{issued.Token, "Bearer", 3600})
}
