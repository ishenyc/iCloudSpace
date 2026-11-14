package httpapi

import (
	"net/http"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/mailview"
)

func (a *MailAccess) rawMessageView(w http.ResponseWriter, r *http.Request, lease *addressauth.Lease) {
	uid, err := mailUID(r.PathValue("uid"))
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		a.fail(w, r, mailview.ErrInvalid, "")
		return
	}
	message, err := a.mail.RawMessage(r.Context(), lease, uid)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), presentMailMessage(message))
}
