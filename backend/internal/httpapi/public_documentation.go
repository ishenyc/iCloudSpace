package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// Documentation uses only build assets and the static protocol specification.
// It never receives sessions, credentials, installation settings or accounts.
type PublicDocumentation struct {
	specification []byte
	page          []byte
	ui            *PublicViewerUI
}

func NewPublicDocumentation(directory string) (*PublicDocumentation, error) {
	raw, err := json.Marshal(publicOpenAPI())
	if err != nil {
		return nil, err
	}
	ui, err := openPublicAssets(directory, "docs.html", "/docs")
	if err != nil {
		return nil, err
	}
	page := make([]byte, 0, len(ui.index)+32)
	page = append(page, ui.index[:ui.head]...)
	page = append(page, []byte(`<base href="/docs/">`)...)
	page = append(page, ui.index[ui.head:]...)
	return &PublicDocumentation{specification: raw, page: page, ui: ui}, nil
}

func (d *PublicDocumentation) Close() error {
	if d == nil {
		return nil
	}
	return d.ui.Close()
}

func (d *PublicDocumentation) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		if !documentationRequest(w, r) {
			return
		}
		http.Redirect(w, r, "/docs/", http.StatusPermanentRedirect)
	})
	mux.HandleFunc("GET /docs/{$}", func(w http.ResponseWriter, r *http.Request) {
		if !documentationRequest(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "docs.html", time.Time{}, bytes.NewReader(d.page))
	})
	mux.HandleFunc("GET /docs/assets/{asset...}", d.ui.asset)
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		if !documentationRequest(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		http.ServeContent(w, r, "openapi.json", time.Time{}, bytes.NewReader(d.specification))
	})
}

func documentationRequest(w http.ResponseWriter, r *http.Request) bool {
	viewerHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "Documentation does not accept query parameters.", http.StatusBadRequest)
		return false
	}
	return true
}
