package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

const PublicViewerBase = "/viewer"

// PublicViewerUI accepts built assets only. Its constructor cannot receive or
// expose an installed management entry, a session, or an access credential.
type PublicViewerUI struct {
	root  *os.Root
	index []byte
	head  int
}

func NewPublicViewerUI(directory string) (*PublicViewerUI, error) {
	return openPublicAssets(directory, "viewer.html", PublicViewerBase)
}

func openPublicAssets(directory, filename, base string) (*PublicViewerUI, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrUI
	}
	failed := true
	defer func() {
		if failed {
			root.Close()
		}
	}()
	file, err := root.Open(filename)
	if err != nil {
		return nil, ErrUI
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, ErrUI
	}
	index, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(index) > 1<<20 {
		return nil, ErrUI
	}
	head := uiHeadInsertion(index)
	lower := bytes.ToLower(index)
	if head < 0 || bytes.Contains(lower, []byte("<base")) || bytes.Contains(lower, []byte("space-runtime")) || bytes.Contains(lower, []byte("space-public-viewer")) || !uiAssetsExist(root, index, base) {
		return nil, ErrUI
	}
	failed = false
	return &PublicViewerUI{root: root, index: index, head: head}, nil
}

func (ui *PublicViewerUI) Close() error {
	if ui == nil || ui.root == nil {
		return nil
	}
	return ui.root.Close()
}
func (ui *PublicViewerUI) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+PublicViewerBase+"/addresses/{address_id}", ui.page)
	mux.HandleFunc("GET "+PublicViewerBase+"/assets/{asset...}", ui.asset)
}
func viewerHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'none'")
}
func (ui *PublicViewerUI) page(w http.ResponseWriter, r *http.Request) {
	viewerHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	id, valid := positiveDecimal(r.PathValue("address_id"))
	if !valid || r.URL.RawQuery != "" || r.URL.ForceQuery {
		WriteProblem(w, 400, currentMeta(w), Problem{Kind: "invalid_request", Code: "VIEWER_INPUT_INVALID", Message: "Use an explicit mailbox viewer path and fragment authorization."})
		return
	}
	configuration, _ := json.Marshal(struct {
		Version        int    `json:"version"`
		AddressID      string `json:"address_id"`
		PublicMailPath string `json:"public_mail_path"`
	}{1, decimal(id), PublicMailBase})
	injection := []byte(`<base href="/viewer/"><script id="space-public-viewer" type="application/json">` + string(configuration) + `</script>`)
	bound := make([]byte, 0, len(ui.index)+len(injection))
	bound = append(bound, ui.index[:ui.head]...)
	bound = append(bound, injection...)
	bound = append(bound, ui.index[ui.head:]...)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "viewer.html", time.Time{}, bytes.NewReader(bound))
}
func (ui *PublicViewerUI) asset(w http.ResponseWriter, r *http.Request) {
	viewerHeaders(w)
	reference := "assets/" + r.PathValue("asset")
	if reference == "assets/" || path.Clean(reference) != reference || strings.Contains(reference, "\\") {
		http.NotFound(w, r)
		return
	}
	file, err := ui.root.Open(reference)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}
