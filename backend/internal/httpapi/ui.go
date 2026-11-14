package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	nethtml "golang.org/x/net/html"
)

var ErrUI = errors.New("httpapi: management assets or installed entry are invalid")

const ManagementUIPath = "/admin"

type ManagementUI struct {
	root     *os.Root
	entry    string
	index    []byte
	previous string
}

// NewManagementUI binds one built frontend to its installed entry. Neither API
// discovery nor cookies are inferred from the current browser pathname.
func NewManagementUI(directory, entry string) (*ManagementUI, error) {
	return NewManagementUIWithPrevious(directory, entry, "")
}

// NewManagementUIWithPrevious accepts one explicit navigation-only transition.
// It does not mount old APIs or authenticate an old session cookie.
func NewManagementUIWithPrevious(directory, entry, previous string) (*ManagementUI, error) {
	return NewManagementUIWithRecovery(directory, entry, previous, previous)
}

// NewManagementUIWithRecovery keeps one explicit old storage scope available
// after its navigation routes have been retired. No old API is mounted and no
// browser operation is replayed by publishing this recovery identity.
func NewManagementUIWithRecovery(directory, entry, previous, recovery string) (*ManagementUI, error) {
	if recovery == "" {
		recovery = previous
	}
	if !validUIEntry(entry) {
		return nil, ErrUI
	}
	for _, old := range []string{previous, recovery} {
		if old != "" && (!validUIEntry(old) || old == entry || strings.HasPrefix(old, entry+"/") || strings.HasPrefix(entry, old+"/")) {
			return nil, ErrUI
		}
	}
	if previous != "" && previous != recovery {
		return nil, ErrUI
	}
	return openManagementUI(directory, entry, previous, recovery)
}

func validUIEntry(entry string) bool {
	if entry == "" || entry == "/" || entry[0] != '/' || strings.HasSuffix(entry, "/") || strings.ContainsAny(entry, "?#%{}\\\x00\r\n\t ") || strings.Contains(entry, "//") {
		return false
	}
	for _, part := range strings.Split(entry, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	if entry == "/api" || strings.HasPrefix(entry, "/api/") || entry == "/healthz" || entry == "/docs" || entry == "/openapi.json" || entry == "/oauth" || strings.HasPrefix(entry, "/oauth/") || entry == PublicViewerBase || strings.HasPrefix(entry, PublicViewerBase+"/") {
		return false
	}
	return true
}

func openManagementUI(directory, entry, previous, recovery string) (*ManagementUI, error) {
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
	file, err := root.Open("index.html")
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
	lower := bytes.ToLower(index)
	head := uiHeadInsertion(index)
	if head < 0 || bytes.Contains(lower, []byte("<base")) || bytes.Contains(lower, []byte(`id="space-runtime"`)) {
		return nil, ErrUI
	}
	if !uiAssetsExist(root, index, entry) {
		return nil, ErrUI
	}
	bootstrap, _ := json.Marshal(struct {
		Version             int    `json:"version"`
		UIPath              string `json:"ui_path"`
		ControlPath         string `json:"control_path"`
		PublicMailPath      string `json:"public_mail_path"`
		PreviousControlPath string `json:"previous_control_path,omitempty"`
	}{1, entry, entry + "/api/control/v1", PublicMailBase, previousControlPath(recovery)})
	injection := []byte(`<base href="` + html.EscapeString(entry+"/") + `"><script id="space-runtime" type="application/json">` + string(bootstrap) + `</script>`)
	bound := make([]byte, 0, len(index)+len(injection))
	bound = append(bound, index[:head]...)
	bound = append(bound, injection...)
	bound = append(bound, index[head:]...)
	failed = false
	return &ManagementUI{root: root, entry: entry, index: bound, previous: previous}, nil
}

func previousControlPath(previous string) string {
	if previous == "" {
		return ""
	}
	return previous + "/api/control/v1"
}

// Base and runtime data must precede every relative script/link request. A
// tokenizer locates the real start tag without matching a comment or script.
func uiHeadInsertion(index []byte) int {
	tokenizer := nethtml.NewTokenizer(bytes.NewReader(index))
	offset := 0
	for {
		kind := tokenizer.Next()
		offset += len(tokenizer.Raw())
		if kind == nethtml.ErrorToken {
			return -1
		}
		if kind == nethtml.StartTagToken {
			name, _ := tokenizer.TagName()
			if bytes.EqualFold(name, []byte("head")) {
				return offset
			}
		}
	}
}

func uiAssetsExist(root *os.Root, index []byte, entry string) bool {
	document, err := nethtml.Parse(bytes.NewReader(index))
	if err != nil {
		return false
	}
	scripts := 0
	var visit func(*nethtml.Node) bool
	visit = func(node *nethtml.Node) bool {
		if node.Type == nethtml.ElementNode && (node.Data == "script" || node.Data == "link") {
			for _, attribute := range node.Attr {
				if node.Data == "script" && attribute.Key != "src" || node.Data == "link" && attribute.Key != "href" {
					continue
				}
				if node.Data == "script" {
					scripts++
				}
				u, err := url.Parse(attribute.Val)
				if err != nil || u.IsAbs() || u.Host != "" {
					return false
				}
				reference := strings.TrimPrefix(u.Path, "./")
				if strings.HasPrefix(reference, "/") {
					if !strings.HasPrefix(reference, entry+"/") {
						return false
					}
					reference = strings.TrimPrefix(reference, entry+"/")
				}
				if reference == "" || path.Clean(reference) != reference || strings.Contains(reference, "\\") {
					return false
				}
				file, err := root.Open(reference)
				if err != nil {
					return false
				}
				info, err := file.Stat()
				file.Close()
				if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
					return false
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if !visit(child) {
				return false
			}
		}
		return true
	}
	return visit(document) && scripts > 0
}
func (ui *ManagementUI) Close() error {
	if ui == nil || ui.root == nil {
		return nil
	}
	return ui.root.Close()
}
func (ui *ManagementUI) Register(mux *http.ServeMux) {
	mux.Handle(ui.entry, ui)
	mux.Handle(ui.entry+"/", ui)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, ui.entry, http.StatusTemporaryRedirect)
	})
	if ui.previous != "" {
		mux.HandleFunc(ui.previous, ui.previousNavigation)
		mux.HandleFunc(ui.previous+"/", ui.previousNavigation)
	}
}

func (ui *ManagementUI) previousNavigation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	relative := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, ui.previous), "/")
	if relative == "api" || strings.HasPrefix(relative, "api/") {
		WriteProblem(w, http.StatusNotFound, currentMeta(w), Problem{Kind: "not_found", Code: "ENDPOINT_NOT_FOUND", Message: "The endpoint does not exist."})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := ui.entry + strings.TrimPrefix(r.URL.EscapedPath(), ui.previous)
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	if r.URL.ForceQuery && r.URL.RawQuery == "" {
		target += "?"
	}
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}
func (ui *ManagementUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != ui.entry && !strings.HasPrefix(r.URL.Path, ui.entry+"/") {
		http.NotFound(w, r)
		return
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, ui.entry), "/")
	if relative == "api" || strings.HasPrefix(relative, "api/") {
		WriteProblem(w, 404, currentMeta(w), Problem{Kind: "not_found", Code: "ENDPOINT_NOT_FOUND", Message: "The endpoint does not exist."})
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", 405)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
	if relative != "" && relative != "index.html" {
		if strings.Contains(relative, "\\") || path.Clean(relative) != relative || strings.HasPrefix(relative, "/") {
			http.NotFound(w, r)
			return
		}
		file, err := ui.root.Open(relative)
		if err == nil {
			defer file.Close()
			info, e := file.Stat()
			if e == nil && info.Mode().IsRegular() {
				w.Header().Set("Cache-Control", "no-cache")
				if strings.HasPrefix(relative, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.ServeContent(w, r, info.Name(), info.ModTime(), file)
				return
			}
		}
		if relative == "assets" || strings.HasPrefix(relative, "assets/") || path.Ext(relative) != "" {
			http.NotFound(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(ui.index))
}
