package mailout

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	nethtml "golang.org/x/net/html"
	"icloudspace/internal/content"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const FingerprintVersion = "mailout-prepared/v2"

type prepared struct {
	mail        *content.Prepared
	fingerprint [32]byte
	version     string
}

func prepare(r Request) (*prepared, error) {
	return prepareVersion(r, FingerprintVersion)
}
func prepareVersion(r Request, version string) (*prepared, error) {
	if version != FingerprintVersion && version != "mailout-prepared/v1" {
		return nil, ErrConflict
	}
	p, e := content.Prepare(r.Draft)
	if e != nil {
		return nil, ErrInvalid
	}
	if version == FingerprintVersion {
		p.Subject = strings.TrimSpace(p.Subject)
		if p.Subject == "" || strings.TrimSpace(p.Body.Text) == "" && len(p.Attachments) == 0 {
			return nil, ErrInvalid
		}
	}
	type file struct {
		Filename, MediaType, CID string
		Inline                   bool
		Size                     int
		SHA256                   [32]byte
	}
	files := make([]file, 0, len(p.Attachments))
	for _, a := range p.Attachments {
		files = append(files, file{a.Filename, a.MediaType, a.ContentID, a.Inline, len(a.Bytes), sha256.Sum256(a.Bytes)})
	}
	encoded, e := json.Marshal(struct {
		Version   string
		AddressID int64
		To        content.Mailbox
		Subject   string
		Input     content.Body
		Body      content.RenderedBody
		Files     []file
	}{version, r.AddressID, p.To, p.Subject, r.Draft.Body, p.Body, files})
	if e != nil {
		return nil, ErrInvalid
	}
	return &prepared{mail: p, fingerprint: sha256.Sum256(encoded), version: version}, nil
}
func (s *Service) Preview(draft content.Draft) (Preview, error) {
	p, e := content.RenderBody(draft.Body, content.DraftInputBytes, content.DraftRenderBytes)
	if e != nil {
		return Preview{}, ErrInvalid
	}
	return Preview{Text: p.Text, HTML: p.HTML, Attachments: len(draft.Attachments)}, nil
}
func validNativeKey(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-", rune(c))) {
			return false
		}
	}
	return true
}

// Query keys preserve stored PostgreSQL text, including keys outside the
// stricter grammar used to create new submissions.
func validQueryKey(s string) bool {
	return len(s) > 0 && len(s) <= 16<<10 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func token(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func wireCID(s string) bool {
	return token(s, 256) && strings.IndexFunc(s, unicode.IsSpace) < 0 && !strings.ContainsAny(s, "<>\"'") && !strings.HasPrefix(strings.ToLower(s), "cid:")
}

type boundedWriter struct {
	bytes.Buffer
	limit int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.limit {
		return 0, ErrInvalid
	}
	return w.Buffer.Write(p)
}
func rewriteCIDs(source string, uploads []Uploaded) (string, error) {
	mapping := map[string]string{}
	for _, u := range uploads {
		if u.Inline {
			parsed, err := url.Parse(u.URL)
			validURL := err == nil && parsed.User == nil && parsed.Fragment == "" && ((parsed.Scheme == "https" && parsed.Host != "") || (parsed.Scheme == "cid" && parsed.Opaque == u.ContentID && parsed.RawQuery == ""))
			if !wireCID(u.ContentID) || mapping[u.LogicalCID] != "" || !validURL {
				return "", ErrProvider
			}
			mapping[u.LogicalCID] = u.URL
		}
	}
	doc, e := nethtml.Parse(strings.NewReader(source))
	if e != nil {
		return "", ErrInvalid
	}
	var body *nethtml.Node
	var walk func(*nethtml.Node) error
	walk = func(n *nethtml.Node) error {
		if n.Type == nethtml.ElementNode && n.Data == "body" {
			body = n
		}
		if n.Type == nethtml.ElementNode && n.Data == "img" {
			for i, a := range n.Attr {
				if a.Key == "src" && strings.HasPrefix(strings.ToLower(a.Val), "cid:") {
					logical, e := url.PathUnescape(a.Val[4:])
					if e != nil || mapping[logical] == "" {
						return ErrProvider
					}
					n.Attr[i].Val = mapping[logical]
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if e := walk(c); e != nil {
				return e
			}
		}
		return nil
	}
	if walk(doc) != nil || body == nil {
		return "", ErrProvider
	}
	w := &boundedWriter{limit: content.DraftRenderBytes}
	for n := body.FirstChild; n != nil; n = n.NextSibling {
		if e = nethtml.Render(w, n); e != nil {
			return "", ErrInvalid
		}
	}
	return w.String(), nil
}

type measuredReader struct {
	r    io.Reader
	hash io.Writer
	size int64
}

func (r *measuredReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	if n > 0 {
		r.size += int64(n)
		r.hash.Write(p[:n])
	}
	return n, e
}
