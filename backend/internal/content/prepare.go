package content

import (
	"bytes"
	"mime"
	"net/url"
	"strings"
	"unicode"

	messageMail "github.com/emersion/go-message/mail"
	"github.com/gabriel-vasile/mimetype"
	nethtml "golang.org/x/net/html"
)

const (
	DraftInputBytes      = 100 << 10
	DraftRenderBytes     = 512 << 10
	DraftAttachmentBytes = 10 << 20
	DraftAttachments     = 10
)

type DraftAttachment struct {
	Filename  string
	MediaType string
	ContentID string
	Inline    bool
	Bytes     []byte
}

type Draft struct {
	Recipient   string
	Subject     string
	Body        Body
	Attachments []DraftAttachment
}

// Prepared owns independent attachment byte slices. Provider upload references,
// final Content-IDs, request ownership and fingerprints belong to their use
// cases/adapters and are not guessed or synthesized here.
type Prepared struct {
	To                   Mailbox
	Subject              string
	Body                 RenderedBody
	Attachments          []DraftAttachment
	ReferencedContentIDs []string
}

func Prepare(draft Draft) (*Prepared, error) {
	if !validUTF8(draft.Subject) || len(draft.Subject) > 998 || hasControl(draft.Subject) || hasControl(draft.Recipient) {
		return nil, ErrDraft
	}
	to, err := messageMail.ParseAddress(draft.Recipient)
	if err != nil || normalizeMailbox(to.Address) == "" {
		return nil, ErrDraft
	}
	if len(draft.Attachments) > DraftAttachments {
		return nil, &BudgetError{Resource: "attachments"}
	}
	body, err := RenderBody(draft.Body, DraftInputBytes, DraftRenderBytes)
	if err != nil {
		return nil, err
	}
	out := &Prepared{To: Mailbox{Name: to.Name, Address: to.Address}, Subject: draft.Subject, Body: body}
	var total int64
	inline := make(map[string]bool)
	identifiers := make(map[string]bool)
	for _, file := range draft.Attachments {
		if !validFilename(file.Filename) || !validUTF8(file.MediaType) || hasControl(file.MediaType) {
			return nil, ErrDraft
		}
		total += int64(len(file.Bytes))
		if total > DraftAttachmentBytes {
			return nil, &BudgetError{Resource: "attachment_bytes"}
		}
		mediaType, params, err := mime.ParseMediaType(file.MediaType)
		if err != nil || mediaType == "" {
			return nil, ErrDraft
		}
		if file.ContentID != "" {
			if !validCID(file.ContentID) || identifiers[file.ContentID] {
				return nil, ErrDraft
			}
			identifiers[file.ContentID] = true
		}
		if file.Inline {
			if !validCID(file.ContentID) || inline[file.ContentID] {
				return nil, ErrDraft
			}
			switch mediaType {
			case "image/png", "image/jpeg", "image/gif", "image/webp":
				if mimetype.Detect(file.Bytes).String() != mediaType {
					return nil, ErrDraft
				}
			default:
				return nil, ErrDraft
			}
			inline[file.ContentID] = true
		}
		file.MediaType = mime.FormatMediaType(mediaType, params)
		file.Bytes = bytes.Clone(file.Bytes)
		out.Attachments = append(out.Attachments, file)
	}
	refs, err := inlineReferences(out.Body.HTML)
	if err != nil {
		return nil, ErrDraft
	}
	for _, cid := range refs {
		if !inline[cid] {
			return nil, ErrDraft
		}
	}
	out.ReferencedContentIDs = refs
	return out, nil
}

func validFilename(filename string) bool {
	return filename != "" && filename != "." && filename != ".." && len(filename) <= 255 &&
		filename == strings.TrimSpace(filename) && validUTF8(filename) && !hasControl(filename) && !strings.ContainsAny(filename, "/\\")
}

func hasControl(value string) bool { return strings.IndexFunc(value, unicode.IsControl) >= 0 }

func validCID(cid string) bool {
	if cid == "" || len(cid) > 256 || !validUTF8(cid) {
		return false
	}
	return strings.IndexFunc(cid, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("<>\"'", r)
	}) < 0 && !strings.HasPrefix(strings.ToLower(cid), "cid:")
}

func inlineReferences(source string) ([]string, error) {
	doc, err := nethtml.Parse(strings.NewReader(source))
	if err != nil {
		return nil, err
	}
	var refs []string
	seen := make(map[string]bool)
	var walk func(*nethtml.Node) error
	walk = func(node *nethtml.Node) error {
		if node.Type == nethtml.ElementNode && node.Data == "img" {
			for _, attr := range node.Attr {
				if attr.Key != "src" || !strings.HasPrefix(strings.ToLower(attr.Val), "cid:") {
					continue
				}
				cid, err := url.PathUnescape(attr.Val[4:])
				if err != nil || !validCID(cid) {
					return ErrDraft
				}
				if !seen[cid] {
					refs = append(refs, cid)
					seen[cid] = true
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(doc); err != nil {
		return nil, err
	}
	return refs, nil
}
