package content

import (
	"io"
	"mime"
	"regexp"
	"strings"

	nethtml "golang.org/x/net/html"
)

// RegistrationBanEvidence classifies a received notification. It neither
// authenticates the sender cryptographically nor proves a provider's current
// account state. Summary contains no source text, email address or user ID.
// The intake owner persists the first evidence; this layer changes no state.
type RegistrationBanEvidence struct {
	AddressID string
	Service   string
	Kind      string
	Summary   string
}

var registrationAssociation = regexp.MustCompile(`(?i)\baccount\s+associated\s+with\s+`)

// DetectRegistrationBan requires independently complete headers and displayed
// bodies. Attachment retention failures do not invalidate an otherwise complete
// body. Directory and route must be the receiving source's immutable snapshot.
// Weak recipient fallback is never used, even when the source permits it for
// ordinary mail attribution. A body address alone cannot create evidence.
func DetectRegistrationBan(message *Message, route SourceRoute, directory *Directory, maxHTMLBytes int64) (RegistrationBanEvidence, bool) {
	if message == nil || !message.HeaderComplete || !message.BodyComplete || maxHTMLBytes <= 0 ||
		!registrationSubject(message.Subject) || directory == nil {
		return RegistrationBanEvidence{}, false
	}
	// Privacy routing also requires an actual delivery header. A visible To/Cc
	// or X-ICLOUD-HME claim by itself is insufficient for this classification.
	hasDelivery := false
	for _, field := range message.Recipients.Strong {
		hasDelivery = hasDelivery || field.Valid && len(field.Addresses) > 0
	}
	if !hasDelivery {
		return RegistrationBanEvidence{}, false
	}
	attribution := directory.Attribute(message.Recipients, route, false)
	if !attribution.Determinate || len(attribution.Matches) == 0 {
		return RegistrationBanEvidence{}, false
	}
	texts := []string{message.Text}
	if message.HTML != "" {
		visible, ok := registrationHTMLText(message.HTML, maxHTMLBytes)
		if !ok {
			return RegistrationBanEvidence{}, false
		}
		texts = append(texts, visible)
	}
	account, ok := registrationAccount(texts)
	if !ok {
		return RegistrationBanEvidence{}, false
	}
	for _, match := range attribution.Matches {
		if match.ID != "" && match.Address == account {
			return RegistrationBanEvidence{
				AddressID: match.ID,
				Service:   "openai",
				Kind:      "account_deactivated",
				Summary:   "Account deactivation notification detected",
			}, true
		}
	}
	return RegistrationBanEvidence{}, false
}

func registrationSubject(subject string) bool {
	decoded, err := new(mime.WordDecoder).DecodeHeader(subject)
	if err != nil {
		return false
	}
	subject = strings.ToLower(strings.Join(strings.Fields(decoded), " "))
	const title = "openai - access deactivated"
	if subject == title {
		return true
	}
	// The provider may append one bracketed case identifier. Reply/forward
	// prefixes and arbitrary suffixes are different message subjects.
	suffix, found := strings.CutPrefix(subject, title+" [")
	if !found || !strings.HasSuffix(suffix, "]") {
		return false
	}
	suffix = strings.TrimSuffix(suffix, "]")
	return strings.TrimSpace(suffix) != "" && !strings.ContainsAny(suffix, "[]")
}

func registrationAccount(texts []string) (string, bool) {
	account := ""
	for _, text := range texts {
		text = strings.Join(strings.Fields(text), " ")
		for _, span := range registrationAssociation.FindAllStringIndex(text, -1) {
			tail := text[span[1]:]
			candidate := ""
			if strings.HasPrefix(tail, "<") {
				end := strings.IndexByte(tail, '>')
				if end > 1 {
					candidate = tail[1:end]
				}
			} else {
				end := strings.IndexAny(tail, " \t\r\n\v\f<>()[]{}\"';:,!?")
				if end < 0 {
					end = len(tail)
				}
				candidate = tail[:end]
				// A single sentence terminator is not part of an addr-spec.
				candidate = strings.TrimSuffix(candidate, ".")
			}
			candidate = normalizeMailbox(candidate)
			if candidate == "" || account != "" && candidate != account {
				return "", false
			}
			account = candidate
		}
	}
	return account, account != ""
}

// Tokenization removes non-displayed regions before the established renderer
// interprets the remaining HTML. In particular, a parser must not reparent text
// from an invalid head element into the visible body. Attributes and comments
// cannot supply association text. Unclosed hidden regions fail conservatively.
func registrationHTMLText(source string, maxBytes int64) (string, bool) {
	if int64(len(source)) > maxBytes {
		return "", false
	}
	tokens := nethtml.NewTokenizer(strings.NewReader(source))
	var visible strings.Builder
	var hidden []string
	for {
		kind := tokens.Next()
		if kind == nethtml.ErrorToken {
			if tokens.Err() != io.EOF || len(hidden) > 0 {
				return "", false
			}
			break
		}
		raw := string(tokens.Raw())
		switch kind {
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			name, _ := tokens.TagName()
			if registrationHiddenElement(string(name)) {
				if kind == nethtml.StartTagToken {
					hidden = append(hidden, string(name))
				}
				continue
			}
		case nethtml.EndTagToken:
			name, _ := tokens.TagName()
			if len(hidden) > 0 {
				for i := len(hidden) - 1; i >= 0; i-- {
					if hidden[i] == string(name) {
						hidden = hidden[:i]
						break
					}
				}
				continue
			}
		case nethtml.CommentToken, nethtml.DoctypeToken:
			continue
		}
		if len(hidden) == 0 {
			visible.WriteString(raw)
		}
	}
	text, err := TextFromHTML(visible.String(), maxBytes)
	return text, err == nil
}

func registrationHiddenElement(name string) bool {
	switch name {
	case "head", "script", "style", "template", "title", "noscript", "iframe", "object", "svg", "math":
		return true
	default:
		return false
	}
}
