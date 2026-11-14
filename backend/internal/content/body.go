package content

import (
	"bytes"
	"html"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	nethtml "golang.org/x/net/html"
)

type BodyFormat string

const (
	BodyText     BodyFormat = "text"
	BodyMarkdown BodyFormat = "markdown"
	BodyHTML     BodyFormat = "html"
)

type Body struct {
	Format BodyFormat
	Source string
}

type RenderedBody struct {
	Text string
	HTML string
}

// The maintained sanitizer is the security boundary. This policy permits mail
// formatting, safe links, bounded inert CSS and logical inline images; it
// permits no external image fetch, forms or active/embedded content.
func mailPolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements("a", "abbr", "b", "blockquote", "br", "caption", "code", "col", "colgroup", "dd", "del", "div", "dl", "dt", "em", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "li", "ol", "p", "pre", "s", "small", "span", "strong", "sub", "sup", "table", "tbody", "td", "th", "thead", "tr", "u", "ul")
	p.AllowAttrs("title").Globally()
	p.AllowStyles("color", "background-color").Matching(regexp.MustCompile(`(?i)^(#[0-9a-f]{3,8}|[a-z]{1,20})$`)).Globally()
	p.AllowStyles("text-align").MatchingEnum("left", "center", "right", "justify").Globally()
	p.AllowStyles("font-weight").MatchingEnum("normal", "bold", "400", "600", "700").Globally()
	p.AllowStyles("font-style").MatchingEnum("normal", "italic").Globally()
	p.AllowStyles("text-decoration").MatchingEnum("none", "underline", "line-through").Globally()
	p.AllowAttrs("href").Matching(regexp.MustCompile(`(?i)^(https?://|mailto:)`)).OnElements("a")
	p.AllowAttrs("src").Matching(regexp.MustCompile(`(?i)^cid:[^\x00-\x20<>"']{1,256}$`)).OnElements("img")
	p.AllowAttrs("alt").OnElements("img")
	p.AllowAttrs("colspan", "rowspan").Matching(regexp.MustCompile(`^[1-9][0-9]{0,2}$`)).OnElements("td", "th")
	p.AllowAttrs("start").Matching(regexp.MustCompile(`^[0-9]{1,9}$`)).OnElements("ol")
	p.AllowURLSchemes("http", "https", "mailto", "cid")
	p.AllowRelativeURLs(false)
	p.RequireParseableURLs(true)
	p.RequireNoFollowOnLinks(true)
	p.RequireNoReferrerOnLinks(true)
	return p
}

// SafeFragment does not resolve CID URLs. The caller must bind logical CIDs to
// verified local/provider objects before displaying images. Its input and
// output each have the supplied byte ceiling.
func SafeFragment(source string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		return "", ErrLimits
	}
	if int64(len(source)) > maxBytes {
		return "", &BudgetError{Resource: "render"}
	}
	out := mailPolicy().Sanitize(validText(source))
	if int64(len(out)) > maxBytes {
		return "", &BudgetError{Resource: "render"}
	}
	return out, nil
}

// RenderBody is deterministic and has no provider or filesystem effects.
func RenderBody(body Body, inputBytes, renderBytes int64) (RenderedBody, error) {
	if inputBytes <= 0 || renderBytes <= 0 {
		return RenderedBody{}, ErrLimits
	}
	if int64(len(body.Source)) > inputBytes {
		return RenderedBody{}, &BudgetError{Resource: "input"}
	}
	if !validUTF8(body.Source) {
		return RenderedBody{}, ErrDraft
	}
	var raw string
	switch body.Format {
	case BodyText:
		raw = "<pre>" + html.EscapeString(body.Source) + "</pre>"
	case BodyMarkdown:
		var rendered bytes.Buffer
		markdown := goldmark.New(goldmark.WithExtensions(extension.GFM))
		if err := markdown.Convert([]byte(body.Source), &rendered); err != nil {
			return RenderedBody{}, ErrDraft
		}
		raw = rendered.String()
	case BodyHTML:
		raw = body.Source
	default:
		return RenderedBody{}, ErrDraft
	}
	safe, err := SafeFragment(raw, renderBytes)
	if err != nil {
		return RenderedBody{}, err
	}
	plain := textFromSafeHTML(safe, true)
	if body.Format == BodyText {
		plain = body.Source
	}
	if int64(len(plain)) > renderBytes {
		return RenderedBody{}, &BudgetError{Resource: "render"}
	}
	return RenderedBody{Text: plain, HTML: safe}, nil
}

// RenderReceived returns an inline HTML fragment. It does not mark an
// incomplete Message complete or choose among archived messages.
func RenderReceived(message *Message, maxBytes int64) (string, error) {
	if message == nil {
		return "", ErrMalformed
	}
	if message.HTML != "" {
		return SafeFragment(message.HTML, maxBytes)
	}
	return SafeFragment("<pre>"+html.EscapeString(message.Text)+"</pre>", maxBytes)
}

// TextFromHTML uses the same sanitization policy as rendering. Offsets returned
// by FindCodes for HTML refer to this visible text, never HTML source bytes.
func TextFromHTML(source string, maxBytes int64) (string, error) {
	safe, err := SafeFragment(source, maxBytes)
	if err != nil {
		return "", err
	}
	text := textFromSafeHTML(safe, false)
	if int64(len(text)) > maxBytes {
		return "", &BudgetError{Resource: "render"}
	}
	return text, nil
}

func textFromSafeHTML(source string, references bool) string {
	doc, err := nethtml.Parse(strings.NewReader(source))
	if err != nil {
		return ""
	}
	var out strings.Builder
	var walk func(*nethtml.Node)
	walk = func(node *nethtml.Node) {
		block := false
		if node.Type == nethtml.ElementNode {
			if references && node.Data == "img" {
				alt := ""
				for _, attribute := range node.Attr {
					if attribute.Key == "alt" {
						alt = attribute.Val
					}
				}
				if alt == "" {
					out.WriteString("[图片]")
				} else {
					out.WriteString("[图片：" + alt + "]")
				}
				return
			}
			switch node.Data {
			case "br", "hr":
				out.WriteByte('\n')
				return
			case "p", "div", "li", "tr", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6":
				block = true
			case "td", "th":
				out.WriteByte('\t')
			}
			if block {
				out.WriteByte('\n')
			}
			if references && node.Data == "li" {
				out.WriteString("• ")
			}
		}
		if node.Type == nethtml.TextNode {
			out.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if references && node.Type == nethtml.ElementNode && node.Data == "a" {
			for _, attribute := range node.Attr {
				if attribute.Key == "href" {
					out.WriteString(" (" + attribute.Val + ")")
				}
			}
		}
		if block {
			out.WriteByte('\n')
		}
	}
	walk(doc)
	lines := strings.Split(out.String(), "\n")
	var clean []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" && (len(clean) == 0 || clean[len(clean)-1] == "") {
			continue
		}
		clean = append(clean, line)
	}
	return strings.TrimSpace(strings.Join(clean, "\n"))
}

func validUTF8(source string) bool { return utf8.ValidString(source) }
