// Package compose builds the text/plain and text/html alternatives used by
// the mail transport. Markdown source is never sent as an HTML MIME type.
package compose

import (
	"bytes"
	"errors"
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	nethtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const MaxSourceBytes = 100 << 10
const MaxRenderedBytes = 512 << 10

type Body struct {
	Text string `json:"text"`
	HTML string `json:"html"`
}

var markdown = goldmark.New(goldmark.WithExtensions(extension.GFM))
var mailPolicy = func() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	p.AllowRelativeURLs(false)
	p.AllowURLSchemes("cid")
	p.AllowStyles("color", "background-color").Matching(regexp.MustCompile(`(?i)^(#[0-9a-f]{3,8}|[a-z]{1,20})$`)).Globally()
	p.AllowStyles("text-align").MatchingEnum("left", "center", "right", "justify").Globally()
	p.AllowStyles("font-weight").MatchingEnum("normal", "bold", "400", "600", "700").Globally()
	p.AllowStyles("font-style").MatchingEnum("normal", "italic").Globally()
	p.AllowStyles("text-decoration").MatchingEnum("none", "underline", "line-through").Globally()
	return p
}()

func Render(format, source string) (Body, error) {
	if !utf8.ValidString(source) || len(source) > MaxSourceBytes || strings.ContainsRune(source, 0) {
		return Body{}, errors.New("正文必须是有效 UTF-8，且不能超过 100 KiB")
	}
	var content string
	switch format {
	case "", "text":
		content := "<div>" + strings.ReplaceAll(html.EscapeString(strings.ReplaceAll(source, "\r\n", "\n")), "\n", "</div><div>") + "</div>"
		if len(content) > MaxRenderedBytes {
			return Body{}, errors.New("转换后的邮件正文过大")
		}
		return Body{Text: source, HTML: content}, nil
	case "markdown":
		var output bytes.Buffer
		if err := markdown.Convert([]byte(source), &output); err != nil {
			return Body{}, errors.New("Markdown 转换失败")
		}
		content = output.String()
	case "html":
		content = source
	default:
		return Body{}, errors.New("正文格式必须为 text、markdown 或 html")
	}
	content = mailPolicy.Sanitize(content)
	nodes, err := parse(content)
	if err != nil {
		return Body{}, errors.New("HTML 正文无效")
	}
	var text strings.Builder
	var walk func(*nethtml.Node)
	walk = func(n *nethtml.Node) {
		block := n.Type == nethtml.ElementNode && strings.Contains("|p|div|h1|h2|h3|h4|h5|h6|li|tr|pre|blockquote|hr|", "|"+n.Data+"|")
		if block {
			text.WriteByte('\n')
		}
		if n.Type == nethtml.TextNode {
			text.WriteString(n.Data)
		}
		if n.Type == nethtml.ElementNode {
			switch n.Data {
			case "br":
				text.WriteByte('\n')
			case "li":
				text.WriteString("• ")
			case "td", "th":
				text.WriteByte('\t')
			case "img":
				text.WriteString("[图片" + imageLabel(n) + "]")
			}
			styles := map[string]string{"table": "border-collapse:collapse", "td": "border:1px solid #d1d5db;padding:6px 10px", "th": "border:1px solid #d1d5db;padding:6px 10px", "pre": "white-space:pre-wrap;background-color:#f3f4f6;padding:12px", "blockquote": "border-left:3px solid #d1d5db;padding-left:12px"}
			if style := styles[n.Data]; style != "" {
				merged := false
				for i, a := range n.Attr {
					if a.Key == "style" {
						n.Attr[i].Val = a.Val + ";" + style
						merged = true
						break
					}
				}
				if !merged {
					n.Attr = append(n.Attr, nethtml.Attribute{Key: "style", Val: style})
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if n.Type == nethtml.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" && !strings.HasPrefix(a.Val, "cid:") {
					text.WriteString(" (" + a.Val + ")")
				}
			}
		}
		if block {
			text.WriteByte('\n')
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	content, err = serialize(nodes)
	if err != nil || len(content) > MaxRenderedBytes || text.Len() > MaxRenderedBytes {
		return Body{}, errors.New("转换后的邮件正文过大")
	}
	return Body{Text: strings.TrimSpace(text.String()), HTML: content}, nil
}

func imageLabel(n *nethtml.Node) string {
	for _, a := range n.Attr {
		if a.Key == "alt" && a.Val != "" {
			return "：" + a.Val
		}
	}
	return ""
}

// RewriteCIDs only changes img/src references, never text, links, or arbitrary
// attributes. An unknown CID is a missing attachment, not a remote fetch.
func RewriteCIDs(content string, replacements map[string]string) (string, error) {
	uris := make(map[string]string, len(replacements))
	for id, value := range replacements {
		uris[id] = "cid:" + value
	}
	return RewriteImageSources(content, uris)
}

// RewriteImageSources binds logical CID references to transport-controlled
// sources. Apple expects its verified upload URL and rewrites that URL to the
// final MIME Content-ID; a cachedpart ID is not a deliverable Content-ID.
func RewriteImageSources(content string, replacements map[string]string) (string, error) {
	nodes, err := parse(content)
	if err != nil {
		return "", err
	}
	var walk func(*nethtml.Node) error
	walk = func(n *nethtml.Node) error {
		if n.Type == nethtml.ElementNode && n.Data == "img" {
			for i, a := range n.Attr {
				if a.Key != "src" || !strings.HasPrefix(strings.ToLower(a.Val), "cid:") {
					continue
				}
				cid, err := url.PathUnescape(a.Val[4:])
				if err != nil {
					return errors.New("正文图片 CID 无效")
				}
				replacement, ok := replacements[cid]
				if !ok {
					return errors.New("正文引用的图片附件不存在")
				}
				n.Attr[i].Val = replacement
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	for _, n := range nodes {
		if err := walk(n); err != nil {
			return "", err
		}
	}
	return serialize(nodes)
}

func parse(content string) ([]*nethtml.Node, error) {
	return nethtml.ParseFragment(strings.NewReader(content), &nethtml.Node{Type: nethtml.ElementNode, Data: "div", DataAtom: atom.Div})
}
func serialize(nodes []*nethtml.Node) (string, error) {
	var out strings.Builder
	for _, n := range nodes {
		if err := nethtml.Render(&out, n); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}
