package content

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"net/mail"
	"strconv"
	"strings"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // library charset conversion to UTF-8
	messageMail "github.com/emersion/go-message/mail"
	messageText "github.com/emersion/go-message/textproto"
)

// wireBudget also bounds the library's multipart-header allocations. NextPart
// may prefetch body bytes, so its window allows a small buffer per nesting level
// in addition to HeaderBytes. Actual header size is checked independently.
type wireBudget struct {
	r      io.Reader
	left   int64
	read   int64
	window int64 // -1 while reading bodies
}

func (r *wireBudget) Read(p []byte) (int, error) {
	if r.left == 0 {
		var probe [1]byte
		n, err := r.r.Read(probe[:])
		if n > 0 {
			return 0, &BudgetError{Resource: "message"}
		}
		return 0, err
	}
	if r.window == 0 {
		return 0, &BudgetError{Resource: "header"}
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	if r.window > 0 && int64(len(p)) > r.window {
		p = p[:r.window]
	}
	n, err := r.r.Read(p)
	r.left -= int64(n)
	r.read += int64(n)
	if r.window > 0 {
		r.window -= int64(n)
	}
	return n, err
}

type parser struct {
	limits    Limits
	wire      *wireBudget
	result    *Message
	parts     int
	bodyLeft  int64
	filesLeft int64
}

type bodyPair struct{ text, html string }

// Parse consumes a single MIME input under explicit budgets. A non-nil Message
// returned with an error is metadata-only/partial, never a complete parse.
// Body truncation and unsupported charset are also visible in Issues/Complete.
// No error includes the source header or body.
func Parse(r io.Reader, limits Limits) (*Message, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrMalformed
	}
	m := &Message{Complete: true, BodyComplete: true}
	wire := &wireBudget{r: r, left: limits.MessageBytes, window: -1}
	defer func() { m.WireBytes = wire.read }()
	buffered := bufio.NewReader(wire)
	raw, err := captureHeader(buffered, limits.HeaderBytes)
	m.RawHeader = raw
	if err != nil {
		m.issue("header_unavailable", "", isBudget(err))
		m.WireBytes = wire.read
		return m, safeParseError(err)
	}
	h, err := messageText.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		m.issue("header_malformed", "", false)
		return m, ErrMalformed
	}
	header := message.Header{Header: h}
	m.HeaderComplete = true
	fields := header.Fields()
	for fields.Next() {
		m.Headers = append(m.Headers, HeaderField{Name: fields.Key(), Value: fields.Value()})
	}
	m.Subject, err = header.Text("Subject")
	m.Subject = validText(m.Subject)
	if err != nil {
		m.issue("subject_charset", "", false)
	}
	m.FromText, err = header.Text("From")
	m.FromText = validText(m.FromText)
	if err != nil {
		m.issue("from_charset", "", false)
	}
	from, err := messageMail.ParseAddressList(header.Get("From"))
	if err == nil {
		if len(from) > limits.Addresses {
			m.issue("address_limit", "", true)
			from = from[:limits.Addresses]
		}
		for _, address := range from {
			m.From = append(m.From, Mailbox{Name: validText(address.Name), Address: address.Address})
		}
	} else if header.Get("From") != "" {
		m.issue("from_malformed", "", false)
	}
	m.Date, _ = mail.ParseDate(header.Get("Date"))
	m.MessageID = header.Get("Message-ID")
	m.Recipients = CollectRecipients(m.Headers, limits.Addresses)
	if m.Recipients.Limited {
		m.issue("address_limit", "", true)
	}
	p := parser{limits: limits, wire: wire, result: m, bodyLeft: limits.BodyBytes, filesLeft: limits.AttachmentBytes}
	body, err := p.part(header, buffered, "", 0, true)
	m.Text, m.HTML = body.text, body.html
	if int64(len(m.Text))+int64(len(m.HTML)) > limits.BodyBytes {
		// Joining multiple body fragments introduces separator bytes that are
		// not decoded input. Keep the stored representation bounded as well.
		textBytes := min(int64(len(m.Text)), limits.BodyBytes)
		m.Text = validText(m.Text[:textBytes])
		htmlBytes := min(int64(len(m.HTML)), limits.BodyBytes-int64(len(m.Text)))
		m.HTML = validText(m.HTML[:htmlBytes])
		m.issue("body_truncated", "", true)
	}
	if err == nil {
		// Includes MIME epilogues and unused bytes in the wire budget.
		_, err = io.Copy(io.Discard, buffered)
	}
	m.WireBytes = wire.read
	if err != nil {
		m.issue("mime_incomplete", "", isBudget(err))
		return m, safeParseError(err)
	}
	return m, nil
}

// Only detects the header/body separator; MIME field parsing belongs to the
// maintained go-message parser. ReadSlice avoids allocating an unbounded line.
func captureHeader(r *bufio.Reader, limit int64) ([]byte, error) {
	var raw []byte
	lineStart := 0
	for {
		chunk, err := r.ReadSlice('\n')
		if int64(len(raw))+int64(len(chunk)) > limit {
			return raw, &BudgetError{Resource: "header"}
		}
		raw = append(raw, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(raw) > 0 {
			// A header-only RFC 5322 message need not have a body separator.
			// Let the mature header parser decide whether these fields are valid.
			return raw, nil
		}
		if err != nil {
			return raw, err
		}
		line := raw[lineStart:]
		if bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")) {
			return raw, nil
		}
		lineStart = len(raw)
	}
}

func (p *parser) part(h message.Header, rawBody io.Reader, path string, depth int, bodyAllowed bool) (bodyPair, error) {
	p.parts++
	if p.parts > p.limits.Parts {
		return bodyPair{}, &BudgetError{Resource: "parts"}
	}
	if depth > p.limits.Depth {
		return bodyPair{}, &BudgetError{Resource: "depth"}
	}
	var headerSize int64
	fields := h.Fields()
	for fields.Next() {
		b, err := fields.Raw()
		if err != nil {
			return bodyPair{}, ErrMalformed
		}
		headerSize += int64(len(b))
		if headerSize > p.limits.HeaderBytes {
			return bodyPair{}, &BudgetError{Resource: "header"}
		}
	}
	mediaType, params, err := h.ContentType()
	if err != nil {
		return bodyPair{}, ErrMalformed
	}
	disposition, dispositionParams, _ := h.ContentDisposition()
	filename := dispositionParams["filename"]
	if filename == "" {
		filename = params["name"]
	}
	cid := strings.Trim(strings.TrimSpace(h.Get("Content-ID")), "<>")
	isMultipart := strings.HasPrefix(mediaType, "multipart/")
	isTextBody := mediaType == "text/plain" || mediaType == "text/html"
	isFile := !bodyAllowed || disposition == "attachment" || filename != "" || (!isMultipart && !isTextBody)
	decodeHeader := h
	if isFile && strings.HasPrefix(mediaType, "text/") && params["charset"] != "" {
		// Attachment integrity is transfer-decoded bytes, not charset-converted
		// text. Charset conversion is only for the actual displayed body.
		decodeHeader = h.Copy()
		fileParams := make(map[string]string, len(params))
		for key, value := range params {
			if key != "charset" {
				fileParams[key] = value
			}
		}
		decodeHeader.Set("Content-Type", mime.FormatMediaType(mediaType, fileParams))
	}
	entity, decodeErr := message.New(decodeHeader, rawBody)
	if decodeErr != nil {
		if message.IsUnknownEncoding(decodeErr) {
			p.result.issue("unsupported_transfer_encoding", path, false)
			_, err := io.Copy(io.Discard, rawBody)
			return bodyPair{}, err
		}
		p.result.issue("unsupported_charset", path, false)
	}
	if isMultipart && !isFile {
		if params["boundary"] == "" {
			return bodyPair{}, ErrMalformed
		}
		reader := messageText.NewMultipartReader(entity.Body, params["boundary"])
		var body bodyPair
		var textParts, htmlParts strings.Builder
		collected := func() bodyPair {
			if mediaType == "multipart/alternative" {
				return body
			}
			return bodyPair{text: textParts.String(), html: htmlParts.String()}
		}
		index := 0
		relatedRoot := false
		for {
			// The library does not expose per-part header limits. Bound its
			// underlying reads while NextPart parses a header; existing parser
			// buffers are themselves bounded by the declared depth.
			overhead := int64(depth+2) * 8192
			p.wire.window = math.MaxInt64
			if p.limits.HeaderBytes <= math.MaxInt64-overhead {
				p.wire.window = p.limits.HeaderBytes + overhead
			}
			part, err := reader.NextPart()
			p.wire.window = -1
			if err == io.EOF {
				if mediaType == "multipart/related" && !relatedRoot {
					return collected(), ErrMalformed
				}
				return collected(), nil
			}
			if err != nil {
				return collected(), err
			}
			index++
			childPath := strconv.Itoa(index)
			if path != "" {
				childPath = path + "." + childPath
			}
			childHeader := message.Header{Header: part.Header}
			allow := bodyAllowed
			if mediaType == "multipart/related" {
				start := strings.Trim(params["start"], "<>")
				allow = allow && ((start == "" && index == 1) || (start != "" && strings.Trim(childHeader.Get("Content-ID"), "<>") == start))
				relatedRoot = relatedRoot || allow
			}
			child, err := p.part(childHeader, part, childPath, depth+1, allow)
			if mediaType == "multipart/alternative" {
				if child.text != "" {
					body.text = child.text
				}
				if child.html != "" {
					body.html = child.html
				}
			} else {
				appendBody(&textParts, child.text)
				appendBody(&htmlParts, child.html)
			}
			if err != nil {
				return collected(), err
			}
		}
	}
	if isFile {
		if len(p.result.Attachments) >= p.limits.Attachments {
			return bodyPair{}, &BudgetError{Resource: "attachments"}
		}
		b, size, complete, err := readRetained(entity.Body, p.filesLeft)
		if err != nil {
			return bodyPair{}, err
		}
		file := Attachment{Part: path, Filename: validText(filename), MediaType: mediaType, Disposition: disposition,
			ContentID: cid, Inline: disposition == "inline" || cid != "", Size: size, Complete: complete}
		if complete {
			file.Bytes = b
			p.filesLeft -= size
		} else {
			p.result.issue("attachment_truncated", path, true)
		}
		p.result.Attachments = append(p.result.Attachments, file)
		return bodyPair{}, nil
	}
	b, size, complete, err := readRetained(entity.Body, p.bodyLeft)
	p.bodyLeft -= int64(len(b))
	if err != nil {
		return bodyPair{}, err
	}
	if !complete {
		p.result.issue("body_truncated", path, true)
	}
	_ = size // only retained textual bytes are useful outside this pure layer
	text := validText(string(b))
	if mediaType == "text/html" {
		return bodyPair{html: text}, nil
	}
	return bodyPair{text: text}, nil
}

func readRetained(r io.Reader, limit int64) ([]byte, int64, bool, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, int64(len(b)), false, err
	}
	if int64(len(b)) < limit {
		return b, int64(len(b)), true, nil
	}
	var probe [1]byte
	count, err := io.ReadFull(r, probe[:])
	if count == 0 && err == io.EOF {
		return b, int64(len(b)), true, nil
	}
	if err != nil {
		return nil, int64(len(b)) + int64(count), false, err
	}
	n, err := io.Copy(io.Discard, r)
	return b, int64(len(b)) + int64(count) + n, false, err
}

func validText(s string) string { return strings.ToValidUTF8(s, "") }

func appendBody(out *strings.Builder, fragment string) {
	if fragment == "" {
		return
	}
	if out.Len() > 0 {
		out.WriteByte('\n')
	}
	out.WriteString(fragment)
}

func isBudget(err error) bool {
	var budget *BudgetError
	return errors.As(err, &budget)
}

func safeParseError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var budget *BudgetError
	if errors.As(err, &budget) {
		return budget
	}
	return ErrMalformed
}
