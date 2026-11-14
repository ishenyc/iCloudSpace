// Package content owns pure, bounded mail interpretation. It never opens an
// archive, changes mailbox state, contacts a provider, or persists a result.
package content

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrLimits    = errors.New("content: all limits must be positive")
	ErrMalformed = errors.New("content: malformed MIME")
	ErrDraft     = errors.New("content: invalid draft")
)

// Limits are supplied by the use case. BodyBytes and AttachmentBytes bound the
// total retained decoded bytes, including MIME alternatives and related parts.
// HeaderBytes applies to each header block. MessageBytes bounds the entire wire
// input, including preambles, epilogues and parts that are not retained.
type Limits struct {
	MessageBytes    int64
	HeaderBytes     int64
	BodyBytes       int64
	AttachmentBytes int64
	Parts           int
	Depth           int
	Addresses       int
	Attachments     int
}

func (l Limits) validate() error {
	if l.MessageBytes <= 0 || l.HeaderBytes <= 0 || l.BodyBytes <= 0 || l.AttachmentBytes <= 0 ||
		l.Parts <= 0 || l.Depth <= 0 || l.Addresses <= 0 || l.Attachments <= 0 {
		return ErrLimits
	}
	return nil
}

// BudgetError is safe to log: it contains no mail content or address.
type BudgetError struct{ Resource string }

func (e *BudgetError) Error() string { return fmt.Sprintf("content: %s budget exceeded", e.Resource) }

type HeaderField struct {
	Name  string
	Value string // unfolded, with duplicate fields retained in wire order
}

type Mailbox struct {
	Name    string
	Address string
}

type Issue struct {
	Code string
	Part string // MIME child indices, e.g. "1.2"; empty denotes the root
}

type Attachment struct {
	Part        string
	Filename    string
	MediaType   string
	Disposition string
	ContentID   string // identifier without angle brackets; case is preserved
	Inline      bool
	Size        int64 // decoded bytes observed, including discarded bytes
	Bytes       []byte
	Complete    bool // false means Bytes must not be used as the original file
}

type Message struct {
	// RawHeader is the complete original top-level header, including its blank
	// separator when present and original line endings. The archive owner keeps
	// raw MIME. An incomplete header is explicitly flagged in Issues/Complete.
	RawHeader      []byte
	HeaderComplete bool // full top-level header captured and parsed, independent of body retention
	Headers        []HeaderField
	Subject        string
	FromText       string
	From           []Mailbox
	Date           time.Time
	MessageID      string
	Text           string
	HTML           string // decoded source, NOT safe to insert into a document
	Attachments    []Attachment
	Recipients     RecipientEvidence
	Issues         []Issue
	Complete       bool
	BodyComplete   bool // attachment retention/metadata failures need not invalidate the displayed body
	Truncated      bool
	WireBytes      int64
}

func (m *Message) issue(code, part string, truncated bool) {
	m.Issues = append(m.Issues, Issue{Code: code, Part: part})
	m.Complete = false
	m.Truncated = m.Truncated || truncated
	switch code {
	case "body_truncated", "header_unavailable", "header_malformed", "unsupported_transfer_encoding", "unsupported_charset", "mime_incomplete":
		m.BodyComplete = false
	}
}
