// Package mailview owns canonical local mailbox reads and explicit consumption.
// It has no provider/network mutation port and never allocates mailbox UIDs.
package mailview

import (
	"errors"
	"icloudspace/internal/content"
	"io"
)

var (
	ErrInvalid     = errors.New("mailview: invalid request")
	ErrDenied      = errors.New("mailview: lease scope rejected")
	ErrNotFound    = errors.New("mailview: message not found")
	ErrStale       = errors.New("mailview: snapshot changed")
	ErrConsumed    = errors.New("mailview: message already consumed")
	ErrStorage     = errors.New("mailview: storage operation failed")
	ErrMetadata    = errors.New("mailview: canonical metadata rejected")
	ErrUnavailable = errors.New("mailview: original body unavailable")
	ErrBudget      = errors.New("mailview: read budget exceeded")
	ErrUnknown     = errors.New("mailview: claim acknowledgement unknown; query required")
	ErrReadOnly    = errors.New("mailview: installation writes disabled")
)

type Mailbox struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}
type Attachment struct {
	Part        string `json:"part,omitempty"`
	Filename    string `json:"filename"`
	MediaType   string `json:"media_type"`
	Disposition string `json:"disposition,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
	Inline      bool   `json:"inline,omitempty"`
	ByteSize    int64  `json:"byte_size"`
	Complete    bool   `json:"complete"`
}
type Remote struct {
	SourceGeneration int64  `json:"source_generation,string"`
	Mailbox          string `json:"mailbox"`
	UIDValidity      uint32 `json:"uid_validity"`
	UID              uint32 `json:"uid"`
}
type Metadata struct {
	EntryID               int64     `json:"entry_id,string"`
	MessageID             int64     `json:"message_id,string"`
	UID                   uint32    `json:"uid"`
	Remote                Remote    `json:"remote"`
	RFCMessageID          string    `json:"rfc_message_id"`
	Subject               string    `json:"subject"`
	From                  []Mailbox `json:"from"`
	To                    []Mailbox `json:"to"`
	CC                    []Mailbox `json:"cc"`
	SentAt                *int64    `json:"sent_at,omitempty,string"`
	ReceivedAt            int64     `json:"received_at,string"`
	VisibleAt             int64     `json:"visible_at,string"`
	Seen                  bool      `json:"seen"`
	ContentState          string    `json:"content_state"`
	RawState              string    `json:"raw_state"`
	DeclaredBodySize      int64     `json:"declared_body_size,string"`
	DeclaredBodyTruncated bool      `json:"declared_body_truncated"`
	Preview               string    `json:"preview"`
}
type Message struct {
	Metadata     Metadata     `json:"metadata"`
	Text         string       `json:"text"`
	HTML         string       `json:"html"`
	Attachments  []Attachment `json:"attachments"`
	BodyComplete bool         `json:"body_complete"`
	ViewKey      string       `json:"view_key,omitempty"`
}
type SnapshotRef struct {
	AuthGeneration     int64  `json:"auth_generation,string"`
	MessageID          int64  `json:"message_id,string"`
	EntryID            int64  `json:"entry_id,string"`
	LocalUID           uint32 `json:"local_uid"`
	LocalUIDValidity   int64  `json:"local_uid_validity,string"`
	ViewKey            string `json:"view_key"`
	ViewScopeAddressID int64  `json:"view_scope_address_id,string"`
	SelectedAt         int64  `json:"selected_at,string"`
	Remote             Remote `json:"remote"`
}
type Snapshot struct {
	Ref      SnapshotRef `json:"ref"`
	Message  Message     `json:"message"`
	Consumed bool        `json:"consumed"`
}
type Code struct {
	Code       string `json:"code"`
	EntryID    int64  `json:"entry_id,string"`
	UID        uint32 `json:"uid"`
	ReceivedAt int64  `json:"received_at,string"`
}
type Page struct {
	Limit      int
	BeforeTime *int64
	BeforeID   int64
}
type MessagePage struct {
	Items    []Metadata `json:"items"`
	More     bool       `json:"more"`
	NextTime *int64     `json:"next_time,omitempty,string"`
	NextID   int64      `json:"next_id,string"`
}
type Status struct {
	UIDValidity int64  `json:"uid_validity,string"`
	UIDNext     uint64 `json:"uid_next"`
	Messages    int64  `json:"messages,string"`
	Unseen      int64  `json:"unseen,string"`
	HighestUID  uint32 `json:"highest_uid"`
}
type BodyReader interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
}
type Raw struct {
	Reader   BodyReader
	ByteSize int64
	Original bool
	State    string
}

func (r *Raw) Close() error {
	if r != nil && r.Reader != nil {
		return r.Reader.Close()
	}
	return nil
}

type Download struct {
	Reader                         io.ReadCloser
	Filename, MediaType, ContentID string
	ByteSize                       int64
}

func (d *Download) Close() error {
	if d != nil && d.Reader != nil {
		return d.Reader.Close()
	}
	return nil
}

type ClaimRequest struct {
	Key      string
	Snapshot SnapshotRef
}
type ClaimResult struct {
	Key       string `json:"key"`
	Committed bool   `json:"committed"`
	Remote    Remote `json:"remote"`
	ClaimedAt int64  `json:"claimed_at,string"`
	Snippet   string `json:"snippet,omitempty"`
}
type Options struct {
	Clock  func() int64
	Limits content.Limits
	// Wake must coalesce source IDs and return immediately. The root owns the
	// bounded scheduler; this callback must never perform or wait for network IO.
	Wake func(int64)
}

func DefaultLimits() content.Limits {
	return content.Limits{MessageBytes: 100 << 20, HeaderBytes: 128 << 10, BodyBytes: 512 << 10, AttachmentBytes: 100 << 20, Parts: 1000, Depth: 30, Addresses: 10000, Attachments: 1000}
}
