// Package intake owns one bounded, read-only upstream scan and its atomic
// canonical checkpoint. Admission, scheduling, consumption and Seen writes
// belong to their callers.
package intake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"icloudspace/internal/blobstore"
	"icloudspace/internal/content"
	upstream "icloudspace/internal/provider/imap"
	"icloudspace/internal/sourceguard"
)

var (
	ErrInvalid        = errors.New("intake: invalid input")
	ErrStale          = errors.New("intake: snapshot changed")
	ErrUnresolved     = errors.New("intake: unresolved checkpoint")
	ErrUnknown        = errors.New("intake: checkpoint outcome unknown")
	ErrUIDExhausted   = errors.New("intake: local UID space exhausted")
	ErrSourceChanged  = errors.New("intake: source bytes changed")
	ErrTimestampRange = errors.New("intake: timestamp outside signed nanosecond range")
)

type PendingError struct{ BatchKey string }

func (e *PendingError) Error() string { return ErrUnresolved.Error() }
func (e *PendingError) Unwrap() error { return ErrUnresolved }

const (
	MaxSegment          = 32
	TargetBytes  int64  = 16 << 20
	RecentWindow uint32 = 1024
)

type Source struct {
	ID                   int64  `json:"id"`
	Revision             int64  `json:"revision"`
	Generation           int64  `json:"generation"`
	CredentialGeneration int64  `json:"credential_generation"`
	Enabled              bool   `json:"enabled"`
	Kind                 string `json:"kind"`
	Namespace            string `json:"namespace"`
	Username             string `json:"username"`
	Host                 string `json:"host"`
	Port                 uint16 `json:"port"`
	AllowWeak            bool   `json:"allow_weak"`
}

type Alias struct {
	ID             int64  `json:"id"`
	Revision       int64  `json:"revision"`
	AuthGeneration int64  `json:"auth_generation"`
	Email          string `json:"email"`
	Lifecycle      string `json:"lifecycle"`
	Enabled        bool   `json:"enabled"`
	Deleted        bool   `json:"deleted"`
	UIDNext        uint64 `json:"uid_next"`
}

type Cursor struct {
	Exists      bool   `json:"exists"`
	UIDValidity uint32 `json:"uid_validity"`
	Committed   uint32 `json:"committed"`
	Observed    uint32 `json:"observed"`
	Revision    int64  `json:"revision"`
}

type Backfill struct {
	AddressID   int64  `json:"address_id"`
	ScanEpoch   int64  `json:"scan_epoch"`
	UIDValidity uint32 `json:"uid_validity"`
	Lower       uint32 `json:"lower"`
	Upper       uint32 `json:"upper"`
	Committed   uint32 `json:"committed"`
	State       string `json:"state"`
}

// Pending is a narrow snapshot projection. Callers rotate PendingAfter across
// runs; each run checks at most 32 old remote UIDs, independently of discovery.
type Pending struct {
	AddressID   int64  `json:"address_id"`
	MessageID   int64  `json:"message_id"`
	Generation  int64  `json:"generation"`
	UIDValidity uint32 `json:"uid_validity"`
	UID         uint32 `json:"uid"`
	SelectedAt  int64  `json:"selected_at"`
}

type Snapshot struct {
	Source   Source    `json:"source"`
	Mailbox  string    `json:"mailbox"`
	Cursor   Cursor    `json:"cursor"`
	Aliases  []Alias   `json:"aliases"`
	Backfill *Backfill `json:"backfill,omitempty"`
	Pending  []Pending `json:"pending"`
}

type InputSnapshot struct {
	Gate     *sourceguard.Lease
	Snapshot Snapshot
	Endpoint upstream.Endpoint // Never persisted in a plan or diagnostic.
	// Zero reuses an unfinished cursor's observed frontier, otherwise captures
	// selected UIDNext-1. A supplied frontier must agree with that continuation.
	CapturedUpper uint32
}

// ReadLease admits no mutation method. The concrete adapter only EXAMINEs and
// PEEKs; a source gate and a global IMAP slot must already be held by the caller.
type ReadLease interface {
	Snapshot() upstream.Snapshot
	Discover(context.Context, upstream.Discovery) (upstream.DiscoveryPage, error)
	Metadata(context.Context, uint32, []uint32) ([]upstream.Metadata, error)
	Headers(context.Context, uint32, []uint32) ([]upstream.Header, error)
	StreamRawBatch(context.Context, uint32, []uint32, func(uint32, io.Reader) error) error
	ValidateSelection(context.Context, uint32) error
	Release()
}

type Acquire func(context.Context, upstream.Endpoint, upstream.Scope, string) (ReadLease, error)

type Result struct {
	BatchKey        string
	Through         uint32
	CapturedUpper   uint32
	Complete        bool
	Messages        int
	Links           int
	Publications    int
	Bytes           int64
	Recovered       bool
	PendingAfter    int64
	TimestampIssues []TimestampIssue
}
type TimestampIssue struct {
	UID  uint32 `json:"uid"`
	Code string `json:"code"`
}

type Resolution string

const (
	Committed    Resolution = "committed"
	NotCommitted Resolution = "not_committed"
	Unknown      Resolution = "unknown"
)

type claim struct {
	UID                uint32             `json:"uid"`
	Identity           blobstore.Identity `json:"identity"`
	PreviousGeneration int64              `json:"previous_generation"`
}

type plan struct {
	BatchKey      string    `json:"batch_key"`
	Snapshot      Snapshot  `json:"snapshot"`
	UIDValidity   uint32    `json:"uid_validity"`
	Upper         uint32    `json:"upper"`
	After         uint32    `json:"after"`
	Through       uint32    `json:"through"`
	UIDs          []uint32  `json:"uids"`
	Claims        []claim   `json:"claims"`
	Invalidations []Pending `json:"invalidations"`
	CreatedAt     int64     `json:"created_at"`
}

type checkpoint struct {
	Plan     plan    `json:"plan"`
	Messages []draft `json:"messages"`
}

type recipient struct {
	Role     string `json:"role"`
	Ordinal  int    `json:"ordinal"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Evidence string `json:"evidence"`
}

type attachment struct {
	Part        string `json:"part"`
	Filename    string `json:"filename"`
	MediaType   string `json:"media_type"`
	ContentID   string `json:"content_id"`
	Disposition string `json:"disposition"`
	Inline      bool   `json:"inline"`
	Size        int64  `json:"byte_size"`
	Complete    bool   `json:"complete"`
}

type mailbox struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}

type banFact struct {
	AddressID  int64  `json:"address_id"`
	Detail     string `json:"detail"`
	DetectedAt int64  `json:"detected_at"`
}

// draft contains one source view, regardless of the number of matched aliases.
// Attachment bytes and raw bodies never enter this retained batch structure.
type draft struct {
	UID              uint32                     `json:"uid"`
	ExistingID       int64                      `json:"existing_id"`
	Size             int64                      `json:"size"`
	ReceivedAt       int64                      `json:"received_at"`
	SentAt           *int64                     `json:"sent_at"`
	Seen             bool                       `json:"seen"`
	Header           []byte                     `json:"header"`
	HeaderComplete   bool                       `json:"header_complete"`
	State            string                     `json:"state"`
	MessageID        string                     `json:"message_id"`
	Subject          string                     `json:"subject"`
	From             []mailbox                  `json:"from"`
	To               []mailbox                  `json:"to"`
	CC               []mailbox                  `json:"cc"`
	Text             string                     `json:"text"`
	HTML             string                     `json:"html"`
	BodyComplete     bool                       `json:"body_complete"`
	Attachments      []attachment               `json:"attachments"`
	Recipients       []recipient                `json:"recipients"`
	Codes            []string                   `json:"codes"`
	Code             *string                    `json:"code"`
	Links            []int64                    `json:"links"`
	Receipt          *blobstore.Receipt         `json:"receipt,omitempty"`
	ObjectKey        string                     `json:"object_key"`
	ObjectState      string                     `json:"object_state"`
	ObjectGeneration int64                      `json:"object_generation"`
	ExpectedSize     int64                      `json:"expected_size"`
	ExpectedSHA      string                     `json:"expected_sha"`
	Evidence         *content.RecipientEvidence `json:"-"`
	Ban              *banFact                   `json:"ban,omitempty"`
	PublishedAt      int64                      `json:"published_at"`
	TimestampIssue   string                     `json:"timestamp_issue,omitempty"`
}

type messageFact struct {
	UID       uint32 `json:"uid"`
	ID        int64  `json:"id"`
	ObjectKey string `json:"object_key"`
}
type entryFact struct {
	AddressID int64  `json:"address_id"`
	MessageID int64  `json:"message_id"`
	ID        int64  `json:"id"`
	UID       uint64 `json:"uid"`
}
type facts struct {
	Messages        []messageFact       `json:"messages"`
	Entries         []entryFact         `json:"entries"`
	Publications    []blobstore.Receipt `json:"publications"`
	Through         uint32              `json:"through"`
	Evidence        []evidenceFact      `json:"evidence"`
	TimestampIssues []TimestampIssue    `json:"timestamp_issues"`
}
type evidenceFact struct {
	AddressID  int64  `json:"address_id"`
	MessageID  *int64 `json:"message_id"`
	DetectedAt int64  `json:"detected_at"`
}
type record struct {
	Intent plan   `json:"intent"`
	Facts  *facts `json:"facts,omitempty"`
}

func digest(value any) ([]byte, []byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(b)
	return b, h[:], nil
}

func token() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func instant(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	n, err := requiredInstant(t)
	if err != nil {
		return nil
	}
	return &n
}

// UnixNano alone wraps outside 1677-09-21T00:12:43.145224192Z through
// 2262-04-11T23:47:16.854775807Z. Reconstructing the same instant admits both
// signed endpoints without depending on the source's timezone.
func requiredInstant(t time.Time) (int64, error) {
	n := t.UnixNano()
	if !time.Unix(0, n).Equal(t) {
		return 0, ErrTimestampRange
	}
	return n, nil
}
