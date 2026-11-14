package httpapi

import (
	"errors"
	"strconv"
	"time"

	"icloudspace/internal/mailview"
)

type remoteMailView struct {
	SourceGeneration string `json:"source_generation"`
	Mailbox          string `json:"mailbox"`
	UIDValidity      uint32 `json:"uid_validity"`
	UID              uint32 `json:"uid"`
}

func presentRemote(value mailview.Remote) remoteMailView {
	return remoteMailView{decimal(value.SourceGeneration), value.Mailbox, value.UIDValidity, value.UID}
}

type mailMetadataView struct {
	EntryID               *string            `json:"entry_id"`
	MessageID             string             `json:"message_id"`
	UID                   *uint32            `json:"uid"`
	Remote                remoteMailView     `json:"remote"`
	RFCMessageID          string             `json:"rfc_message_id"`
	Subject               string             `json:"subject"`
	From                  []mailview.Mailbox `json:"from"`
	To                    []mailview.Mailbox `json:"to"`
	CC                    []mailview.Mailbox `json:"cc"`
	SentAt                *string            `json:"sent_at"`
	ReceivedAt            string             `json:"received_at"`
	VisibleAt             *string            `json:"visible_at"`
	Seen                  bool               `json:"seen"`
	ContentState          string             `json:"content_state"`
	RawState              string             `json:"raw_state"`
	DeclaredBodySize      string             `json:"declared_body_size"`
	DeclaredBodyTruncated bool               `json:"declared_body_truncated"`
	Preview               string             `json:"preview"`
}

func presentMailMetadata(value mailview.Metadata) mailMetadataView {
	view := mailMetadataView{MessageID: decimal(value.MessageID), Remote: presentRemote(value.Remote),
		RFCMessageID: value.RFCMessageID, Subject: value.Subject,
		From: append([]mailview.Mailbox{}, value.From...), To: append([]mailview.Mailbox{}, value.To...), CC: append([]mailview.Mailbox{}, value.CC...),
		SentAt: optionalInstant(value.SentAt), ReceivedAt: instant(value.ReceivedAt), ContentState: value.ContentState,
		RawState: value.RawState, DeclaredBodySize: decimal(value.DeclaredBodySize), DeclaredBodyTruncated: value.DeclaredBodyTruncated, Preview: value.Preview, Seen: value.Seen}
	if value.EntryID > 0 {
		view.EntryID = optionalDecimal(&value.EntryID)
		uid := value.UID
		view.UID = &uid
		view.VisibleAt = optionalInstant(&value.VisibleAt)
	}
	return view
}

type mailMessageView struct {
	Metadata     mailMetadataView     `json:"metadata"`
	Text         string               `json:"text"`
	HTML         string               `json:"html"`
	Attachments  []mailAttachmentView `json:"attachments"`
	BodyComplete bool                 `json:"body_complete"`
}
type mailAttachmentView struct {
	Part        string `json:"part"`
	Filename    string `json:"filename"`
	MediaType   string `json:"media_type"`
	Disposition string `json:"disposition"`
	ContentID   string `json:"content_id"`
	Inline      bool   `json:"inline"`
	ByteSize    string `json:"byte_size"`
	Complete    bool   `json:"complete"`
}

func presentMailMessage(value mailview.Message) mailMessageView {
	view := mailMessageView{Metadata: presentMailMetadata(value.Metadata), Text: value.Text, HTML: value.HTML, BodyComplete: value.BodyComplete, Attachments: []mailAttachmentView{}}
	for _, part := range value.Attachments {
		view.Attachments = append(view.Attachments, mailAttachmentView{part.Part, part.Filename, part.MediaType, part.Disposition, part.ContentID, part.Inline, decimal(part.ByteSize), part.Complete})
	}
	return view
}

// Snapshot references carry exact immutable/CAS facts. They are not authority:
// the request separately supplies a purpose-bound credential for consumption.
type mailSnapshotReference struct {
	AuthGeneration     string         `json:"auth_generation"`
	MessageID          string         `json:"message_id"`
	EntryID            *string        `json:"entry_id"`
	UID                *uint32        `json:"uid"`
	UIDValidity        string         `json:"uid_validity"`
	ViewKey            string         `json:"view_key"`
	ViewScopeAddressID *string        `json:"view_scope_address_id"`
	SelectedAt         string         `json:"selected_at"`
	Remote             remoteMailView `json:"remote"`
}

func presentSnapshotReference(value mailview.SnapshotRef) mailSnapshotReference {
	view := mailSnapshotReference{AuthGeneration: decimal(value.AuthGeneration), MessageID: decimal(value.MessageID), UIDValidity: decimal(value.LocalUIDValidity), ViewKey: value.ViewKey, SelectedAt: instant(value.SelectedAt), Remote: presentRemote(value.Remote)}
	if value.EntryID > 0 {
		view.EntryID = optionalDecimal(&value.EntryID)
		uid := value.LocalUID
		view.UID = &uid
	}
	if value.ViewScopeAddressID > 0 {
		view.ViewScopeAddressID = optionalDecimal(&value.ViewScopeAddressID)
	}
	return view
}

type mailSnapshotView struct {
	Reference mailSnapshotReference `json:"reference"`
	Message   mailMessageView       `json:"message"`
	Consumed  bool                  `json:"consumed"`
}

func presentMailSnapshot(value mailview.Snapshot) mailSnapshotView {
	return mailSnapshotView{presentSnapshotReference(value.Ref), presentMailMessage(value.Message), value.Consumed}
}

func exactInstant(value string) (int64, error) {
	stamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0, mailview.ErrInvalid
	}
	ns := stamp.UnixNano()
	if !stamp.Equal(time.Unix(0, ns)) {
		return 0, mailview.ErrInvalid
	}
	return ns, nil
}
func (value mailSnapshotReference) reference() (mailview.SnapshotRef, error) {
	var result mailview.SnapshotRef
	var ok bool
	if result.AuthGeneration, ok = positiveDecimal(value.AuthGeneration); !ok {
		return result, mailview.ErrInvalid
	}
	if result.MessageID, ok = positiveDecimal(value.MessageID); !ok {
		return result, mailview.ErrInvalid
	}
	if result.LocalUIDValidity, ok = positiveDecimal(value.UIDValidity); !ok || result.LocalUIDValidity > 4294967295 {
		return result, mailview.ErrInvalid
	}
	if (value.EntryID == nil) != (value.UID == nil) {
		return result, mailview.ErrInvalid
	}
	if value.EntryID != nil {
		if result.EntryID, ok = positiveDecimal(*value.EntryID); !ok || *value.UID == 0 {
			return result, mailview.ErrInvalid
		}
		result.LocalUID = *value.UID
	}
	if value.ViewScopeAddressID != nil {
		if result.ViewScopeAddressID, ok = positiveDecimal(*value.ViewScopeAddressID); !ok {
			return result, mailview.ErrInvalid
		}
	}
	if result.Remote.SourceGeneration, ok = positiveDecimal(value.Remote.SourceGeneration); !ok {
		return result, mailview.ErrInvalid
	}
	var err error
	if result.SelectedAt, err = exactInstant(value.SelectedAt); err != nil {
		return result, err
	}
	result.ViewKey = value.ViewKey
	result.Remote.Mailbox = value.Remote.Mailbox
	result.Remote.UIDValidity = value.Remote.UIDValidity
	result.Remote.UID = value.Remote.UID
	return result, nil
}

type mailClaimInput struct {
	Key       string                `json:"claim_key"`
	Reference mailSnapshotReference `json:"reference"`
}

func (input mailClaimInput) request() (mailview.ClaimRequest, error) {
	reference, err := input.Reference.reference()
	if err != nil {
		return mailview.ClaimRequest{}, err
	}
	return mailview.ClaimRequest{Key: input.Key, Snapshot: reference}, nil
}

type mailClaimView struct {
	Key       string         `json:"claim_key"`
	Committed bool           `json:"committed"`
	Remote    remoteMailView `json:"remote"`
	ClaimedAt string         `json:"claimed_at"`
	Snippet   string         `json:"snippet,omitempty"`
}

func presentClaim(value mailview.ClaimResult) mailClaimView {
	return mailClaimView{value.Key, value.Committed, presentRemote(value.Remote), instant(value.ClaimedAt), value.Snippet}
}

func mailUID(value string) (uint32, error) {
	uid, err := strconv.ParseUint(value, 10, 32)
	if err != nil || uid == 0 || strconv.FormatUint(uid, 10) != value {
		return 0, mailview.ErrInvalid
	}
	return uint32(uid), nil
}

func mailErrorProblem(err error, key string) (int, Problem) {
	status, problem := 500, internalProblem()
	switch {
	case errors.Is(err, mailview.ErrInvalid):
		status, problem = 400, Problem{Kind: "invalid_request", Code: "MAIL_INPUT_INVALID", Message: "Check the mailbox request and exact message reference."}
	case errors.Is(err, mailview.ErrDenied):
		status, problem = 403, Problem{Kind: "authorization", Code: "MAIL_SCOPE_DENIED", Message: "This credential does not authorize the mailbox operation."}
	case errors.Is(err, mailview.ErrNotFound):
		status, problem = 404, Problem{Kind: "not_found", Code: "MAIL_NOT_FOUND", Message: "There is no matching message."}
	case errors.Is(err, mailview.ErrUnavailable):
		status, problem = 410, Problem{Kind: "availability", Code: "MAIL_ORIGINAL_UNAVAILABLE", Message: "The original message bytes are unavailable."}
	case errors.Is(err, mailview.ErrStale):
		status, problem = 409, Problem{Kind: "conflict", Code: "MAIL_REFERENCE_CHANGED", Message: "Refresh the message before an explicit new operation.", Outcome: NotSent}
	case errors.Is(err, mailview.ErrConsumed):
		status, problem = 409, Problem{Kind: "conflict", Code: "MAIL_ALREADY_CONSUMED", Message: "This message has already been consumed.", Outcome: NotSent}
	case errors.Is(err, mailview.ErrReadOnly):
		status, problem = 503, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is currently read-only.", Outcome: NotSent}
	case errors.Is(err, mailview.ErrUnknown):
		status, problem = 503, Problem{Kind: "persistence", Code: "MAIL_CLAIM_UNKNOWN", Message: "Query the original claim using the same reference; do not consume again.", SubmissionKey: key, Outcome: Unknown}
	case errors.Is(err, mailview.ErrBudget), errors.Is(err, mailview.ErrMetadata):
		status, problem = 422, Problem{Kind: "content", Code: "MAIL_CONTENT_UNAVAILABLE", Message: "The stored message projection cannot be presented safely."}
	}
	return status, problem
}
