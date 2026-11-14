// Package mailout owns one explicit, provider-neutral mail submission and its
// durable local owner. It has no transport authentication or automatic retry.
package mailout

import (
	"context"
	"errors"
	"icloudspace/internal/content"
	"icloudspace/internal/sourceguard"
	"io"
	"time"
)

var (
	ErrInvalid    = errors.New("mailout: invalid request")
	ErrIneligible = errors.New("mailout: address cannot send")
	ErrConflict   = errors.New("mailout: request conflicts with its durable owner")
	ErrNotFound   = errors.New("mailout: operation not found")
	ErrStorage    = errors.New("mailout: storage operation failed")
	ErrUnknown    = errors.New("mailout: acknowledgement unknown; query original operation")
	ErrReference  = errors.New("mailout: reference not ready")
	ErrProvider   = errors.New("mailout: provider proof rejected")
	ErrReadOnly   = errors.New("mailout: installation writes disabled")
	ErrBudget     = errors.New("mailout: explicit bootstrap budget required")
)

type Outcome string

const (
	Accepted Outcome = "accepted"
	Rejected Outcome = "rejected"
	NotSent  Outcome = "not_sent"
	Unknown  Outcome = "unknown"
)

type Request struct {
	Key       string
	AddressID int64
	Draft     content.Draft
}

func (Request) String() string   { return "mailout: private mail request" }
func (Request) GoString() string { return "mailout: private mail request" }

type Result struct {
	Key                string        `json:"key"`
	AddressID          int64         `json:"address_id,string"`
	State              string        `json:"state"`
	Outcome            Outcome       `json:"outcome"`
	QueryOnly          bool          `json:"query_only"`
	Durable            bool          `json:"durable"`
	ContextKey         string        `json:"context_key,omitempty"`
	RPCID              string        `json:"rpc_id,omitempty"`
	ReferenceID        string        `json:"reference_id,omitempty"`
	ReferenceKind      ReferenceKind `json:"reference_kind,omitempty"`
	UpstreamID         string        `json:"upstream_id,omitempty"`
	Code               string        `json:"code"`
	FingerprintVersion string        `json:"fingerprint_version"`
	RouteOutcome       *Outcome      `json:"route_outcome,omitempty"`
	Retryable          bool          `json:"retryable"`
	Diagnostic         *Diagnostic   `json:"diagnostic,omitempty"`
}

// Diagnostic contains allowlisted protocol facts, never provider response text.
type Diagnostic struct {
	Stage           string `json:"stage"`
	Kind            string `json:"kind,omitempty"`
	HTTPStatus      int    `json:"http_status,omitempty"`
	ProviderCode    string `json:"provider_code,omitempty"`
	Operation       string `json:"operation,omitempty"`
	Attempts        int    `json:"attempts,omitempty"`
	TransportPhase  string `json:"transport_phase,omitempty"`
	TransportReason string `json:"transport_reason,omitempty"`
}

func (Result) String() string   { return "mailout: submission result" }
func (Result) GoString() string { return "mailout: submission result" }

type Preview struct {
	Text        string `json:"text"`
	HTML        string `json:"html"`
	Attachments int    `json:"attachments"`
}

func (Preview) String() string   { return "mailout: private preview" }
func (Preview) GoString() string { return "mailout: private preview" }

type Source struct {
	ID, Revision, Generation, CredentialGeneration, PrincipalRevision int64
	Kind, PrimaryAddress                                              string
}
type Address struct {
	ID, Revision                     int64
	Email, ProviderID, ProviderOwner string
}

// RemoteHint is a locally observed Apple INBOX coordinate, not a reference
// proof. The provider must independently verify its current mailbox epoch and
// the remote message before using it for submission.
type RemoteHint struct {
	UIDValidity, UID uint32
}

type ArchiveHint struct {
	ID               int64
	Header           []byte
	UIDValidity, UID uint32
}

type Scope struct {
	Source       Source
	Address      Address
	Gate         *sourceguard.Lease
	RemoteHints  []RemoteHint
	ArchiveHints []ArchiveHint
}

func (Scope) String() string   { return "mailout: private source scope" }
func (Scope) GoString() string { return "mailout: private source scope" }

// Route and Reference are observed by the provider operation, never supplied
// by a public request. The adapter owns Apple's actual From/relay wire rules.
type Route struct {
	SourceID, AddressID                                               int64
	Alias, Recipient, PrimaryAddress, ProviderAddressID, ProviderFrom string
	OwnerVerified, Active                                             bool
	CheckedAt                                                         int64
}
type Evidence struct {
	ContextKey           string       `json:"context_key"`
	OwnerKey             string       `json:"owner_key"`
	Nonce                string       `json:"nonce"`
	Recipient            string       `json:"recipient"`
	FingerprintScheme    string       `json:"fingerprint_scheme"`
	Fingerprint          []byte       `json:"-"`
	QueryOnly            bool         `json:"query_only"`
	State                string       `json:"state"`
	CandidateID          string       `json:"candidate_id,omitempty"`
	CandidateMessageID   string       `json:"candidate_message_id,omitempty"`
	CandidateUIDValidity uint32       `json:"candidate_uid_validity,omitempty"`
	SeedID               string       `json:"seed_id,omitempty"`
	SeedMessageID        string       `json:"seed_message_id,omitempty"`
	ReferenceID          string       `json:"reference_id,omitempty"`
	AppendOutcome        *Outcome     `json:"append_outcome,omitempty"`
	SeedOutcome          *Outcome     `json:"seed_outcome,omitempty"`
	Draft                *DraftIntent `json:"draft,omitempty"`
}

func (Evidence) String() string   { return "mailout: private compose evidence" }
func (Evidence) GoString() string { return "mailout: private compose evidence" }

type Reference struct {
	Kind                 ReferenceKind `json:"kind"`
	ContextKey           string        `json:"context_key"`
	OwnerKey             string        `json:"owner_key"`
	Nonce                string        `json:"nonce"`
	CandidateID          string        `json:"candidate_id,omitempty"`
	SeedID               string        `json:"seed_id,omitempty"`
	ID                   string        `json:"id"`
	MessageID            string        `json:"message_id"`
	Subject              string        `json:"subject"`
	Alias                string        `json:"alias"`
	Recipient            string        `json:"recipient"`
	CandidateUIDValidity uint32        `json:"candidate_uid_validity,omitempty"`
	UIDValidity          uint32        `json:"uid_validity,omitempty"`
	UID                  uint32        `json:"uid,omitempty"`
	CheckedAt            int64         `json:"checked_at,string"`
	Relay                string        `json:"relay,omitempty"`
}
type ReferenceKind string

const (
	IncomingReference ReferenceKind = "incoming"
	SeedReference     ReferenceKind = "bootstrap_seed"
	RouteReference    ReferenceKind = "hme_route"
)

func (Reference) String() string   { return "mailout: private provider reference" }
func (Reference) GoString() string { return "mailout: private provider reference" }

type Candidate struct {
	ID, MessageID, Nonce string
	UIDValidity, UID     uint32
}
type DraftIntent struct {
	From    string `json:"from"`
	To      string `json:"to"`
	ReplyTo string `json:"reply_to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
}
type BootstrapPlan struct {
	ContextKey, OwnerKey, Nonce, RPCID string
	Draft                              DraftIntent
}
type RPCReceipt struct {
	Outcome           Outcome
	RPCID, UpstreamID string
	Matched           bool
	ObservedMessageID string
}
type RouteReceipt struct {
	Outcome Outcome
	Matched bool
}
type AppendReceipt struct {
	Outcome   Outcome
	Candidate Candidate
	Matched   bool
	Verified  bool
}
type Upload struct {
	Filename, MediaType, LogicalCID string
	Inline                          bool
	ByteSize                        int64
	SHA256                          [32]byte
	Body                            io.Reader
}

func (Upload) String() string   { return "mailout: private upload stream" }
func (Upload) GoString() string { return "mailout: private upload stream" }

type Uploaded struct {
	ID, Filename, MediaType, ContentID string
	URL                                string
	ByteSize                           int64
	SHA256                             [32]byte
	Inline                             bool
	LogicalCID                         string
}
type Submission struct {
	Key, OwnerKey, RPCID           string
	Route                          Route
	Reference                      Reference
	Recipient, Subject, Text, HTML string
	Attachments                    []Uploaded
}

func (Submission) String() string   { return "mailout: private immutable submission" }
func (Submission) GoString() string { return "mailout: private immutable submission" }

// Open returns one operation/session jar. Every method uses that same operation
// until Close. Mutating methods perform one attempt: no retries or redirects.
// ReadReference is read-only and honors its context deadline (at most 30s).
type Provider interface {
	Open(context.Context, Scope) (Operation, error)
}
type Operation interface {
	ValidateRoute(context.Context, string) (Route, error)
	ResolveRoute(context.Context, Route, Reference) (RouteReceipt, error)
	ReadReference(context.Context, Route, Evidence) (Reference, bool, error)
	FindCandidate(context.Context, Route, Evidence) (Candidate, bool, error)
	AppendDraft(context.Context, Route, BootstrapPlan) (AppendReceipt, error)
	SubmitSeed(context.Context, Route, Candidate, BootstrapPlan) (RPCReceipt, error)
	Upload(context.Context, Route, Reference, Upload) (Uploaded, error)
	Submit(context.Context, Submission) (RPCReceipt, error)
	Close() error
}
type BootstrapStage string

const (
	AppendStage BootstrapStage = "append"
	SeedStage   BootstrapStage = "seed"
)

type Options struct {
	Clock              func() int64
	AuthorizeBootstrap func(context.Context, Scope, string, BootstrapStage) error
	ReferenceWait      time.Duration
}
type ContextRequest struct {
	Key       string
	AddressID int64
	Recipient string
	Bootstrap bool
}
type ContextStatus struct {
	Evidence   Evidence    `json:"evidence"`
	Ready      bool        `json:"ready"`
	ReadOnly   bool        `json:"query_only"`
	Reference  *Reference  `json:"reference,omitempty"`
	Code       string      `json:"code"`
	Diagnostic *Diagnostic `json:"diagnostic,omitempty"`
}
