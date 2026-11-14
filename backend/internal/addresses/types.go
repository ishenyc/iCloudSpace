// Package addresses owns canonical address metadata, grouping, reconciliation
// and durable HME lifecycle ownership. Provider JSON never enters this package.
package addresses

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const DefaultLimit = 20
const MaximumLimit = 1000

var (
	ErrInvalid       = errors.New("addresses: invalid input")
	ErrNotFound      = errors.New("addresses: resource not found")
	ErrConflict      = errors.New("addresses: revision or identity conflict")
	ErrIneligible    = errors.New("addresses: address is not eligible")
	ErrReadOnly      = errors.New("addresses: installation writes disabled")
	ErrInstallation  = errors.New("addresses: installation identity mismatch")
	ErrCommitUnknown = errors.New("addresses: commit outcome unknown; query original resource")
	ErrDirectory     = errors.New("addresses: incomplete or mismatched directory")
	ErrProvider      = errors.New("addresses: provider unavailable")
	ErrCapacity      = errors.New("addresses: local enabled capacity exceeded")
)

type FieldError struct{ Field string }

func (e *FieldError) Error() string { return fmt.Sprintf("%s: %s", ErrInvalid, e.Field) }
func (e *FieldError) Unwrap() error { return ErrInvalid }

type Metadata struct {
	ID                   int64
	SourceID             int64
	SourceLabel          string
	SourceKind           string
	Address              string
	Kind                 string
	Label                string
	GroupID              *int64
	Lifecycle            string
	Enabled              bool
	ArchivedAt           *int64
	ArchiveReason        *string
	DeletedAt            *int64
	ProviderID           *string
	ProviderOwner        *string
	ProviderActive       *bool
	ForwardingEmail      *string
	Revision             int64
	AuthGeneration       int64
	UIDValidity          int64
	UIDNext              int64
	HasMail              bool
	CredentialProfile    string
	RegistrationBanned   bool
	RegistrationBannedAt *int64
	LatestReceivedAt     *int64
	Capabilities         []string
	LastSyncState        string
	LastSyncError        string
	LastSyncedAt         *int64
	LastAccessedAt       *int64
	CreatedAt            int64
	UpdatedAt            int64
}

type Filter struct {
	SourceID  *int64
	GroupID   *int64
	Ungrouped bool
	Query     string
	Enabled   *bool
	HasMail   *bool
	Archive   string // all (default), archived, unarchived
}
type Page struct {
	Limit  int
	Offset int64
}
type MetadataPage struct {
	Items  []Metadata
	Total  int64
	Limit  int
	Offset int64
}
type Group struct {
	ID           int64
	Name         string
	Revision     int64
	AddressCount int64
}
type Selection struct {
	ID               int64
	ExpectedRevision int64
}
type GroupChange struct {
	Set bool
	ID  *int64
}
type PatchInput struct {
	ExpectedRevision int64
	Label            *string
	Enabled          *bool
	Group            GroupChange
}
type CreateInput struct {
	SourceID          int64
	Address           string
	Label             string
	GroupID           *int64
	Enabled           bool
	CredentialProfile string
	OwnerKey          string
}
type RandomInput struct {
	SourceID          int64
	Count             int
	Label             string
	GroupID           *int64
	CredentialProfile string
	OwnerKey          string
}

// Issuer participates in the address transaction. A retained encrypted bundle
// never substitutes for grant issuance. A nil issuer rejects creation.
type IssueRequest struct {
	SourceID   int64
	AddressID  int64
	Generation int64
	Profile    string
	OwnerKey   string
}
type Issuer func(context.Context, *sql.Tx, IssueRequest) error

// IssueFactory acquires the credential authority's shared issuance scope before
// any source/address SQL row lock. Close runs after the transaction has ended,
// including a terminal unknown COMMIT result. The root adapts its Authority.
type IssueScope struct {
	Stage Issuer
	Close func()
}
type IssueFactory func(context.Context) (IssueScope, error)

// Directory is a complete, authenticated snapshot of a single Apple subject.
// Complete can be true only after the adapter has rejected pagination, missing
// fields, upstream errors, duplicates and count inconsistencies.
type Directory struct {
	Subject          string
	Complete         bool
	SelectedForward  string
	ForwardAddresses []string
	Entries          []RemoteAddress
}
type RemoteAddress struct {
	ID      string
	Address string
	Forward string
	Active  bool
	Label   string
}
type Candidate struct {
	Address string
	ID      string
}

// Provider has no retry permission. Generate/Reserve/Deactivate/Delete each
// represent exactly one attempt; all recovery routes call Directory only.
type Provider interface {
	Directory(context.Context) (Directory, error)
	Generate(context.Context) (Candidate, error)
	Reserve(context.Context, Candidate, string, string) error
	Deactivate(context.Context, string) error
	Delete(context.Context, string) error
}

// A definite upstream refusal is different from a lost acknowledgement. Only
// the provider can make this assertion from its complete wire response.
type ProviderRejection interface {
	error
	DefinitiveRejection() bool
	FailureCode() string
}

type Reconciliation struct {
	Imported       int
	Existing       int
	Archived       int
	Rediscovered   int
	Active         int
	Inactive       int
	SkippedForward int
	Conflicts      int
	Pending        int
}
type HMECreateInput struct {
	SourceID          int64
	RequestKey        string
	ExpectedRevision  int64
	Label             string
	GroupID           *int64
	OwnerKey          string
	CredentialProfile string
}
type HMEDeleteInput struct {
	AddressID        int64
	RequestKey       string
	ExpectedRevision int64
	ConfirmAddress   string
	OwnerKey         string
}
type Operation struct {
	Key              string
	SourceID         int64
	AddressID        *int64
	Kind             string
	OwnerKey         string
	Nonce            string
	CandidateAddress *string
	CandidateID      *string
	State            string
	ErrorCode        string
	QueryOnly        bool
	CreatedAt        int64
	UpdatedAt        int64
}
