// Package localcleanup owns explicit local retirement and bounded original-body
// reclamation. It never issues an upstream operation or guesses its outcome.
package localcleanup

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"icloudspace/internal/blobstore"
	"icloudspace/internal/sourceguard"
)

var (
	ErrInvalid  = errors.New("localcleanup: invalid request")
	ErrConflict = errors.New("localcleanup: identity or request conflict")
	ErrNotFound = errors.New("localcleanup: operation or identity not found")
	ErrStorage  = errors.New("localcleanup: storage unavailable")
	ErrReadOnly = errors.New("localcleanup: writes disabled")
	ErrUnknown  = errors.New("localcleanup: commit acknowledgement unknown; query original operation")
	ErrBusy     = errors.New("localcleanup: worker already active")
	ErrEvidence = errors.New("localcleanup: exact file evidence unavailable")
)

// Fence is the Authority's SourceChangeScope. The root supplies adapters to
// BeginSourceChange and ResolveSourceChange; this owner never owns that gate.
type Fence interface {
	Close() error
	MarkUncertain()
	Resolve(context.Context) error
}
type BeginFence func(context.Context, *sourceguard.Lease) (Fence, error)
type ResolveFence func(context.Context, *sourceguard.Lease) error
type FreshAuthorization func(context.Context, *sql.Tx) error
type Options struct {
	BeginFence   BeginFence
	ResolveFence ResolveFence
	BatchSize    int
	Interval     time.Duration
	Clock        func() int64
}
type SourceDeleteRequest struct {
	OperationKey, OwnerKey, ConfirmNamespace string
	SourceID, ExpectedRevision               int64
}
type AddressPurgeRequest struct {
	OperationKey, OwnerKey, ConfirmAddress string
	AddressID, ExpectedRevision            int64
	ExpectedSourceID                       int64
}
type Receipt struct {
	OperationKey, Kind, State                                  string
	SourceID                                                   int64
	AddressID                                                  *int64
	PayloadScrubbed, InventoryComplete                         bool
	Objects, Collected, Absent, Shared, Protected, NeedsReview int64
	Unacknowledged, UnresolvedOperations                       int64
	LastErrorCode                                              string
}
type Progress struct{ Visited, Collected, Absent, Shared, Protected, NeedsReview int }
type object struct {
	OperationKey string
	SourceID     int64
	Receipt      blobstore.Receipt
	State        string
}

func (object) String() string  { return "localcleanup: private original-body reference" }
func (Receipt) String() string { return "localcleanup: operation receipt" }
