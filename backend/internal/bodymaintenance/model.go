// Package bodymaintenance owns bounded canonical original-body maintenance.
// It never deletes mail identities, mailbox UIDs, grants or consumption facts.
package bodymaintenance

import (
	"errors"
	"icloudspace/internal/blobstore"
	"time"
)

const DefaultCapacityBytes int64 = 10 << 30
const DefaultBatchSize = 32

var (
	ErrInvalid   = errors.New("bodymaintenance: invalid request")
	ErrStorage   = errors.New("bodymaintenance: storage operation failed")
	ErrReadOnly  = errors.New("bodymaintenance: installation writes disabled")
	ErrStale     = errors.New("bodymaintenance: body generation changed")
	ErrProtected = errors.New("bodymaintenance: unresolved or referenced body is protected")
	ErrUnknown   = errors.New("bodymaintenance: SQL acknowledgement unknown; query required")
	ErrBusy      = errors.New("bodymaintenance: maintenance worker already active")
	ErrEvidence  = errors.New("bodymaintenance: body evidence cannot authorize collection")
)

type Options struct {
	// Zero selects 10GiB. Capacity counts available original bytes globally.
	CapacityBytes int64
	// Each of four phases visits at most BatchSize rows, never a filesystem tree.
	BatchSize int
	Interval  time.Duration
	Clock     func() int64
}
type Reference struct {
	SourceID int64
	Receipt  blobstore.Receipt
}

func (Reference) String() string   { return "bodymaintenance: private body reference" }
func (Reference) GoString() string { return "bodymaintenance: private body reference" }

type Usage struct {
	AvailableBytes string
	CapacityBytes  int64
	OverCapacity   bool
}
type Result struct {
	Before, After                                                         Usage
	Evicted, Collected, Verified, Damaged, Orphans, Protected, Unresolved int
	Recovered                                                             int
}
type CheckResult struct {
	State              string
	Changed, Recovered bool
}
type object struct {
	Reference
	State, PublicationState string
	RetentionOrderAt        int64
}
