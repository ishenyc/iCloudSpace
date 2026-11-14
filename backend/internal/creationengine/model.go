// Package creationengine owns finite automatic address plans and their durable
// single-attempt claims. It never retries a provider mutation or rotates keys.
package creationengine

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"icloudspace/internal/addresses"
	"icloudspace/internal/sourceguard"
)

var (
	ErrInvalid      = errors.New("creationengine: invalid input")
	ErrNotFound     = errors.New("creationengine: resource absent")
	ErrConflict     = errors.New("creationengine: policy changed")
	ErrIneligible   = errors.New("creationengine: source is ineligible")
	ErrCapacity     = errors.New("creationengine: configured address maximum reached")
	ErrReadOnly     = errors.New("creationengine: installation writes disabled")
	ErrInstallation = errors.New("creationengine: installation identity mismatch")
	ErrStorage      = errors.New("creationengine: storage failed")
	ErrUnknown      = errors.New("creationengine: acknowledgement unknown; query original attempt")
	ErrUnresolved   = errors.New("creationengine: original attempt requires resolution")
	ErrNotDue       = errors.New("creationengine: no eligible due slot")
)

const (
	MaximumAttempts   = 5
	MinimumInterval   = 5 * time.Minute
	RoundDuration     = time.Hour
	RateLimitCooldown = 61 * time.Minute
)

type Random func(upper int64) (int64, error)
type Creator interface {
	CreateHME(context.Context, addresses.HMECreateInput, addresses.Provider) (addresses.Operation, error)
}
type Options struct {
	Clock             func() int64
	Random            Random
	Workers           int
	PollInterval      time.Duration
	OperationTimeout  time.Duration
	OverdueGrace      time.Duration
	CredentialProfile string
	Logger            *slog.Logger
}
type Settings struct {
	MaximumAddresses int
	AttemptsPerRound int
}
type Policy struct {
	SourceID, Revision                              int64
	Enabled                                         bool
	ScheduleKind                                    string
	IntervalMilliseconds                            *int64
	MaximumAddresses, AttemptsPerRound              int
	CooldownUntil, LastAttemptedAt, LastConfirmedAt *int64
	PausedReason, LastAddress, LastErrorDetail      string
	CreatedAt, UpdatedAt                            int64
	Slots                                           []Slot
	PendingAttempt                                  *Attempt
}
type Slot struct {
	SourceID, PolicyRevision, ScheduledFor int64
	State                                  string
}
type Attempt struct {
	ID, SourceID, PolicyRevision, ScheduledFor int64
	Ordinal                                    int
	State, OwnerKey, OperationKey, ErrorCode   string
	ClaimedAt, FinishedAt                      *int64
	CreatedAt                                  int64
	OperationState                             string
	AddressID                                  *int64
}

func (Attempt) String() string   { return "creationengine: private attempt metadata" }
func (Attempt) GoString() string { return "creationengine: private attempt metadata" }

type Engine struct {
	db           *sql.DB
	installation string
	guards       *sourceguard.Registry
	creator      Creator
	provider     func(int64) addresses.Provider
	options      Options
	randomMu     sync.Mutex
	mu           sync.Mutex
	active       map[int64]bool
	after        int64
	wake         chan struct{}
	running      atomic.Bool
}
