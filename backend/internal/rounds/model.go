// Package rounds coordinates bounded source synchronization rounds. Business
// operations, MIME, provider sessions and consume/Seen mutations remain outside.
package rounds

import (
	"context"
	"errors"
	"time"

	"icloudspace/internal/sourceguard"
)

var (
	ErrInvalid        = errors.New("rounds: invalid configuration or input")
	ErrCapacity       = errors.New("rounds: source capacity exceeded")
	ErrClosed         = errors.New("rounds: admission closed")
	ErrStale          = errors.New("rounds: source scope changed")
	ErrUnknown        = errors.New("rounds: terminal persistence unknown")
	ErrNotRecorded    = errors.New("rounds: terminal not recorded")
	ErrTimestampRange = errors.New("rounds: timestamp outside signed nanosecond range")
	ErrClockOrder     = errors.New("rounds: terminal clock has not advanced")
)

type Trigger string

const (
	Automatic Trigger = "automatic"
	Manual    Trigger = "manual"
	Public    Trigger = "public"
)

type Phase string

const (
	Directory Phase = "directory"
	Mail      Phase = "mail"
	Finalize  Phase = "finalize"
	Resolve   Phase = "resolve"
)

type Outcome string

const (
	Succeeded  Outcome = "succeeded"
	Degraded   Outcome = "degraded"
	Failed     Outcome = "failed"
	Cancelled  Outcome = "cancelled"
	Superseded Outcome = "superseded"
	Unknown    Outcome = "unknown"
)

type State string

const (
	Queued   State = "queued"
	Running  State = "running"
	Waiting  State = "waiting"
	Finished State = "finished"
)

type Scope struct {
	SourceID              int64
	Revision              int64
	Generation            int64
	CredentialGeneration  int64
	ConfigurationRevision int64
}
type Source struct {
	Scope          Scope
	Enabled        bool
	HasDirectory   bool
	RestInterval   time.Duration
	AutomaticAfter *int64
	LastTerminal   *int64
}

type MailFrontier struct {
	UIDValidity   uint32
	CapturedUpper uint32
	Committed     uint32
	Backfill      *BackfillFrontier
}

// Backfills are distinct streams, never a substitute for the source cursor.
// Completed streams advance by address ID (then epoch for the same address).
type BackfillFrontier struct {
	AddressID     int64
	ScanEpoch     int64
	UIDValidity   uint32
	CapturedUpper uint32
	Committed     uint32
}
type Counters struct {
	Discovered, Archived, Links int64
	Bytes                       int64
}
type Problem struct {
	Code      string
	Retryable bool
	// Uncertain forbids retry, regardless of Retryable. The executor retains
	// its own durable mutation/request identifiers and query-only recovery.
	Uncertain bool
}
type StepState string

const (
	StepComplete StepState = "complete"
	StepPending  StepState = "pending"
	StepFailed   StepState = "failed"
)

type StepInput struct {
	Source   Source
	RoundID  string
	Trigger  Trigger
	Phase    Phase
	Attempt  int
	Frontier *MailFrontier
	Gate     *sourceguard.Lease
	// Non-nil only for Mail, already acquired after Gate. The executor owns
	// its read-pool lease; the coordinator returns this permit after Step.
	IMAPSlot *Permit
}
type StepResult struct {
	State    StepState
	Frontier *MailFrontier
	Counters Counters
	Problem  Problem
}
type Executor interface {
	Step(context.Context, StepInput) (StepResult, error)
}
type ExecutorFunc func(context.Context, StepInput) (StepResult, error)

func (f ExecutorFunc) Step(c context.Context, i StepInput) (StepResult, error) { return f(c, i) }

type Terminal struct {
	Source             Source
	RoundID            string
	Trigger            Trigger
	Outcome            Outcome
	ErrorCode          string
	DirectoryErrorCode string
	At                 int64
	AutomaticAfter     *int64
	MailComplete       bool
}
type Resolution string

const (
	Recorded    Resolution = "recorded"
	NotRecorded Resolution = "not_recorded"
	Unresolved  Resolution = "unknown"
)

type Repository interface {
	LoadCatalog(context.Context, int) ([]Source, error)
	CurrentSource(context.Context, int64) (Source, error)
	RecordTerminal(context.Context, *sourceguard.Lease, Terminal) error
	ResolveTerminal(context.Context, *sourceguard.Lease, Terminal) (Resolution, error)
}

type Progress struct {
	Source             Scope
	RoundID            string
	Trigger            Trigger
	Phase              Phase
	State              State
	Outcome            Outcome
	QueuedAt           int64
	StartedAt          int64
	FinishedAt         int64
	ReadyAt            int64
	Attempts           int
	FailedAttempts     int
	Segments           int
	Retries            int
	AdmissionWaits     int
	AdmissionErrors    int
	ActiveTime         time.Duration
	Recovered          bool
	ErrorCode          string
	DirectoryErrorCode string
	Frontier           *MailFrontier
	Counters           Counters
	WaitingManual      bool
}
type Event struct {
	Sequence uint64
	At       int64
	Level    string
	Scope    string
	Name     string
	Outcome  string
	Progress Progress
}
type Events struct {
	Items        []Event
	Lost         uint64
	LastSequence uint64
}
type Disposition string

const (
	WakeQueued    Disposition = "queued"
	WakeCoalesced Disposition = "coalesced"
	WakeThrottled Disposition = "throttled"
	WakeDisabled  Disposition = "disabled"
	WakeUnknown   Disposition = "unknown_source"
	WakeClosed    Disposition = "closed"
)

type WakeResult struct {
	Disposition Disposition
	RoundID     string
	RetryAt     int64
	FollowUp    bool
}

type Timer interface {
	C() <-chan time.Time
	Stop()
}
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}
type realClock struct{}

func (realClock) Now() time.Time                 { return time.Now() }
func (realClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.Timer.C }
func (t realTimer) Stop() {
	if !t.Timer.Stop() {
		select {
		case <-t.Timer.C:
		default:
		}
	}
}

type Config struct {
	Workers          int
	MaxSources       int
	EventCapacity    int
	StepTimeout      time.Duration
	RoundTimeout     time.Duration // Zero leaves the aggregate active time uncapped; each step remains bounded.
	AdmissionTimeout time.Duration
	AdmissionRetry   time.Duration
	StoreTimeout     time.Duration
	ReloadInterval   time.Duration
	RetryDelay       time.Duration
	MaxRetries       int // Zero selects two; only explicitly Retryable steps retry.
	PublicInterval   time.Duration
	// A directory failure remains a real recorded error when mail succeeds.
	AllowDegradedDirectory bool
	Clock                  Clock
}

func ns(t time.Time) (int64, error) {
	n := t.UnixNano()
	if !time.Unix(0, n).Equal(t) {
		return 0, ErrTimestampRange
	}
	return n, nil
}
func copied(s Source) Source {
	s.AutomaticAfter = copyNS(s.AutomaticAfter)
	s.LastTerminal = copyNS(s.LastTerminal)
	return s
}
func copyNS(n *int64) *int64 {
	if n == nil {
		return nil
	}
	v := *n
	return &v
}
func copyFrontier(v *MailFrontier) *MailFrontier {
	if v == nil {
		return nil
	}
	c := *v
	if v.Backfill != nil {
		backfill := *v.Backfill
		c.Backfill = &backfill
	}
	return &c
}
func copyProgress(p Progress) Progress { p.Frontier = copyFrontier(p.Frontier); return p }
func validScope(s Scope) bool {
	return s.SourceID > 0 && s.Revision > 0 && s.Generation > 0 && s.CredentialGeneration > 0 && s.ConfigurationRevision > 0
}
