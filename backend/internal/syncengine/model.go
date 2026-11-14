// Package syncengine assembles one canonical synchronization step. Rounds owns
// admission, retries, time budgets, fairness and terminal automatic cooldown.
package syncengine

import (
	"context"
	"errors"
	"sync"
	"time"

	"icloudspace/internal/accounts"
	"icloudspace/internal/addresses"
	"icloudspace/internal/intake"
	"icloudspace/internal/providersession"
	"icloudspace/internal/rounds"
	"icloudspace/internal/sourceguard"
)

var (
	ErrInvalid          = errors.New("syncengine: invalid composition or step")
	ErrRecoveryRequired = errors.New("syncengine: intake receipt requires explicit recovery")
	ErrBackfillUnknown  = errors.New("syncengine: backfill registration commit outcome unknown")
)

// Settings is immutable for one configuration revision. The composition root
// may provide a snapshot loader; source passwords never belong in Settings.
type Settings struct {
	Revision                  int64
	Mailbox, DirectoryProfile string
}
type Config struct {
	Registry          *sourceguard.Registry
	Slots             *rounds.Slots
	Accounts          *accounts.Service
	Sessions          *providersession.Service
	Addresses         *addresses.Service
	Intake            *intake.Repository
	Pipeline          *intake.Pipeline
	Rounds            *rounds.Postgres
	Options           func(context.Context, rounds.Source) (Settings, error)
	RecoveryTimeout   time.Duration
	MaxPendingSources int
	Clock             func() time.Time
}
type pendingCursor struct {
	scope rounds.Scope
	after int64
	used  uint64
}
type Executor struct {
	config   Config
	mu       sync.Mutex
	pending  map[int64]pendingCursor
	sequence uint64
}

func New(config Config) (*Executor, error) {
	if config.Registry == nil || config.Slots == nil || config.Accounts == nil || config.Sessions == nil || config.Addresses == nil || config.Intake == nil || config.Pipeline == nil || config.Rounds == nil || config.Intake.Registry != config.Registry || config.Pipeline.Registry != config.Registry || config.Pipeline.Repository != config.Intake || config.Rounds.Registry != config.Registry || config.Rounds.DB != config.Intake.DB {
		return nil, ErrInvalid
	}
	if config.RecoveryTimeout == 0 {
		config.RecoveryTimeout = 3 * time.Second
	}
	if config.RecoveryTimeout < time.Millisecond || config.RecoveryTimeout > time.Minute {
		return nil, ErrInvalid
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaxPendingSources == 0 {
		config.MaxPendingSources = 1024
	}
	if config.MaxPendingSources < 1 || config.MaxPendingSources > 10000 {
		return nil, ErrInvalid
	}
	if config.Options == nil {
		config.Options = func(_ context.Context, source rounds.Source) (Settings, error) {
			return Settings{Revision: source.Scope.ConfigurationRevision, Mailbox: "INBOX", DirectoryProfile: "mailbox"}, nil
		}
	}
	return &Executor{config: config, pending: map[int64]pendingCursor{}}, nil
}
func (e *Executor) pendingAfter(scope rounds.Scope) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	value := e.pending[scope.SourceID]
	if value.scope != scope {
		return 0
	}
	return value.after
}
func (e *Executor) remember(scope rounds.Scope, after int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sequence++
	if _, ok := e.pending[scope.SourceID]; !ok && len(e.pending) >= e.config.MaxPendingSources {
		var oldestID int64
		oldest := ^uint64(0)
		for id, value := range e.pending {
			if value.used < oldest {
				oldestID, oldest = id, value.used
			}
		}
		delete(e.pending, oldestID)
	}
	e.pending[scope.SourceID] = pendingCursor{scope: scope, after: after, used: e.sequence}
}
func failed(err error, code string, retryable, uncertain bool) (rounds.StepResult, error) {
	return rounds.StepResult{State: rounds.StepFailed, Problem: rounds.Problem{Code: code, Retryable: retryable, Uncertain: uncertain}}, err
}

var _ rounds.Executor = (*Executor)(nil)
