package seenworker

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"icloudspace/internal/pgschema"
	"icloudspace/internal/rounds"
	"icloudspace/internal/sourceguard"
	"icloudspace/internal/vault"
)

type Service struct {
	db                                             *sql.DB
	installation                                   string
	box                                            *vault.Vault
	guards                                         *sourceguard.Registry
	slots                                          *rounds.Slots
	options                                        Options
	open                                           OpenFunc
	worker                                         chan struct{}
	running                                        atomic.Bool
	ctx                                            context.Context
	cancel                                         context.CancelFunc
	mu                                             sync.Mutex
	closed                                         bool
	work                                           sync.WaitGroup
	commit                                         func(*sql.Tx) error
	discoveryBudget, admissionBudget, sourceBudget time.Duration
}

func New(ctx context.Context, db *sql.DB, installation string, box *vault.Vault, guards *sourceguard.Registry, slots *rounds.Slots, options Options) (*Service, error) {
	if db == nil || box == nil || guards == nil || slots == nil || installation == "" || options.BatchSize < 0 || options.BatchSize > 32 || options.Interval < 0 || options.Backoff < 0 || options.MaxBackoff < 0 || options.QueryDelay < 0 {
		return nil, ErrInvalid
	}
	if pgschema.Check(ctx, db) != nil {
		return nil, ErrStorage
	}
	var actual string
	var proof []byte
	if db.QueryRowContext(ctx, `SELECT i.installation_id,k.proof FROM space.installation i JOIN space.key_binding k ON k.singleton=i.singleton WHERE i.singleton`).Scan(&actual, &proof) != nil {
		return nil, ErrStorage
	}
	expected, e := box.Fingerprint(installation)
	if e != nil || actual != installation || len(proof) != len(expected) || subtle.ConstantTimeCompare(proof, expected[:]) != 1 {
		return nil, ErrCredentials
	}
	if options.BatchSize == 0 {
		options.BatchSize = 16
	}
	if options.Interval == 0 {
		options.Interval = time.Second
	}
	if options.Backoff == 0 {
		options.Backoff = 5 * time.Second
	}
	if options.MaxBackoff == 0 {
		options.MaxBackoff = 5 * time.Minute
	}
	if options.QueryDelay == 0 {
		options.QueryDelay = 30 * time.Second
	}
	if options.MaxBackoff < options.Backoff {
		return nil, ErrInvalid
	}
	if options.Clock == nil {
		options.Clock = func() int64 { return time.Now().UnixNano() }
	}
	open := options.Open
	if open == nil {
		open, e = NewWriter(guards, slots, options.Writer)
		if e != nil {
			return nil, e
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &Service{db: db, installation: installation, box: box, guards: guards, slots: slots, options: options, open: open, worker: make(chan struct{}, 1), ctx: lifetime, cancel: cancel, commit: (*sql.Tx).Commit, discoveryBudget: time.Second, admissionBudget: 250 * time.Millisecond, sourceBudget: time.Minute}, nil
}
func validIdentity(id Identity) bool {
	return id.SourceID > 0 && id.SourceGeneration > 0 && id.UIDValidity > 0 && id.UID > 0 && id.Mailbox != "" && len(id.Mailbox) <= 1024 && utf8.ValidString(id.Mailbox) && !strings.ContainsAny(id.Mailbox, "\r\n\x00")
}
func storage(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrStorage
}
func (s *Service) begin(ctx context.Context) (context.Context, func(), error) {
	if s == nil {
		return nil, nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, ErrClosed
	}
	s.work.Add(1)
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	return operation, func() { stop(); cancel(); s.work.Done() }, nil
}
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.work.Wait()
	return nil
}
func (s *Service) Run(ctx context.Context) error {
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	if !s.running.CompareAndSwap(false, true) {
		return ErrBusy
	}
	defer s.running.Store(false)
	// One supervisor owns the bounded source queue. Standalone Step remains
	// exclusive with Run, rather than creating a second hidden scheduler.
	select {
	case s.worker <- struct{}{}:
		defer func() { <-s.worker }()
	default:
		return ErrBusy
	}
	return s.runSources(ctx)
}
func (s *Service) Step(ctx context.Context) (Result, error) {
	var result Result
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return result, e
	}
	defer done()
	select {
	case s.worker <- struct{}{}:
		defer func() { <-s.worker }()
	case <-ctx.Done():
		return result, ctx.Err()
	default:
		return result, ErrBusy
	}
	discovery, cancel := context.WithTimeout(ctx, s.discoveryBudget)
	jobs, e := s.due(discovery)
	cancel()
	if e != nil {
		return result, e
	}
	for _, job := range jobs {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		result.Visited++
		if e = s.process(ctx, job, &result); e != nil {
			if errors.Is(e, errAdmissionUnavailable) {
				result.Deferred++
				continue
			}
			return result, e
		}
	}
	return result, nil
}
func add(now int64, duration time.Duration) int64 {
	if now > math.MaxInt64-int64(duration) {
		return math.MaxInt64
	}
	return now + int64(duration)
}
func (s *Service) retryAt(attempts int32) int64 {
	delay := s.options.Backoff
	for i := int32(0); i < attempts && delay < s.options.MaxBackoff; i++ {
		if delay > s.options.MaxBackoff/2 {
			delay = s.options.MaxBackoff
		} else {
			delay *= 2
		}
	}
	return add(s.options.Clock(), delay)
}
