package rounds

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	"icloudspace/internal/sourceguard"
)

type round struct {
	source          Source
	progress        Progress
	next            time.Time
	queued          bool
	consecutive     int
	terminalOutcome Outcome
	terminalCode    string
	mailComplete    bool
	terminal        *Terminal
	cancel          context.CancelFunc
}
type sourceState struct {
	source       Source
	round        *round
	last         Progress
	followManual bool
	publicAfter  time.Time
	deleted      bool
	refreshAfter time.Time
}
type job struct {
	source                        Source
	id                            string
	phase                         Phase
	trigger                       Trigger
	attempt                       int
	frontier                      *MailFrontier
	remaining                     time.Duration
	terminal                      *Terminal
	terminalOutcome               Outcome
	errorCode, directoryErrorCode string
	mailComplete                  bool
	ctx                           context.Context
}
type jobResult struct {
	job            job
	result         StepResult
	err            error
	admission      bool
	admissionError bool
	fenced         bool
	startedAt      int64
	duration       time.Duration
	terminal       *Terminal
	resolution     Resolution
}
type catalogResult struct {
	sources []Source
	err     error
}

type Coordinator struct {
	mu               sync.Mutex
	cfg              Config
	repo             Repository
	executor         Executor
	registry         *sourceguard.Registry
	slots            *Slots
	states           map[int64]*sourceState
	order            []int64
	ready            []int64
	inflight         int
	events           []Event
	sequence         uint64
	catalogErrors    uint64
	catalogReloads   uint64
	catalogErrorCode string
	boot             string
	nextID           uint64
	started          bool
	closing          bool
	wake             chan struct{}
	jobs             chan job
	results          chan jobResult
	reload           chan struct{}
	catalog          chan catalogResult
	cancel           context.CancelFunc
	done             chan struct{}
	doneOnce         sync.Once
	wg               sync.WaitGroup
}

func New(cfg Config, repo Repository, executor Executor, registry *sourceguard.Registry, slots *Slots) (*Coordinator, error) {
	if cfg.Workers < 1 || repo == nil || executor == nil || registry == nil || slots == nil || slots.registry != registry {
		return nil, ErrInvalid
	}
	if cfg.MaxSources == 0 {
		cfg.MaxSources = 1024
	}
	if cfg.EventCapacity == 0 {
		cfg.EventCapacity = 512
	}
	if cfg.StepTimeout == 0 {
		cfg.StepTimeout = 45 * time.Second
	}
	if cfg.AdmissionTimeout == 0 {
		cfg.AdmissionTimeout = 10 * time.Millisecond
	}
	if cfg.AdmissionRetry == 0 {
		cfg.AdmissionRetry = 25 * time.Millisecond
	}
	if cfg.StoreTimeout == 0 {
		cfg.StoreTimeout = 3 * time.Second
	}
	if cfg.ReloadInterval == 0 {
		cfg.ReloadInterval = time.Second
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 250 * time.Millisecond
	}
	if cfg.PublicInterval == 0 {
		cfg.PublicInterval = time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 2
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.MaxSources < 1 || cfg.EventCapacity < 1 || cfg.StepTimeout < 0 || cfg.RoundTimeout < 0 || cfg.AdmissionTimeout < 0 || cfg.AdmissionRetry < 0 || cfg.StoreTimeout < 0 || cfg.ReloadInterval < 0 || cfg.RetryDelay < 0 || cfg.PublicInterval < 0 || cfg.MaxRetries < 0 {
		return nil, ErrInvalid
	}
	if _, err := ns(cfg.Clock.Now()); err != nil {
		return nil, err
	}
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return &Coordinator{cfg: cfg, repo: repo, executor: executor, registry: registry, slots: slots, states: make(map[int64]*sourceState), boot: hex.EncodeToString(seed[:]), wake: make(chan struct{}, 1), jobs: make(chan job, cfg.Workers), results: make(chan jobResult, cfg.Workers), reload: make(chan struct{}, 1), catalog: make(chan catalogResult, 1), done: make(chan struct{})}, nil
}

func (m *Coordinator) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started || m.closing {
		m.mu.Unlock()
		return ErrClosed
	}
	m.mu.Unlock()
	load, cancel := context.WithTimeout(ctx, m.cfg.StoreTimeout)
	sources, err := m.repo.LoadCatalog(load, m.cfg.MaxSources)
	cancel()
	if err != nil {
		return err
	}
	if err = validateCatalog(sources, m.cfg.MaxSources); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.closing {
		return ErrClosed
	}
	runCtx, stop := context.WithCancel(ctx)
	m.cancel = stop
	m.started = true
	m.catalogReloads = 1
	m.applyCatalog(sources)
	for i := 0; i < m.cfg.Workers; i++ {
		m.wg.Add(1)
		go m.worker(runCtx)
	}
	m.wg.Add(1)
	go m.loader(runCtx)
	go m.loop(runCtx)
	return nil
}

// Wake does no IO and never waits for a source gate, worker or network slot.
func (m *Coordinator) Wake(sourceID int64, trigger Trigger) WakeResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started || m.closing {
		return WakeResult{Disposition: WakeClosed}
	}
	if trigger != Manual && trigger != Public {
		return WakeResult{Disposition: WakeUnknown}
	}
	s := m.states[sourceID]
	if s == nil || s.deleted {
		return WakeResult{Disposition: WakeUnknown}
	}
	if !s.source.Enabled {
		return WakeResult{Disposition: WakeDisabled}
	}
	if s.round != nil {
		if trigger == Manual && s.round.progress.Trigger == Public && s.source.HasDirectory {
			if !s.followManual {
				s.followManual = true
				s.round.progress.WaitingManual = true
				return WakeResult{Disposition: WakeQueued, FollowUp: true}
			}
			return WakeResult{Disposition: WakeCoalesced, FollowUp: true}
		}
		return WakeResult{Disposition: WakeCoalesced, RoundID: s.round.progress.RoundID}
	}
	now := m.cfg.Clock.Now()
	if trigger == Public && now.Before(s.publicAfter) {
		at, _ := ns(s.publicAfter)
		return WakeResult{Disposition: WakeThrottled, RetryAt: at}
	}
	if trigger == Public {
		s.publicAfter = now.Add(m.cfg.PublicInterval)
	}
	r := m.begin(s, trigger, now)
	m.signal()
	return WakeResult{Disposition: WakeQueued, RoundID: r.progress.RoundID}
}

func (m *Coordinator) Progress(sourceID int64) (Progress, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[sourceID]
	if s == nil {
		return Progress{}, false
	}
	if s.round != nil {
		return copyProgress(s.round.progress), true
	}
	return copyProgress(s.last), s.last.RoundID != ""
}
func (m *Coordinator) Events(after uint64) Events {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := Events{LastSequence: m.sequence}
	if len(m.events) > 0 && after < m.events[0].Sequence-1 {
		out.Lost = m.events[0].Sequence - after - 1
	}
	for _, e := range m.events {
		if e.Sequence > after {
			e.Progress = copyProgress(e.Progress)
			out.Items = append(out.Items, e)
		}
	}
	return out
}

type Statistics struct {
	Sources, Ready, InFlight, Slots int
	Closing                         bool
	CatalogErrors                   uint64
	CatalogReloads                  uint64
	CatalogErrorCode                string
}

func (m *Coordinator) Statistics() Statistics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Statistics{Sources: len(m.states), Ready: len(m.ready), InFlight: m.inflight, Slots: m.slots.Active(), Closing: m.closing, CatalogErrors: m.catalogErrors, CatalogReloads: m.catalogReloads, CatalogErrorCode: m.catalogErrorCode}
}
func (m *Coordinator) Done() <-chan struct{} { return m.done }
func (m *Coordinator) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if !m.started {
		m.closing = true
		m.doneOnce.Do(func() { close(m.done) })
		m.mu.Unlock()
		return nil
	}
	m.closing = true
	m.signal()
	m.mu.Unlock()
	select {
	case <-m.done:
		return nil
	default:
	}
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		m.cancel()
		return ctx.Err()
	}
}
func (m *Coordinator) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func validateCatalog(sources []Source, max int) error {
	if len(sources) > max {
		return ErrCapacity
	}
	seen := make(map[int64]bool, len(sources))
	for _, s := range sources {
		if !validScope(s.Scope) || s.RestInterval < 0 || seen[s.Scope.SourceID] {
			return ErrInvalid
		}
		seen[s.Scope.SourceID] = true
	}
	return nil
}

// Called under mu. Identity changes cancel old work but never transplant its
// frontier, terminal state or cooldown onto the new source/configuration scope.
func (m *Coordinator) applyCatalog(sources []Source) {
	found := make(map[int64]bool, len(sources))
	m.order = m.order[:0]
	for _, value := range sources {
		id := value.Scope.SourceID
		found[id] = true
		s := m.states[id]
		m.order = append(m.order, id)
		if s == nil {
			if len(m.states) >= m.cfg.MaxSources {
				continue
			}
			m.states[id] = &sourceState{source: copied(value)}
			continue
		}
		changed := s.source.Scope != value.Scope || s.source.RestInterval != value.RestInterval || s.source.HasDirectory != value.HasDirectory || !value.Enabled
		// The loader may have read before a terminal transaction committed and
		// deliver afterwards. Never replace a newer acknowledged schedule with
		// that older read snapshot from the same configuration scope.
		if s.source.Scope == value.Scope && s.source.LastTerminal != nil && (value.LastTerminal == nil || *value.LastTerminal < *s.source.LastTerminal) {
			value.LastTerminal = copyNS(s.source.LastTerminal)
			value.AutomaticAfter = copyNS(s.source.AutomaticAfter)
		}
		if s.source.Scope != value.Scope {
			s.refreshAfter = time.Time{}
		}
		s.source = copied(value)
		s.deleted = false
		if changed && s.round != nil {
			if s.round.cancel != nil {
				s.round.cancel()
			} else {
				m.finishLocal(s, Superseded, "source_changed")
			}
		}
	}
	for id, s := range m.states {
		if !found[id] {
			s.deleted = true
			if s.round == nil {
				delete(m.states, id)
			} else if s.round.cancel != nil {
				s.round.cancel()
			} else {
				m.finishLocal(s, Superseded, "source_removed")
				delete(m.states, id)
			}
		}
	}
	sort.Slice(m.order, func(i, j int) bool { return m.order[i] < m.order[j] })
}

func (m *Coordinator) begin(s *sourceState, trigger Trigger, now time.Time) *round {
	m.nextID++
	at, _ := ns(now)
	phase := Mail
	if trigger != Public && s.source.HasDirectory {
		phase = Directory
	}
	r := &round{source: copied(s.source), next: now, progress: Progress{Source: s.source.Scope, RoundID: m.boot + "-" + strconv.FormatUint(m.nextID, 10), Trigger: trigger, Phase: phase, State: Queued, QueuedAt: at, ReadyAt: at}}
	s.round = r
	m.enqueue(s)
	m.event(r, "round_queued", "round", "info")
	return r
}
func (m *Coordinator) enqueue(s *sourceState) {
	if s.round != nil && !s.round.queued {
		s.round.queued = true
		m.ready = append(m.ready, s.source.Scope.SourceID)
	}
}
func (m *Coordinator) event(r *round, name, scope, level string) {
	m.sequence++
	at, _ := ns(m.cfg.Clock.Now())
	e := Event{Sequence: m.sequence, At: at, Level: level, Scope: scope, Name: name, Progress: copyProgress(r.progress)}
	e.Outcome = string(r.progress.Outcome)
	switch name {
	case "attempt_failed":
		e.Outcome = "failed"
	case "attempt_unknown":
		e.Outcome = "unknown"
	case "attempt_completed":
		e.Outcome = "succeeded"
	}
	if len(m.events) == m.cfg.EventCapacity {
		copy(m.events, m.events[1:])
		m.events[len(m.events)-1] = e
	} else {
		m.events = append(m.events, e)
	}
}
func (m *Coordinator) finishLocal(s *sourceState, outcome Outcome, code string) {
	r := s.round
	if r == nil {
		return
	}
	r.progress.State = Finished
	r.progress.Outcome = outcome
	r.progress.ErrorCode = code
	r.progress.FinishedAt, _ = ns(m.cfg.Clock.Now())
	s.last = copyProgress(r.progress)
	m.event(r, "round_"+string(outcome), "round", "info")
	s.round = nil
	kept := m.ready[:0]
	for _, id := range m.ready {
		if id != s.source.Scope.SourceID {
			kept = append(kept, id)
		}
	}
	m.ready = kept
	s.followManual = false
}

func (m *Coordinator) loop(ctx context.Context) {
	defer func() {
		m.cancel()
		m.wg.Wait()
		m.mu.Lock()
		m.closing = true
		for _, s := range m.states {
			if s.round != nil {
				m.finishLocal(s, Cancelled, "shutdown")
			}
		}
		m.ready = nil
		m.inflight = 0
		m.mu.Unlock()
		m.doneOnce.Do(func() { close(m.done) })
	}()
	nextReload := m.cfg.Clock.Now().Add(m.cfg.ReloadInterval)
	for {
		m.mu.Lock()
		now := m.cfg.Clock.Now()
		if !m.closing {
			for _, id := range m.order {
				s := m.states[id]
				if s != nil && s.round == nil && !s.deleted && s.source.Enabled && !now.Before(automaticReadyAt(s, now)) {
					m.begin(s, Automatic, now)
				}
			}
		}
		// FIFO rotation skips not-yet-ready work. A continuation is always put
		// at the tail; it cannot monopolize a worker by looping inside Step.
		count := len(m.ready)
		for n := 0; n < count && m.inflight < m.cfg.Workers; n++ {
			id := m.ready[0]
			m.ready = m.ready[1:]
			s := m.states[id]
			if s == nil || s.round == nil {
				continue
			}
			r := s.round
			if !r.queued || r.cancel != nil {
				continue
			}
			if now.Before(r.next) {
				m.ready = append(m.ready, id)
				continue
			}
			r.queued = false
			if m.cfg.RoundTimeout > 0 && r.progress.Phase != Finalize && r.progress.Phase != Resolve && r.progress.ActiveTime >= m.cfg.RoundTimeout {
				m.prepareTerminal(s, Failed, "round_budget_exhausted", now)
				continue
			}
			workCtx, cancel := context.WithCancel(ctx)
			r.cancel = cancel
			r.progress.State = Running
			m.inflight++
			var remaining time.Duration
			if m.cfg.RoundTimeout > 0 {
				remaining = m.cfg.RoundTimeout - r.progress.ActiveTime
			}
			j := job{source: copied(r.source), id: r.progress.RoundID, phase: r.progress.Phase, trigger: r.progress.Trigger, attempt: r.progress.Attempts + 1, frontier: copyFrontier(r.progress.Frontier), remaining: remaining, terminal: r.terminal, terminalOutcome: r.terminalOutcome, errorCode: r.terminalCode, directoryErrorCode: r.progress.DirectoryErrorCode, mailComplete: r.mailComplete, ctx: workCtx}
			m.jobs <- j
		}
		pending := m.inflight > 0
		for _, s := range m.states {
			pending = pending || s.round != nil
		}
		if m.closing && !pending {
			m.mu.Unlock()
			return
		}
		due := nextReload
		if m.closing {
			due = now.Add(time.Hour)
		}
		for _, s := range m.states {
			if s.round != nil && s.round.queued && s.round.next.Before(due) {
				due = s.round.next
			}
			if !m.closing && s.round == nil && !s.deleted && s.source.Enabled {
				at := now
				if s.source.AutomaticAfter != nil {
					at = time.Unix(0, *s.source.AutomaticAfter)
				}
				if s.refreshAfter.After(at) {
					at = s.refreshAfter
				}
				if at.Before(due) {
					due = at
				}
			}
		}
		// All workers may be busy while a ready queue remains. Wait for their
		// result instead of repeatedly allocating zero-duration timers.
		if m.inflight == m.cfg.Workers && due.Before(nextReload) {
			due = nextReload
		}
		delay := due.Sub(now)
		if delay < 0 {
			delay = 0
		}
		m.mu.Unlock()
		timer := m.cfg.Clock.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-m.wake:
			timer.Stop()
		case result := <-m.results:
			timer.Stop()
			m.mu.Lock()
			m.handle(result)
			m.mu.Unlock()
		case loaded := <-m.catalog:
			timer.Stop()
			m.mu.Lock()
			if loaded.err == nil {
				m.applyCatalog(loaded.sources)
				m.catalogReloads++
				if m.catalogErrorCode != "" {
					m.event(&round{}, "catalog_recovered", "catalog", "info")
				}
				m.catalogErrorCode = ""
			} else {
				m.catalogErrors++
				m.catalogErrorCode = "catalog_read_failed"
				if errors.Is(loaded.err, ErrCapacity) {
					m.catalogErrorCode = "catalog_capacity"
				}
				m.event(&round{progress: Progress{ErrorCode: m.catalogErrorCode}}, "catalog_failed", "catalog", "warn")
			}
			m.mu.Unlock()
		case <-timer.C():
			if !m.cfg.Clock.Now().Before(nextReload) {
				select {
				case m.reload <- struct{}{}:
				default:
				}
				nextReload = m.cfg.Clock.Now().Add(m.cfg.ReloadInterval)
			}
		}
	}
}

func (m *Coordinator) loader(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.reload:
		}
		load, cancel := context.WithTimeout(ctx, m.cfg.StoreTimeout)
		sources, err := m.repo.LoadCatalog(load, m.cfg.MaxSources)
		cancel()
		if err == nil {
			err = validateCatalog(sources, m.cfg.MaxSources)
		}
		select {
		case m.catalog <- catalogResult{sources, err}:
		case <-ctx.Done():
			return
		}
	}
}

func (m *Coordinator) handle(done jobResult) {
	m.inflight--
	s := m.states[done.job.source.Scope.SourceID]
	if s == nil || s.round == nil || s.round.progress.RoundID != done.job.id {
		return
	}
	r := s.round
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	now := m.cfg.Clock.Now()
	if done.fenced || s.deleted || !s.source.Enabled || s.source.Scope != r.source.Scope || s.source.RestInterval != r.source.RestInterval || s.source.HasDirectory != r.source.HasDirectory {
		s.refreshAfter = now.Add(m.cfg.ReloadInterval)
		select {
		case m.reload <- struct{}{}:
		default:
		}
		m.finishLocal(s, Superseded, "source_changed")
		if s.deleted {
			delete(m.states, s.source.Scope.SourceID)
		}
		return
	}
	if done.admission {
		r.progress.AdmissionWaits++
		if done.admissionError {
			r.progress.AdmissionErrors++
			r.progress.ErrorCode = "source_read_failed"
			m.event(r, "admission_failed", "admission", "info")
		}
		r.progress.State = Waiting
		r.next = now.Add(m.cfg.AdmissionRetry)
		r.progress.ReadyAt, _ = ns(r.next)
		m.enqueue(s)
		return
	}
	if done.job.phase == Finalize || done.job.phase == Resolve {
		if errors.Is(done.err, ErrClockOrder) || errors.Is(done.err, ErrTimestampRange) {
			r.terminal = nil
			r.progress.Phase = Finalize
			r.progress.State = Waiting
			r.progress.Outcome = ""
			r.progress.ErrorCode = "terminal_clock_not_advanced"
			if errors.Is(done.err, ErrTimestampRange) {
				r.progress.ErrorCode = "terminal_timestamp_range"
			}
			r.next = now.Add(m.cfg.RetryDelay)
			r.progress.ReadyAt, _ = ns(r.next)
			m.event(r, "terminal_clock_wait", "schedule", "info")
			m.enqueue(s)
			return
		}
		if done.terminal != nil {
			r.terminal = done.terminal
		}
		if done.err == nil && done.resolution == Recorded {
			m.complete(s)
			return
		}
		if errors.Is(done.err, ErrStale) {
			m.finishLocal(s, Superseded, "source_changed")
			return
		}
		if done.resolution == NotRecorded || errors.Is(done.err, ErrNotRecorded) {
			r.progress.Phase = Finalize
			r.terminal = nil
		} else {
			r.progress.Phase = Resolve
		}
		r.progress.State = Waiting
		r.progress.Outcome = Unknown
		r.progress.ErrorCode = "terminal_persistence_unknown"
		r.next = now.Add(m.cfg.RetryDelay)
		r.progress.ReadyAt, _ = ns(r.next)
		m.event(r, "terminal_unresolved", "schedule", "info")
		m.enqueue(s)
		return
	}
	r.progress.Attempts++
	if r.progress.Attempts == 1 {
		r.progress.StartedAt = done.startedAt
	}
	r.progress.ActiveTime += done.duration
	if !validCounters(done.result.Counters) {
		done.err = ErrInvalid
		done.result.Problem = Problem{Code: "invalid_counters"}
		done.result.Counters = Counters{}
	}
	r.progress.Counters.Discovered += done.result.Counters.Discovered
	r.progress.Counters.Archived += done.result.Counters.Archived
	r.progress.Counters.Links += done.result.Counters.Links
	r.progress.Counters.Bytes += done.result.Counters.Bytes
	failed := done.err != nil || done.result.State == StepFailed
	if !failed && !validContinuation(done.job.phase, r.progress.Frontier, done.result) {
		done.result.Problem = Problem{Code: "invalid_frontier"}
		failed = true
	}
	if failed {
		code := safeCode(done.result.Problem.Code)
		if code == "" {
			code = "step_failed"
		}
		if errors.Is(done.err, context.DeadlineExceeded) && code != "round_budget_exhausted" {
			code = "step_timeout"
		}
		r.progress.FailedAttempts++
		r.consecutive++
		r.progress.ErrorCode = code
		name := "attempt_failed"
		if done.result.Problem.Uncertain {
			name = "attempt_unknown"
		}
		m.event(r, name, "attempt", "info")
		if done.result.Problem.Retryable && !done.result.Problem.Uncertain && r.consecutive <= m.cfg.MaxRetries && (m.cfg.RoundTimeout == 0 || r.progress.ActiveTime < m.cfg.RoundTimeout) {
			r.progress.Retries++
			r.progress.State = Waiting
			r.next = now.Add(m.cfg.RetryDelay)
			r.progress.ReadyAt, _ = ns(r.next)
			m.enqueue(s)
			return
		}
		if done.job.phase == Directory && m.cfg.AllowDegradedDirectory {
			r.progress.DirectoryErrorCode = code
			r.progress.Phase = Mail
			r.consecutive = 0
			r.next = now
			r.progress.State = Queued
			m.event(r, "directory_degraded", "phase", "info")
			m.enqueue(s)
			return
		}
		outcome := Failed
		if done.result.Problem.Uncertain {
			outcome = Unknown
		}
		m.prepareTerminal(s, outcome, code, now)
		return
	}
	r.consecutive = 0
	r.progress.ErrorCode = ""
	m.event(r, "attempt_completed", "attempt", "info")
	if done.job.phase == Directory {
		r.progress.Phase = Mail
		r.next = now
		r.progress.State = Queued
		m.enqueue(s)
		return
	}
	r.progress.Segments++
	r.progress.Frontier = copyFrontier(done.result.Frontier)
	if done.result.State == StepPending {
		r.next = now
		r.progress.State = Queued
		m.event(r, "segment_pending", "phase", "info")
		m.enqueue(s)
		return
	}
	r.mailComplete = true
	outcome := Succeeded
	code := ""
	if r.progress.DirectoryErrorCode != "" {
		outcome = Degraded
		code = r.progress.DirectoryErrorCode
	}
	m.prepareTerminal(s, outcome, code, now)
}

func automaticReadyAt(s *sourceState, now time.Time) time.Time {
	at := now
	if s.source.AutomaticAfter != nil {
		at = time.Unix(0, *s.source.AutomaticAfter)
	}
	if s.refreshAfter.After(at) {
		at = s.refreshAfter
	}
	return at
}

func (m *Coordinator) prepareTerminal(s *sourceState, outcome Outcome, code string, now time.Time) {
	r := s.round
	r.terminalOutcome = outcome
	r.terminalCode = code
	r.progress.ErrorCode = code
	r.progress.Phase = Finalize
	r.progress.State = Queued
	r.next = now
	m.enqueue(s)
}
func (m *Coordinator) complete(s *sourceState) {
	r := s.round
	t := r.terminal
	r.progress.State = Finished
	r.progress.Outcome = t.Outcome
	r.progress.ErrorCode = t.ErrorCode
	r.progress.Recovered = t.Outcome == Succeeded && r.progress.FailedAttempts > 0
	r.progress.FinishedAt = t.At
	s.source.LastTerminal = copyNS(&t.At)
	if t.Trigger == Automatic {
		s.source.AutomaticAfter = copyNS(t.AutomaticAfter)
	}
	level := "info"
	if t.Outcome == Failed {
		level = "warn"
	}
	m.event(r, "round_"+string(t.Outcome), "round", level)
	s.last = copyProgress(r.progress)
	s.round = nil
	if s.followManual {
		s.followManual = false
		m.begin(s, Manual, m.cfg.Clock.Now())
	}
}

func validCounters(c Counters) bool {
	return c.Discovered >= 0 && c.Archived >= 0 && c.Links >= 0 && c.Bytes >= 0
}
func validContinuation(phase Phase, old *MailFrontier, result StepResult) bool {
	if result.State != StepComplete && result.State != StepPending {
		return false
	}
	if phase == Directory {
		return result.State == StepComplete && result.Frontier == nil
	}
	n := result.Frontier
	if n == nil {
		return old == nil && result.State == StepComplete
	}
	if n.UIDValidity == 0 || n.Committed > n.CapturedUpper {
		return false
	}
	if b := n.Backfill; b != nil {
		if b.AddressID < 1 || b.ScanEpoch < 1 || b.UIDValidity != n.UIDValidity || b.Committed > b.CapturedUpper || b.CapturedUpper > n.CapturedUpper || n.Committed != n.CapturedUpper {
			return false
		}
	}
	if old != nil {
		if n.UIDValidity != old.UIDValidity || n.CapturedUpper != old.CapturedUpper || n.Committed < old.Committed {
			return false
		}
		progress := n.Committed > old.Committed
		switch {
		case old.Backfill == nil && n.Backfill != nil:
			progress = true
		case old.Backfill != nil && n.Backfill == nil:
			if old.Backfill.Committed != old.Backfill.CapturedUpper || result.State != StepComplete {
				return false
			}
			progress = true
		case old.Backfill != nil && n.Backfill != nil:
			before, after := old.Backfill, n.Backfill
			if before.AddressID == after.AddressID && before.ScanEpoch == after.ScanEpoch {
				if before.UIDValidity != after.UIDValidity || before.CapturedUpper != after.CapturedUpper || after.Committed < before.Committed {
					return false
				}
				progress = progress || after.Committed > before.Committed || (result.State == StepComplete && after.Committed == after.CapturedUpper)
			} else {
				if before.Committed != before.CapturedUpper || after.AddressID < before.AddressID || (after.AddressID == before.AddressID && after.ScanEpoch <= before.ScanEpoch) {
					return false
				}
				progress = true
			}
		}
		if !progress {
			return false
		}
	}
	if result.State == StepPending {
		return n.Committed < n.CapturedUpper || n.Backfill != nil
	}
	return n.Committed == n.CapturedUpper && (n.Backfill == nil || n.Backfill.Committed == n.Backfill.CapturedUpper)
}
func safeCode(code string) string {
	if len(code) == 0 || len(code) > 80 {
		return ""
	}
	for _, c := range code {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == ':' || c == '-') {
			return ""
		}
	}
	return code
}
