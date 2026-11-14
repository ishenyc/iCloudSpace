package rounds

import (
	"context"
	"errors"
	"time"
)

func (m *Coordinator) worker(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-m.jobs:
			result := m.execute(j)
			select {
			case m.results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (m *Coordinator) execute(j job) (done jobResult) {
	done.job = j
	defer func() {
		if recover() != nil {
			done.err = ErrInvalid
			if j.phase == Finalize || j.phase == Resolve {
				done.resolution = Unresolved
			} else {
				done.result = StepResult{State: StepFailed, Problem: Problem{Code: "executor_panic"}}
			}
		}
	}()
	admit, cancel := context.WithTimeout(j.ctx, m.cfg.AdmissionTimeout)
	gate, err := m.registry.Acquire(admit, j.source.Scope.SourceID)
	cancel()
	if err != nil {
		done.admission = true
		done.err = err
		return
	}
	defer gate.Close()
	load, cancel := context.WithTimeout(j.ctx, m.cfg.StoreTimeout)
	current, err := m.repo.CurrentSource(load, j.source.Scope.SourceID)
	cancel()
	if err != nil {
		if errors.Is(err, ErrStale) {
			done.fenced = true
			return
		}
		done.admission = true
		done.admissionError = true
		done.err = err
		return
	}
	if !current.Enabled || current.Scope != j.source.Scope || current.RestInterval != j.source.RestInterval || current.HasDirectory != j.source.HasDirectory {
		done.fenced = true
		return
	}
	if j.phase == Finalize || j.phase == Resolve {
		t := j.terminal
		if t == nil {
			now := m.cfg.Clock.Now()
			at, e := ns(now)
			if e != nil {
				done.err = e
				return
			}
			if j.source.LastTerminal != nil && at <= *j.source.LastTerminal {
				done.err = ErrClockOrder
				return
			}
			t = &Terminal{Source: copied(j.source), RoundID: j.id, Trigger: j.trigger, Outcome: j.terminalOutcome, ErrorCode: j.errorCode, DirectoryErrorCode: j.directoryErrorCode, At: at, MailComplete: j.mailComplete}
			if j.trigger == Automatic {
				after, e := ns(time.Unix(0, at).Add(j.source.RestInterval))
				if e != nil {
					done.err = e
					return
				}
				t.AutomaticAfter = &after
			}
		}
		done.terminal = t
		store, cancel := context.WithTimeout(j.ctx, m.cfg.StoreTimeout)
		defer cancel()
		if j.phase == Resolve {
			done.resolution, done.err = m.repo.ResolveTerminal(store, gate, *t)
			return
		}
		done.err = m.repo.RecordTerminal(store, gate, *t)
		if done.err == nil {
			done.resolution = Recorded
		}
		return
	}
	var permit *Permit
	if j.phase == Mail {
		admit, cancel = context.WithTimeout(j.ctx, m.cfg.AdmissionTimeout)
		permit, err = m.slots.Acquire(admit, gate)
		cancel()
		if err != nil {
			done.admission = true
			done.err = err
			return
		}
		defer permit.Close()
	}
	budget := m.cfg.StepTimeout
	if j.remaining > 0 && j.remaining < budget {
		budget = j.remaining
	}
	if budget <= 0 {
		done.err = context.DeadlineExceeded
		done.result.Problem.Code = "round_budget_exhausted"
		return
	}
	step, cancel := context.WithTimeout(j.ctx, budget)
	defer cancel()
	started := m.cfg.Clock.Now()
	done.startedAt, _ = ns(started)
	done.result, done.err = m.executor.Step(step, StepInput{Source: copied(j.source), RoundID: j.id, Trigger: j.trigger, Phase: j.phase, Attempt: j.attempt, Frontier: copyFrontier(j.frontier), Gate: gate, IMAPSlot: permit})
	done.duration = m.cfg.Clock.Now().Sub(started)
	if done.duration < 0 {
		done.duration = 0
	}
	if step.Err() != nil {
		done.err = step.Err()
	}
	if j.remaining > 0 && done.duration > j.remaining {
		done.err = context.DeadlineExceeded
		done.result.Problem.Code = "round_budget_exhausted"
	}
	return
}
