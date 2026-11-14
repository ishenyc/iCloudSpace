package addressauth

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"icloudspace/internal/sourceguard"
)

// This typed key cannot collide with a credential rotation's client key.
type sourceChangeKey struct{ sourceID int64 }

// SourceChangeScope drains responses holding this Authority's read/reveal/IMAP
// leases while the caller holds its source business guard. It owns admission;
// closing it never releases the caller's guard or rewrites historical rows.
type SourceChangeScope struct {
	a       *Authority
	guard   *sourceguard.Lease
	mu      sync.Mutex
	release func()
	closed  bool
}

func (a *Authority) BeginSourceChange(ctx context.Context, guard *sourceguard.Lease) (*SourceChangeScope, error) {
	if a == nil || guard == nil || !guard.ValidFor(a.guards, guard.SourceID()) {
		return nil, ErrInvalid
	}
	release, err := a.gate.write(ctx)
	if err != nil {
		return nil, err
	}
	if !guard.ValidFor(a.guards, guard.SourceID()) {
		release()
		return nil, ErrInvalid
	}
	if !a.readReady() {
		release()
		return nil, ErrOutcomeUnknown
	}
	return &SourceChangeScope{a: a, guard: guard, release: release}, nil
}

func (s *SourceChangeScope) Close() error {
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.closed {
			s.closed = true
			s.release()
		}
	}
	return nil
}

func (s *SourceChangeScope) MarkUncertain() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.a.uncertain.Store(sourceChangeKey{s.guard.SourceID()}, true)
	}
}

func (s *SourceChangeScope) Resolve(ctx context.Context) error {
	if s == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.guard.ValidFor(s.a.guards, s.guard.SourceID()) {
		return ErrInvalid
	}
	return s.a.resolveSourceChange(ctx, s.guard.SourceID())
}

// ResolveSourceChange is a query of the original source, never a replay. It
// takes the same ordered admission as a source replacement and then waits on
// an independent conflicting row lock. A plain snapshot SELECT is not proof
// that a backend with an unknown COMMIT has released its transaction.
func (a *Authority) ResolveSourceChange(ctx context.Context, guard *sourceguard.Lease) error {
	if a == nil || guard == nil || !guard.ValidFor(a.guards, guard.SourceID()) {
		return ErrInvalid
	}
	release, err := a.gate.write(ctx)
	if err != nil {
		return err
	}
	defer release()
	if !guard.ValidFor(a.guards, guard.SourceID()) {
		return ErrInvalid
	}
	return a.resolveSourceChange(ctx, guard.SourceID())
}

func (a *Authority) resolveSourceChange(ctx context.Context, sourceID int64) error {
	key := sourceChangeKey{sourceID}
	if _, pending := a.uncertain.Load(key); !pending {
		return nil
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(ctx)
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, sourceID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict
		}
		return storageError(ctx)
	}
	if tx.Commit() != nil {
		return storageError(ctx)
	}
	a.uncertain.Delete(key)
	return nil
}
