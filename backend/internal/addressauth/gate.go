package addressauth

import (
	"context"
	"sync"
)

// credentialGate is one Authority's process-wide revocation barrier. Pending
// writers stop admission of new readers. Waiting is cancelable; cancellation
// never releases an already granted lease behind an in-flight sensitive read.
type credentialGate struct {
	mu                      sync.Mutex
	readers, waitingWriters int
	writer                  bool
	changed                 chan struct{}
}

func (g *credentialGate) signal() {
	if g.changed != nil {
		close(g.changed)
	}
	g.changed = make(chan struct{})
}
func (g *credentialGate) read(ctx context.Context) (func(), error) {
	for {
		g.mu.Lock()
		if err := ctx.Err(); err != nil {
			g.mu.Unlock()
			return nil, err
		}
		if !g.writer && g.waitingWriters == 0 {
			g.readers++
			g.mu.Unlock()
			var once sync.Once
			return func() { once.Do(func() { g.mu.Lock(); g.readers--; g.signal(); g.mu.Unlock() }) }, nil
		}
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}
func (g *credentialGate) write(ctx context.Context) (func(), error) {
	g.mu.Lock()
	g.waitingWriters++
	g.signal()
	g.mu.Unlock()
	for {
		g.mu.Lock()
		if err := ctx.Err(); err != nil {
			g.waitingWriters--
			g.signal()
			g.mu.Unlock()
			return nil, err
		}
		if !g.writer && g.readers == 0 {
			g.waitingWriters--
			g.writer = true
			g.mu.Unlock()
			var once sync.Once
			return func() { once.Do(func() { g.mu.Lock(); g.writer = false; g.signal(); g.mu.Unlock() }) }, nil
		}
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-changed:
		}
	}
}
