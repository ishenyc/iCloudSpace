package imap

import (
	"context"
	"io"
	"os"
	"sort"
	"sync"

	protocol "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// fetchExpectation bridges only beta8's late-UID routing limitation. The mutex
// is taken before consuming a literal, preserving wire callback order across
// normal FetchCommand messages and the SDK's asynchronous unilateral handler.
type fetchExpectation struct {
	mu         sync.Mutex
	s          *session
	p          *Pool
	ctx        context.Context
	uids       map[uint32]bool
	seen       map[uint32]bool
	section    *protocol.FetchItemBodySection
	limit      int64
	consume    func(uint32, io.Reader, int64) error
	err        error
	panicValue any
}

func (e *fetchExpectation) fail(err error) {
	if e.err == nil {
		e.err = err
	}
	e.s.fault.CompareAndSwap(nil, &wireFault{err: err})
	e.s.discard()
}

func (e *fetchExpectation) capturePanic(value any) {
	if e.panicValue == nil {
		e.panicValue = value
	}
	e.fail(ErrIncomplete)
}

type checkedReader struct {
	ctx context.Context
	s   *session
	r   io.Reader
}

func (r checkedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.s.bad.Load() {
		return 0, ErrClosed
	}
	return r.r.Read(p)
}

func (e *fetchExpectation) deliver(uid uint32, r io.Reader, size int64) {
	if e.err != nil {
		return
	}
	if !e.uids[uid] {
		e.fail(ErrUnexpectedUID)
		return
	}
	if e.seen[uid] {
		e.fail(ErrDuplicateUID)
		return
	}
	e.seen[uid] = true
	limited := &io.LimitedReader{R: checkedReader{ctx: e.ctx, s: e.s, r: r}, N: size}
	if err := e.consume(uid, limited, size); err != nil {
		e.fail(err)
	} else if limited.N != 0 {
		e.fail(ErrIncomplete)
	}
}

func (e *fetchExpectation) valid(item imapclient.FetchItemDataBodySection) bool {
	if item.Literal == nil || !item.MatchCommand(e.section) {
		e.fail(ErrIncomplete)
		return false
	}
	if item.Literal.Size() > e.limit {
		if e.section.Specifier == protocol.PartSpecifierNone && len(e.section.Part) == 0 && e.section.Partial == nil {
			e.fail(ErrTooLarge)
		} else {
			e.fail(ErrIncomplete)
		}
		return false
	}
	return true
}

// known keeps the UID-first path directly streaming, without a file or copy.
func (e *fetchExpectation) known(msg *imapclient.FetchMessageData) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	var uid uint32
	bodySeen := false
	complete := walkFetchMessage(msg, func(item imapclient.FetchItemData, literal *wireLiteral) {
		switch item := item.(type) {
		case imapclient.FetchItemDataUID:
			if uid != 0 {
				e.fail(ErrDuplicateUID)
			}
			uid = uint32(item.UID)
		case imapclient.FetchItemDataBodySection:
			if e.err != nil {
				return
			}
			if bodySeen {
				e.fail(ErrDuplicateUID)
				return
			}
			bodySeen = true
			if e.valid(item) {
				e.deliver(uid, literal, item.Literal.Size())
			}
		case imapclient.FetchItemDataBinarySection:
			e.fail(ErrIncomplete)
		}
	}, e.fail, e.capturePanic)
	if !bodySeen && e.err == nil {
		e.fail(ErrIncomplete)
	}
	return complete
}

type literalScratch struct {
	file *os.File
	p    *Pool
}

func (p *Pool) newScratch() (*literalScratch, error) {
	p.scratchMu.Lock()
	if p.scratchSlots == nil {
		p.scratchSlots = make(chan struct{}, max(1, p.cfg.MaxIdle))
	}
	slots := p.scratchSlots
	p.scratchMu.Unlock()
	select {
	case slots <- struct{}{}:
	default:
		return nil, ErrScratchBudget
	}
	f, err := os.CreateTemp(p.cfg.ScratchDir, "icloudspace-imap-late-*.tmp")
	if err != nil {
		<-slots
		return nil, ErrScratchIO
	}
	p.scratchCreated.Add(1)
	p.scratchActive.Add(1)
	return &literalScratch{file: f, p: p}, nil
}
func (scratch *literalScratch) close() error {
	closeErr := scratch.file.Close()
	removeErr := os.Remove(scratch.file.Name())
	scratch.p.scratchActive.Add(-1)
	<-scratch.p.scratchSlots
	if closeErr != nil || removeErr != nil {
		return ErrScratchIO
	}
	return nil
}

// unilateral accepts a legal literal before UID using a bounded private file.
// Only this slow path copies. The decoder waits for the literal, so holding mu
// before reading prevents later normal callbacks from overtaking this message.
func (e *fetchExpectation) unilateral(msg *imapclient.FetchMessageData) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if value := recover(); value != nil {
			e.capturePanic(value)
		}
	}()
	var scratch *literalScratch
	defer func() {
		if scratch != nil {
			if err := scratch.close(); err != nil {
				e.fail(err)
			}
		}
	}()
	var uid uint32
	var size int64
	bodySeen := false
	complete := walkFetchMessage(msg, func(item imapclient.FetchItemData, literal *wireLiteral) {
		switch item := item.(type) {
		case imapclient.FetchItemDataUID:
			if uid != 0 {
				e.fail(ErrDuplicateUID)
			}
			uid = uint32(item.UID)
		case imapclient.FetchItemDataBodySection:
			if e.err != nil {
				return
			}
			if uid != 0 {
				if e.uids[uid] {
					e.fail(ErrDuplicateUID)
				} else {
					e.fail(ErrUnexpectedUID)
				}
				return
			}
			if bodySeen {
				e.fail(ErrDuplicateUID)
				return
			}
			bodySeen = true
			if !e.valid(item) {
				return
			}
			var err error
			scratch, err = e.p.newScratch()
			if err != nil {
				e.fail(err)
				return
			}
			size = item.Literal.Size()
			if _, err = io.CopyN(scratch.file, checkedReader{ctx: e.ctx, s: e.s, r: literal}, size); err != nil {
				e.fail(err)
			}
		case imapclient.FetchItemDataBinarySection:
			e.fail(ErrIncomplete)
		}
	}, e.fail, e.capturePanic)
	if !complete || !bodySeen || e.err != nil {
		return
	} // flags-only unsolicited messages are valid
	if _, err := scratch.file.Seek(0, io.SeekStart); err != nil {
		e.fail(ErrScratchIO)
		return
	}
	e.deliver(uid, scratch.file, size)
}

func (l *Lease) fetchLiterals(ctx context.Context, uids []uint32, section *protocol.FetchItemBodySection, limit int64, consume func(uint32, io.Reader, int64) error) error {
	set := protocol.UIDSet(nil)
	requested := make(map[uint32]bool, len(uids))
	for _, uid := range uids {
		requested[uid] = true
		set.AddNum(protocol.UID(uid))
	}
	e := &fetchExpectation{s: l.s, p: l.pool, ctx: ctx, uids: requested, seen: make(map[uint32]bool, len(uids)), section: section, limit: limit, consume: consume}
	l.s.requested.Store(e)
	defer l.s.requested.Store(nil)
	cmd := l.s.client.Fetch(set, &protocol.FetchOptions{UID: true, BodySection: []*protocol.FetchItemBodySection{section}})
	complete := true
	for msg := cmd.Next(); msg != nil; msg = cmd.Next() {
		if !e.known(msg) {
			complete = false
			break
		}
	}
	var commandErr error
	if complete && !l.s.bad.Load() {
		commandErr = cmd.Close()
	}
	// A late-UID handler may still be consuming after the decoder parsed OK.
	// Joining its delivery lock also joins its cleanup and captured panic.
	e.mu.Lock()
	resultErr, panicValue := e.err, e.panicValue
	var missing []uint32
	for _, uid := range uids {
		if !e.seen[uid] {
			missing = append(missing, uid)
		}
	}
	e.mu.Unlock()
	if !complete || l.s.bad.Load() || resultErr != nil || panicValue != nil {
		l.s.discard()
		// No handler holds a partial literal now. Do not call cmd.Close: the
		// decoder completes its pending commands while exiting. Waiting outside
		// e.mu lets buffered late-UID handlers release their own literals.
		_ = l.s.client.Close()
	}
	if panicValue != nil {
		panic(panicValue)
	}
	if resultErr != nil {
		return resultErr
	}
	if commandErr != nil {
		return commandErr
	}
	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
		return &MissingError{UIDs: missing}
	}
	return nil
}
