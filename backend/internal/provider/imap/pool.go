package imap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	protocol "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

type session struct {
	key       [32]byte
	conn      net.Conn
	client    *imapclient.Client
	born      time.Time
	bad       atomic.Bool
	fault     atomic.Pointer[wireFault]
	requested atomic.Pointer[fetchExpectation]
}

type wireFault struct{ err error }

// beta8 routes duplicate/unrequested FETCH messages outside FetchCommand.Next.
// Flags-only notifications are legitimate. Unrequested literals must not be
// silently discarded or read without a budget by the SDK's default handler.
func (s *session) unilateralFetch(msg *imapclient.FetchMessageData) {
	if expected := s.requested.Load(); expected != nil {
		expected.unilateral(msg)
		return
	}
	fail := func(err error) {
		s.fault.CompareAndSwap(nil, &wireFault{err: err})
		s.discard()
	}
	walkFetchMessage(msg, func(item imapclient.FetchItemData, _ *wireLiteral) {
		switch item.(type) {
		case imapclient.FetchItemDataBodySection, imapclient.FetchItemDataBinarySection:
			fail(ErrUnexpectedUID)
		}
	}, fail, func(any) { fail(ErrIncomplete) })
}

func (s *session) discard() { s.bad.Store(true); _ = s.conn.Close() }

type idleEntry struct {
	s       *session
	timer   *time.Timer
	expires time.Time
}

// Pool retains idle sessions only. It is not a concurrency limiter or scheduler.
type Pool struct {
	mu             sync.Mutex
	cfg            Config
	idle           []*idleEntry
	closed         bool
	scratchMu      sync.Mutex
	scratchSlots   chan struct{}
	scratchCreated atomic.Uint64
	scratchActive  atomic.Int64
}

func NewPool(cfg Config) (*Pool, error) {
	if cfg.MaxIdle < 1 || cfg.MaxIdle > 256 {
		return nil, ErrInvalid
	}
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = 2 * time.Minute
	}
	if cfg.MaxLifetime == 0 {
		cfg.MaxLifetime = 25 * time.Minute
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 15 * time.Second
	}
	if cfg.CommandTimeout == 0 {
		cfg.CommandTimeout = 45 * time.Second
	}
	if cfg.IdleTTL < 0 || cfg.IdleTTL > 2*time.Minute || cfg.MaxLifetime <= 0 || cfg.MaxLifetime > 25*time.Minute || cfg.ConnectTimeout < 0 || cfg.TLSHandshakeTimeout < 0 || cfg.CommandTimeout < 0 {
		return nil, ErrInvalid
	}
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		cfg.TLSConfig = cfg.TLSConfig.Clone()
	}
	if cfg.TLSConfig.InsecureSkipVerify {
		return nil, ErrInvalid
	}
	if cfg.TLSConfig.MinVersion < tls.VersionTLS12 {
		cfg.TLSConfig.MinVersion = tls.VersionTLS12
	}
	if cfg.DialContext == nil {
		cfg.DialContext = (&net.Dialer{}).DialContext
	}
	return &Pool{cfg: cfg}, nil
}

func identity(e Endpoint, scope Scope, mailbox string) [32]byte {
	h := sha256.New()
	var length [8]byte
	for _, value := range []string{e.Host, strconv.Itoa(int(e.Port)), e.Username, e.Password, mailbox, strconv.FormatInt(scope.SourceID, 10), strconv.FormatInt(scope.SourceGeneration, 10), strconv.FormatInt(scope.CredentialGeneration, 10)} {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(value))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (p *Pool) take(key [32]byte) (*session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	for i, e := range p.idle {
		if e.s.key == key {
			p.idle = append(p.idle[:i], p.idle[i+1:]...)
			e.timer.Stop()
			if !time.Now().Before(e.expires) || time.Since(e.s.born) >= p.cfg.MaxLifetime {
				e.s.discard()
				return nil, nil
			}
			return e.s, nil
		}
	}
	return nil, nil
}

func (p *Pool) retain(s *session) {
	p.mu.Lock()
	remaining := p.cfg.MaxLifetime - time.Since(s.born)
	if p.closed || s.bad.Load() || remaining <= 0 {
		p.mu.Unlock()
		s.discard()
		return
	}
	var evicted *session
	if len(p.idle) >= p.cfg.MaxIdle {
		e := p.idle[0]
		e.timer.Stop()
		evicted = e.s
		p.idle = p.idle[1:]
	}
	ttl := min(p.cfg.IdleTTL, remaining)
	e := &idleEntry{s: s, expires: time.Now().Add(ttl)}
	p.idle = append(p.idle, e)
	e.timer = time.AfterFunc(ttl, func() {
		p.mu.Lock()
		found := false
		for i, candidate := range p.idle {
			if candidate == e {
				p.idle = append(p.idle[:i], p.idle[i+1:]...)
				found = true
				break
			}
		}
		p.mu.Unlock()
		if found {
			s.discard()
		}
	})
	p.mu.Unlock()
	if evicted != nil {
		evicted.discard()
	}
}

func (p *Pool) Close() error {
	p.mu.Lock()
	p.closed = true
	entries := p.idle
	p.idle = nil
	for _, e := range entries {
		e.timer.Stop()
	}
	p.mu.Unlock()
	for _, e := range entries {
		e.s.discard()
	}
	return nil
}

// watch never waits for the IMAP decoder. Closing the transport unblocks a
// command, including a streaming literal. The caller must join before reuse.
func watch(ctx context.Context, s *session) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			s.discard()
		case <-stop:
		}
	}()
	return func() { close(stop); <-done }
}

func (p *Pool) Acquire(ctx context.Context, endpoint Endpoint, scope Scope, mailbox string) (*Lease, error) {
	if ctx == nil || endpoint.Host == "" || strings.TrimSpace(endpoint.Host) != endpoint.Host || strings.ContainsAny(endpoint.Host, "\r\n\x00/ ") || endpoint.Port == 0 || endpoint.Username == "" || strings.ContainsAny(endpoint.Username, "\x00") || strings.ContainsAny(endpoint.Password, "\x00") || mailbox == "" || strings.ContainsAny(mailbox, "\r\n\x00") || scope.SourceID < 1 || scope.SourceGeneration < 1 || scope.CredentialGeneration < 1 {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, diagnostic("connect", err)
	}
	key := identity(endpoint, scope, mailbox)
	s, err := p.take(key)
	if err != nil {
		return nil, err
	}
	reused := s != nil
	if !reused {
		connectCtx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout)
		conn, dialErr := p.cfg.DialContext(connectCtx, "tcp", net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port))))
		if dialErr != nil {
			if connectCtx.Err() != nil {
				dialErr = connectCtx.Err()
			}
			cancel()
			return nil, diagnostic("connect", dialErr)
		}
		if err := connectCtx.Err(); err != nil {
			cancel()
			_ = conn.Close()
			return nil, diagnostic("connect", err)
		}
		if p.cfg.TLSHandshakeTimeout > 0 {
			cancel()
			connectCtx, cancel = context.WithTimeout(ctx, p.cfg.TLSHandshakeTimeout)
		}
		tlsCfg := p.cfg.TLSConfig.Clone()
		tlsCfg.ServerName = endpoint.Host
		secured := tls.Client(conn, tlsCfg)
		err = secured.HandshakeContext(connectCtx)
		if err != nil {
			if connectCtx.Err() != nil {
				err = connectCtx.Err()
			}
			cancel()
			_ = conn.Close()
			return nil, diagnostic("tls", err)
		}
		cancel()
		s = &session{key: key, conn: secured, born: time.Now()}
		s.client = imapclient.New(secured, &imapclient.Options{UnilateralDataHandler: &imapclient.UnilateralDataHandler{Fetch: s.unilateralFetch}})
	}
	l := &Lease{pool: p, s: s, ctx: ctx, mailbox: mailbox}
	l.stop = watch(ctx, s)
	if !reused {
		err = l.run(ctx, "greeting", func() error { return s.client.WaitGreeting() })
		if err == nil {
			err = l.run(ctx, "login", func() error { return s.client.Login(endpoint.Username, endpoint.Password).Wait() })
		}
	} else {
		err = l.run(ctx, "noop", func() error { return s.client.Noop().Wait() })
	}
	if err == nil {
		err = l.run(ctx, "examine", func() error {
			data, e := s.client.Select(mailbox, &protocol.SelectOptions{ReadOnly: true}).Wait()
			if e != nil {
				return e
			}
			if data.UIDValidity == 0 || data.UIDNext == 0 {
				return ErrIncomplete
			}
			l.snapshot = Snapshot{UIDValidity: data.UIDValidity, UIDNext: uint32(data.UIDNext), Messages: data.NumMessages}
			return nil
		})
	}
	if err != nil {
		l.Discard()
		l.Release()
		return nil, err
	}
	return l, nil
}
