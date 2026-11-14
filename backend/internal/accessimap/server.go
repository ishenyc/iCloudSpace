package accessimap

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"icloudspace/internal/addressauth"
	"icloudspace/internal/mailview"
	"net"
	"sync"
	"time"
)

var ErrConfig = errors.New("accessimap: invalid service configuration")

type Options struct {
	TLSConfig    *tls.Config
	PollInterval time.Duration
}
type Service struct {
	authority *addressauth.Authority
	views     *mailview.Service
	tls       *tls.Config
	poll      time.Duration
	server    *imapserver.Server
	mu        sync.Mutex
	closing   bool
	wires     map[*secureWire]struct{}
	sessions  sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}
type safeLogger struct{}

func (safeLogger) Printf(string, ...interface{}) {}
func New(authority *addressauth.Authority, views *mailview.Service, options Options) (*Service, error) {
	if authority == nil || views == nil || options.TLSConfig == nil || len(options.TLSConfig.Certificates) == 0 {
		return nil, ErrConfig
	}
	cfg := options.TLSConfig.Clone()
	if cfg.MinVersion < tls.VersionTLS12 {
		cfg.MinVersion = tls.VersionTLS12
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < cfg.MinVersion {
		return nil, ErrConfig
	}
	for _, certificate := range cfg.Certificates {
		if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
			return nil, ErrConfig
		}
	}
	if options.PollInterval <= 0 {
		options.PollInterval = time.Second
	}
	s := &Service{authority: authority, views: views, tls: cfg, poll: options.PollInterval}
	s.server = imapserver.New(&imapserver.Options{NewSession: s.newSession, Caps: imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIdle: {}, imap.CapNamespace: {}, imap.CapMove: {}, imap.CapStatusSize: {}, imap.CapUnselect: {}}, Logger: safeLogger{},
		// All accepted connections are TLS below secureWire. The SDK type assertion
		// cannot see through that wrapper; no plaintext listener is ever exposed.
		InsecureAuth: true})
	return s, nil
}

type secureListener struct {
	net.Listener
	service *Service
}

func (l secureListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	wire := newSecureWire(c)
	if !l.service.accept(wire) {
		_ = wire.Close()
		return nil, net.ErrClosed
	}
	return wire, nil
}
func (s *Service) Serve(listener net.Listener) error {
	if s == nil || listener == nil {
		return ErrConfig
	}
	return s.server.Serve(secureListener{Listener: tls.NewListener(listener, s.tls), service: s})
}
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		wires := make([]*secureWire, 0, len(s.wires))
		for wire := range s.wires {
			wires = append(wires, wire)
		}
		s.mu.Unlock()
		// The SDK closes registered connections but does not join their command
		// goroutines, and an accepted wire may not have entered NewSession yet.
		// Cancel every accepted wire before waiting for actual session cleanup.
		for _, wire := range wires {
			_ = wire.Close()
		}
		s.closeErr = s.server.Close()
		s.sessions.Wait()
	})
	return s.closeErr
}

func (s *Service) accept(wire *secureWire) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	if s.wires == nil {
		s.wires = make(map[*secureWire]struct{})
	}
	s.wires[wire] = struct{}{}
	s.sessions.Add(1)
	return true
}

func (s *Service) sessionDone(wire *secureWire) {
	s.mu.Lock()
	_, held := s.wires[wire]
	delete(s.wires, wire)
	s.mu.Unlock()
	if held {
		s.sessions.Done()
	}
}

func (s *Service) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	wire, ok := conn.NetConn().(*secureWire)
	if !ok {
		return nil, nil, ErrConfig
	}
	s.mu.Lock()
	closing := s.closing
	s.mu.Unlock()
	if closing {
		s.sessionDone(wire)
		return nil, nil, net.ErrClosed
	}
	return &session{service: s, wire: wire, ctx: wire.ctx}, nil, nil
}
func cancelled(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeServerBug, Text: "Local mailbox operation failed"}
}
