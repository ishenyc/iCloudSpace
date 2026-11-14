package seenworker

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"icloudspace/internal/rounds"
	"icloudspace/internal/sourceguard"
)

// NewWriter creates no socket. Every Open creates one independent verified TLS
// connection; no object from provider/imap's read-only pool is accepted here.
func NewWriter(guards *sourceguard.Registry, slots *rounds.Slots, config WriterConfig) (OpenFunc, error) {
	if guards == nil || slots == nil || config.ConnectTimeout < 0 || config.CommandTimeout < 0 {
		return nil, ErrInvalid
	}
	if config.TLSConfig != nil && config.TLSConfig.InsecureSkipVerify {
		return nil, ErrInvalid
	}
	if config.TLSConfig != nil {
		config.TLSConfig = config.TLSConfig.Clone()
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 15 * time.Second
	}
	if config.CommandTimeout == 0 {
		config.CommandTimeout = 20 * time.Second
	}
	if config.DialContext == nil {
		config.DialContext = (&net.Dialer{}).DialContext
	}
	return func(ctx context.Context, req OpenRequest) (Connection, error) {
		if !req.Gate.ValidFor(guards, req.Source.ID) || !slots.Owns(req.Permit, req.Gate) || req.Source.ID != req.Identity.SourceID || req.Source.Generation != req.Identity.SourceGeneration || req.Source.Host == "" || req.Source.Port == 0 || req.Source.Username == "" || req.Source.Password == "" || !validIdentity(req.Identity) {
			return nil, ErrInvalid
		}
		connectCtx, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
		defer cancel()
		raw, e := config.DialContext(connectCtx, "tcp", net.JoinHostPort(req.Source.Host, strconv.Itoa(int(req.Source.Port))))
		if e != nil {
			return nil, safeError(ctx, e)
		}
		if raw == nil {
			return nil, ErrNetwork
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if config.TLSConfig != nil {
			cfg = config.TLSConfig.Clone()
		}
		cfg.ServerName = req.Source.Host
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		socket := tls.Client(raw, cfg)
		if e = socket.HandshakeContext(connectCtx); e != nil {
			socket.Close()
			return nil, safeError(ctx, e)
		}
		c := &writeConnection{socket: socket, client: imapclient.New(socket, nil), mailbox: req.Identity.Mailbox, timeout: config.CommandTimeout, queryOnly: req.QueryOnly}
		fail := func(e error) (Connection, error) { c.Close(); return nil, e }
		if e = c.run(ctx, func() error { return c.client.WaitGreeting() }); e != nil {
			return fail(safeError(ctx, e))
		}
		if e = c.run(ctx, func() error { return c.client.Login(req.Source.Username, req.Source.Password).Wait() }); e != nil {
			return fail(ErrCredentials)
		}
		var selected *imap.SelectData
		if e = c.run(ctx, func() error {
			var se error
			selected, se = c.client.Select(req.Identity.Mailbox, &imap.SelectOptions{ReadOnly: req.QueryOnly}).Wait()
			return se
		}); e != nil {
			return fail(safeError(ctx, e))
		}
		if selected == nil || selected.UIDValidity != req.Identity.UIDValidity {
			return fail(ErrStale)
		}
		c.uidValidity = selected.UIDValidity
		return c, nil
	}, nil
}

type writeConnection struct {
	socket      net.Conn
	client      *imapclient.Client
	mailbox     string
	uidValidity uint32
	timeout     time.Duration
	mu          sync.Mutex
	closed      atomic.Bool
	used        atomic.Bool
	once        sync.Once
	queryOnly   bool
}

func (c *writeConnection) UIDValidity() uint32 { return c.uidValidity }
func safeError(ctx context.Context, e error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(e, ErrStale) || errors.Is(e, ErrProtocol) {
		return e
	}
	return ErrNetwork
}
func (c *writeConnection) run(ctx context.Context, fn func() error) error {
	if c.closed.Load() {
		return ErrClosed
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	command, cancel := context.WithTimeout(ctx, c.timeout)
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-command.Done():
			c.socket.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-joined; cancel() }()
	e := fn()
	if e == nil {
		return nil
	}
	if command.Err() != nil {
		return command.Err()
	}
	var protocolError *imap.Error
	if errors.As(e, &protocolError) {
		return protocolError
	}
	return safeError(ctx, e)
}
func (c *writeConnection) fence(ctx context.Context) error {
	var status *imap.StatusData
	e := c.run(ctx, func() error {
		var se error
		status, se = c.client.Status(c.mailbox, &imap.StatusOptions{UIDValidity: true}).Wait()
		return se
	})
	if e != nil {
		return e
	}
	if status == nil || status.UIDValidity != c.uidValidity {
		return ErrStale
	}
	return nil
}
func (c *writeConnection) Flags(ctx context.Context, uid uint32) (Flags, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if uid == 0 {
		return Flags{}, ErrInvalid
	}
	if e := c.fence(ctx); e != nil {
		return Flags{}, safeError(ctx, e)
	}
	result := Flags{}
	e := c.run(ctx, func() error {
		command := c.client.Fetch(imap.UIDSetNum(imap.UID(uid)), &imap.FetchOptions{UID: true, Flags: true})
		fail := func() error { c.socket.Close(); command.Close(); return ErrProtocol }
		for message := command.Next(); message != nil; message = command.Next() {
			if result.Exists {
				return fail()
			}
			var actual uint32
			var haveUID, haveFlags bool
			for item := message.Next(); item != nil; item = message.Next() {
				switch item := item.(type) {
				case imapclient.FetchItemDataUID:
					if haveUID {
						return fail()
					}
					actual = uint32(item.UID)
					haveUID = true
				case imapclient.FetchItemDataFlags:
					if haveFlags {
						return fail()
					}
					haveFlags = true
					for _, flag := range item.Flags {
						if strings.EqualFold(string(flag), string(imap.FlagSeen)) {
							result.Seen = true
						}
					}
				default:
					return fail() // never accumulate unsolicited MIME/body literals
				}
			}
			if !haveUID || !haveFlags || actual != uid {
				return fail()
			}
			result.Exists = true
		}
		return command.Close()
	})
	if e != nil {
		return Flags{}, safeError(ctx, e)
	}
	if e = c.fence(ctx); e != nil {
		return Flags{}, safeError(ctx, e)
	}
	return result, nil
}
func (c *writeConnection) StoreSeen(ctx context.Context, uid uint32) (Outcome, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.queryOnly || uid == 0 || !c.used.CompareAndSwap(false, true) {
		return NotSent, ErrInvalid
	}
	if e := c.fence(ctx); e != nil {
		return NotSent, safeError(ctx, e)
	}
	if c.closed.Load() {
		return NotSent, ErrClosed
	}
	if ctx.Err() != nil {
		return NotSent, ctx.Err()
	}
	started := false
	e := c.run(ctx, func() error {
		started = true
		return c.client.Store(imap.UIDSetNum(imap.UID(uid)), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagSeen}}, nil).Close()
	})
	if !started {
		return NotSent, safeError(ctx, e)
	}
	if e == nil {
		return Accepted, nil
	}
	var response *imap.Error
	if errors.As(e, &response) && (response.Type == imap.StatusResponseTypeNo || response.Type == imap.StatusResponseTypeBad) {
		return Rejected, ErrRejected
	}
	return Unknown, ErrUnknown
}
func (c *writeConnection) Close() error {
	c.once.Do(func() { c.closed.Store(true); c.socket.Close(); c.client.Close() })
	return nil
}
