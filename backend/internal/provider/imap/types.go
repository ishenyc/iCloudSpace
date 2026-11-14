// Package imap provides bounded, read-only leases over an upstream IMAP mailbox.
package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	protocol "github.com/emersion/go-imap/v2"
)

const (
	MaxCandidates              = 256
	MaxMetadataBatch           = 32
	MaxHeaderBytes             = 64 << 10
	MaxDiscoveryCommands       = 64
	MaxMessageBytes      int64 = 100 << 20
)

type Endpoint struct {
	Host     string
	Port     uint16
	Username string
	Password string
}

type Scope struct {
	SourceID             int64
	SourceGeneration     int64
	CredentialGeneration int64
}

// Config does not admit work. MaxIdle must be no greater than the caller's
// global IMAP concurrency. DialContext may supply an approved network route;
// TLS certificate and hostname verification still run over its connection.
type Config struct {
	MaxIdle        int
	IdleTTL        time.Duration
	MaxLifetime    time.Duration
	ConnectTimeout time.Duration
	// A positive value gives TLS a fresh budget after the TCP dial finishes.
	// Zero retains the caller's combined ConnectTimeout policy.
	TLSHandshakeTimeout time.Duration
	CommandTimeout      time.Duration
	TLSConfig           *tls.Config
	// ScratchDir holds only bounded, short-lived late-UID literals. Empty uses
	// the OS temporary directory; files are private (0600) and always removed.
	ScratchDir  string
	DialContext func(context.Context, string, string) (net.Conn, error)
}

type Snapshot struct {
	UIDValidity uint32
	UIDNext     uint32
	Messages    uint32
}

type Discovery struct {
	UIDValidity uint32
	After       uint32
	Through     uint32
	Limit       int
	MaxCommands int
}

type DiscoveryPage struct {
	UIDs           []uint32
	ScannedThrough uint32
	Complete       bool
}

type Metadata struct {
	UID          uint32
	Size         int64
	InternalDate time.Time
	Flags        []string
}

// Header retains unmodified upstream header octets. Truncated is poison for
// consumers requiring complete ownership evidence; a prefix is never a complete
// empty header. Complete is true only after the FETCH finishes successfully.
type Header struct {
	UID       uint32
	RawHeader []byte
	Complete  bool
	Truncated bool
}

var (
	ErrInvalid           = errors.New("invalid IMAP input")
	ErrClosed            = errors.New("IMAP lease or pool closed")
	ErrGenerationChanged = errors.New("IMAP UIDVALIDITY changed")
	ErrNotFound          = errors.New("IMAP message absent")
	ErrTooLarge          = errors.New("IMAP message exceeds limit")
	ErrIncomplete        = errors.New("IMAP content incomplete")
	ErrDuplicateUID      = fmt.Errorf("%w: duplicate UID", ErrIncomplete)
	ErrUnexpectedUID     = fmt.Errorf("%w: unexpected UID", ErrIncomplete)
	ErrScratchBudget     = fmt.Errorf("%w: temporary content capacity", ErrIncomplete)
	ErrScratchIO         = fmt.Errorf("%w: temporary content IO", ErrIncomplete)
)

// MissingError distinguishes normal disappearance (e.g. EXPUNGE) from a broken
// command. Already-consumed literals remain provisional until the caller handles
// this error. It never triggers a retry inside the provider.
type MissingError struct{ UIDs []uint32 }

func (e *MissingError) Error() string { return "upstream IMAP messages absent" }
func (e *MissingError) Unwrap() error { return ErrNotFound }

type ErrorKind string

const (
	KindDNS      ErrorKind = "dns"
	KindConnect  ErrorKind = "connect"
	KindTLS      ErrorKind = "tls"
	KindAuth     ErrorKind = "auth"
	KindCommand  ErrorKind = "command"
	KindTimeout  ErrorKind = "timeout"
	KindCanceled ErrorKind = "canceled"
	KindProtocol ErrorKind = "protocol"
)

// Error deliberately omits underlying network and server messages. Only safe
// local sentinels and context errors are unwrapped.
type Error struct {
	Stage string
	Kind  ErrorKind
	Code  string
	cause error
}

func (e *Error) Error() string { return "upstream IMAP " + e.Stage + ": " + string(e.Kind) }
func (e *Error) Unwrap() error { return e.cause }

func diagnostic(stage string, err error) error {
	if err == nil {
		return nil
	}
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	e := &Error{Stage: stage, Kind: KindCommand}
	var response *protocol.Error
	if errors.As(err, &response) {
		// Only known protocol labels leave this boundary; response text and
		// arbitrary extension response codes are never diagnostic material.
		switch response.Code {
		case protocol.ResponseCodeUnavailable, protocol.ResponseCodeAuthenticationFailed, protocol.ResponseCodeAuthorizationFailed, protocol.ResponseCodeNoPerm, protocol.ResponseCodeNonExistent, protocol.ResponseCodeLimit, protocol.ResponseCodeOverQuota, protocol.ResponseCodeCorruption, protocol.ResponseCodeServerBug, protocol.ResponseCodeClientBug:
			e.Code = string(response.Code)
		}
	}
	switch {
	case errors.Is(err, context.Canceled):
		e.Kind, e.cause = KindCanceled, context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		e.Kind, e.cause = KindTimeout, context.DeadlineExceeded
	case errors.Is(err, ErrGenerationChanged), errors.Is(err, ErrIncomplete), errors.Is(err, ErrTooLarge), errors.Is(err, ErrNotFound):
		e.Kind, e.cause = KindProtocol, err
	default:
		var dns *net.DNSError
		var network net.Error
		switch {
		case errors.As(err, &dns):
			e.Kind = KindDNS
		case errors.As(err, &network) && network.Timeout():
			e.Kind = KindTimeout
		case stage == "connect":
			e.Kind = KindConnect
		case stage == "tls":
			e.Kind = KindTLS
		case stage == "login":
			e.Kind = KindAuth
		case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
			e.Kind = KindConnect
		}
	}
	return e
}
