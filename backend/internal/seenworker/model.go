// Package seenworker owns only durable consume Seen jobs and independent,
// unpooled upstream IMAP write connections. It never consumes local messages.
package seenworker

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"icloudspace/internal/rounds"
	"icloudspace/internal/sourceguard"
)

var (
	ErrInvalid     = errors.New("seenworker: invalid request")
	ErrStorage     = errors.New("seenworker: storage operation failed")
	ErrClosed      = errors.New("seenworker: worker closed")
	ErrBusy        = errors.New("seenworker: worker already active")
	ErrStale       = errors.New("seenworker: remote identity changed")
	ErrDisabled    = errors.New("seenworker: source is disabled")
	ErrReadOnly    = errors.New("seenworker: installation writes disabled")
	ErrCredentials = errors.New("seenworker: credentials rejected")
	ErrNetwork     = errors.New("seenworker: independent IMAP operation failed")
	ErrProtocol    = errors.New("seenworker: IMAP response rejected")
	ErrRejected    = errors.New("seenworker: STORE explicitly rejected")
	ErrUnknown     = errors.New("seenworker: acknowledgement unknown; flags query required")
)

type Identity struct {
	SourceID, SourceGeneration int64
	Mailbox                    string
	UIDValidity, UID           uint32
}
type Source struct {
	ID, Revision, Generation, CredentialGeneration int64
	Host, Username, Password                       string
	Port                                           uint16
}

func (Source) String() string   { return "seenworker: private source credentials" }
func (Source) GoString() string { return "seenworker: private source credentials" }

type OpenRequest struct {
	Gate      *sourceguard.Lease
	Permit    *rounds.Permit
	Source    Source
	Identity  Identity
	QueryOnly bool
}

func (OpenRequest) String() string   { return "seenworker: private independent write request" }
func (OpenRequest) GoString() string { return "seenworker: private independent write request" }

type Flags struct{ Exists, Seen bool }
type Outcome string

const (
	Accepted Outcome = "accepted"
	Rejected Outcome = "rejected"
	NotSent  Outcome = "not_sent"
	Unknown  Outcome = "unknown"
)

type Connection interface {
	UIDValidity() uint32
	Flags(context.Context, uint32) (Flags, error)
	StoreSeen(context.Context, uint32) (Outcome, error)
	Close() error
}
type OpenFunc func(context.Context, OpenRequest) (Connection, error)
type WriterConfig struct {
	TLSConfig                      *tls.Config
	DialContext                    func(context.Context, string, string) (net.Conn, error)
	ConnectTimeout, CommandTimeout time.Duration
}
type Options struct {
	BatchSize                                 int
	Interval, Backoff, MaxBackoff, QueryDelay time.Duration
	Clock                                     func() int64
	Writer                                    WriterConfig
	Open                                      OpenFunc
}
type Result struct{ Visited, Claimed, Stored, Completed, Unknown, Rejected, Deferred int }
type job struct {
	Identity
	State, Owner, LastError  string
	HasOwner                 bool
	Attempts                 int32
	CreatedAt, NextAttemptAt int64
}
