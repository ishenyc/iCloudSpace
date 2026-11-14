// Package externalregistration owns deployment-authorized, purely local
// registration. Deployment authentication is unrelated to mailbox grants,
// management cookies and OAuth refresh/access credentials.
package externalregistration

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"sync"
	"time"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/addresses"
	"icloudspace/internal/pgschema"
	"icloudspace/internal/sourceguard"
)

var (
	ErrInvalid          = errors.New("externalregistration: invalid request")
	ErrUnauthorized     = errors.New("externalregistration: deployment authorization rejected")
	ErrConflict         = errors.New("externalregistration: request or address conflicts")
	ErrQueryOnly        = errors.New("externalregistration: original registration must be queried")
	ErrUnknown          = errors.New("externalregistration: acknowledgement unknown; query original operation")
	ErrNotFound         = errors.New("externalregistration: original operation unavailable")
	ErrStorage          = errors.New("externalregistration: local storage operation failed")
	ErrReadOnly         = errors.New("externalregistration: installation writes disabled")
	ErrIdentityConflict = errors.New("externalregistration: address conflicts with a source identity")
	ErrAddressExists    = errors.New("externalregistration: address already registered")
)

type Config struct {
	DB             *sql.DB
	InstallationID string
	Addresses      *addresses.Service
	Authority      *addressauth.Authority
	Guards         *sourceguard.Registry
	TokenHash      [32]byte
	Clock          func() int64
}

func (Config) String() string   { return "externalregistration: private deployment configuration" }
func (Config) GoString() string { return "externalregistration: private deployment configuration" }

type Service struct {
	db           *sql.DB
	installation string
	addresses    *addresses.Service
	authority    *addressauth.Authority
	guards       *sourceguard.Registry
	tokenHash    [32]byte
	clock        func() int64
	commit       func(*sql.Tx) error
}

func (*Service) String() string { return "externalregistration: private deployment registration owner" }
func (*Service) GoString() string {
	return "externalregistration: private deployment registration owner"
}

func New(ctx context.Context, c Config) (*Service, error) {
	if c.DB == nil || c.InstallationID == "" || c.Addresses == nil || c.Authority == nil || c.Guards == nil {
		return nil, ErrInvalid
	}
	if pgschema.Check(ctx, c.DB) != nil {
		return nil, ErrStorage
	}
	var actual string
	if c.DB.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual) != nil || actual != c.InstallationID {
		return nil, ErrStorage
	}
	if c.Clock == nil {
		c.Clock = func() int64 { return time.Now().UnixNano() }
	}
	return &Service{db: c.DB, installation: c.InstallationID, addresses: c.Addresses, authority: c.Authority, guards: c.Guards, tokenHash: c.TokenHash, clock: c.Clock, commit: (*sql.Tx).Commit}, nil
}

type Access struct {
	owner *Service
	hash  [32]byte
}

func (Access) String() string   { return "externalregistration: private deployment capability" }
func (Access) GoString() string { return "externalregistration: private deployment capability" }
func (s *Service) Authenticate(raw string) (Access, error) {
	if s == nil || s.tokenHash == [32]byte{} || len(raw) < 1 || len(raw) > 4096 {
		return Access{}, ErrUnauthorized
	}
	for _, b := range []byte(raw) {
		if b < '!' || b > '~' {
			return Access{}, ErrUnauthorized
		}
	}
	h := sha256.Sum256([]byte(raw))
	if subtle.ConstantTimeCompare(h[:], s.tokenHash[:]) != 1 {
		return Access{}, ErrUnauthorized
	}
	return Access{s, h}, nil
}
func (s *Service) authorized(a Access) bool {
	return s != nil && a.owner == s && s.tokenHash != [32]byte{} && subtle.ConstantTimeCompare(a.hash[:], s.tokenHash[:]) == 1
}

type Request struct {
	SourceID              int64
	Address, OperationKey string
	sourceEmail           string
}
type Query struct {
	SourceID     int64
	OperationKey string
}
type Receipt struct {
	OperationKey          string
	SourceID              int64
	Address               string
	State                 string
	AddressID, Generation int64
	DeliveryKey           string
	QueryOnly             bool
	Available             bool
	UnavailableReason     string
	EffectiveEnabled      bool
}

// Delivery retains the original Authority read gate through the caller's
// complete HTTP write. Its public receipt has no secret; Bundle is private.
type Delivery struct {
	Receipt Receipt
	Bundle  *addressauth.Bundle
	once    sync.Once
	close   func()
}

func (d *Delivery) Close() error {
	if d != nil {
		d.once.Do(func() {
			if d.close != nil {
				d.close()
			}
			d.Bundle = nil
		})
	}
	return nil
}
func (*Delivery) String() string { return "externalregistration: private original credential delivery" }
func (*Delivery) GoString() string {
	return "externalregistration: private original credential delivery"
}

func validKey(k string) bool {
	if len(k) < 1 || len(k) > 128 {
		return false
	}
	for _, c := range k {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}
func storage(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrStorage
}
