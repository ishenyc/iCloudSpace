// Package adminauth owns management passwords and opaque server-side sessions.
// HTTP origin checks, cookies, CSRF request policy and rate limits belong to the
// transport. This package never initializes an operator or discovers a database.
package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	PasswordCost          = 12
	MinNewPasswordBytes   = 12
	MaxNewPasswordBytes   = 72
	MaxUsernameBytes      = 256
	MaxLoginPasswordBytes = 1024
	MaxOpaqueTokenBytes   = 4096
	// SessionHashVersion 1 is SHA-256 of the raw opaque token bytes, for
	// both session_hash and csrf_hash. Imported hashes keep this meaning.
	SessionHashVersion = 1
)

var (
	ErrInvalidCredentials = errors.New("invalid management credentials")
	ErrUnauthenticated    = errors.New("management session is not active")
	ErrInvalidInput       = errors.New("management authentication input is invalid")
	ErrPasswordPolicy     = errors.New("new password must match confirmation and contain 12 to 72 bytes")
	ErrConflict           = errors.New("management credentials changed concurrently")
	// ErrOutcomeUnknown means a write reached COMMIT but its acknowledgement
	// was lost. Callers must resolve state rather than automatically replay it.
	ErrOutcomeUnknown = errors.New("management authentication write outcome is unknown")
)

// Operator contains only metadata safe to return from a management endpoint.
type Operator struct {
	ID       int64
	Username string
}

// IssuedSession is returned once. Neither opaque token is stored in plaintext.
type IssuedSession struct {
	Operator     Operator
	SessionToken string
	CSRFToken    string
	ExpiresAt    time.Time
}

// Session is a verified snapshot. A transport must call Authenticate for each
// request, and again after waiting for any separate credential rotation gate.
type Session struct {
	Operator  Operator
	ExpiresAt time.Time
	csrfHash  []byte
	verified  bool
	epoch     int64
}

// Epoch binds a provider challenge to the freshly verified operator generation.
// It is internal metadata, never a session bearer or a browser cookie value.
func (s Session) Epoch() int64 {
	if !s.verified {
		return 0
	}
	return s.epoch
}

// Service has one concrete persistence dependency. No provider, credential
// vault, environment configuration or process-wide gate is part of this owner.
type Service struct {
	repository *SQLRepository
	ttl        time.Duration
	dummyHash  []byte
}

func NewService(repository *SQLRepository, sessionTTL time.Duration) (*Service, error) {
	if repository == nil || repository.db == nil || sessionTTL <= 0 {
		return nil, fmt.Errorf("adminauth: repository and positive session TTL are required")
	}
	// Each service gets an unrelated dummy credential. The unknown-user path
	// still performs a cost-12 password comparison without a copied fixture.
	dummyPassword := make([]byte, 32)
	if _, err := rand.Read(dummyPassword); err != nil {
		return nil, fmt.Errorf("prepare management password comparison: %w", err)
	}
	dummyHash, err := bcrypt.GenerateFromPassword(dummyPassword, PasswordCost)
	clear(dummyPassword)
	if err != nil {
		return nil, fmt.Errorf("prepare management password comparison: %w", err)
	}
	return &Service{repository: repository, ttl: sessionTTL, dummyHash: dummyHash}, nil
}

// Login retains the exact password bytes. New-password policy does not
// silently invalidate imported passwords that predate that policy.
func (s *Service) Login(ctx context.Context, username, password string) (IssuedSession, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > MaxUsernameBytes || password == "" || len(password) > MaxLoginPasswordBytes {
		return IssuedSession{}, ErrInvalidInput
	}
	credential, found, err := s.repository.passwordForLogin(ctx, username)
	if err != nil {
		return IssuedSession{}, err
	}
	comparison := s.dummyHash
	if found {
		comparison = []byte(credential.password)
	}
	matched := bcrypt.CompareHashAndPassword(comparison, []byte(password)) == nil
	if !found || !matched || !credential.enabled {
		return IssuedSession{}, ErrInvalidCredentials
	}
	if err := ctx.Err(); err != nil {
		return IssuedSession{}, err
	}
	issued := IssuedSession{Operator: credential.operator}
	issued.SessionToken, err = newOpaqueToken()
	if err != nil {
		return IssuedSession{}, err
	}
	issued.CSRFToken, err = newOpaqueToken()
	if err != nil {
		return IssuedSession{}, err
	}
	created := time.Now().UTC()
	issued.ExpiresAt = created.Add(s.ttl)
	// UnixNano is the canonical time representation; reject overflowing TTLs.
	if issued.ExpiresAt.UnixNano() <= created.UnixNano() || !time.Unix(0, issued.ExpiresAt.UnixNano()).Equal(issued.ExpiresAt) {
		return IssuedSession{}, fmt.Errorf("adminauth: session expiry exceeds canonical time range")
	}
	err = s.repository.issueSession(ctx, credential, tokenHash(issued.SessionToken), tokenHash(issued.CSRFToken), created, issued.ExpiresAt)
	if err != nil {
		return IssuedSession{}, err
	}
	return issued, nil
}

func (s *Service) Authenticate(ctx context.Context, rawSession string) (Session, error) {
	if !validOpaqueInput(rawSession) {
		return Session{}, ErrUnauthenticated
	}
	return s.repository.activeSession(ctx, tokenHash(rawSession))
}

// ValidateCSRF compares a request token with a freshly authenticated session.
// It does not apply HTTP method, Origin, cookie or trusted-proxy policy.
func (s *Service) ValidateCSRF(session Session, rawCSRF string) bool {
	if !session.verified || !validOpaqueInput(rawCSRF) {
		return false
	}
	digest := tokenHash(rawCSRF)
	return subtle.ConstantTimeCompare(session.csrfHash, digest) == 1
}

// Logout is idempotent. A missing, expired or already revoked token is logged
// out; storage errors still propagate rather than being reported as success.
func (s *Service) Logout(ctx context.Context, rawSession string) error {
	if !validOpaqueInput(rawSession) {
		return nil
	}
	return s.repository.revokeSession(ctx, tokenHash(rawSession))
}

// ChangePassword checks the active session and current exact password before
// computing a new encoding. The transaction then rechecks both facts, advances
// the existing epoch, and revokes every session in the same commit.
func (s *Service) ChangePassword(ctx context.Context, rawSession, currentPassword, newPassword, confirmation string) error {
	if !validOpaqueInput(rawSession) {
		return ErrUnauthenticated
	}
	if currentPassword == "" || len(currentPassword) > MaxLoginPasswordBytes {
		return ErrInvalidInput
	}
	if len(newPassword) < MinNewPasswordBytes || len(newPassword) > MaxNewPasswordBytes || newPassword != confirmation {
		return ErrPasswordPolicy
	}
	hash := tokenHash(rawSession)
	credential, err := s.repository.passwordForSession(ctx, hash)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(credential.password), []byte(currentPassword)) != nil {
		return ErrInvalidCredentials
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoding, err := bcrypt.GenerateFromPassword([]byte(newPassword), PasswordCost)
	if err != nil {
		return fmt.Errorf("encode management password: %w", err)
	}
	return s.repository.replacePassword(ctx, hash, credential, string(encoding))
}

func newOpaqueToken() (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", fmt.Errorf("generate management session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(secret[:]), nil
}

func tokenHash(raw string) []byte {
	digest := sha256.Sum256([]byte(raw))
	return digest[:]
}

func validOpaqueInput(raw string) bool {
	return len(raw) > 0 && len(raw) <= MaxOpaqueTokenBytes
}
