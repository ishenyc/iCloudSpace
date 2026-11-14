// Package providersession owns canonical Apple capsules and explicit auth
// requests. It never discovers a password, silently logs in, or replays an
// uncertain provider action.
package providersession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"icloudspace/internal/provider/apple"
	"icloudspace/internal/sourceguard"
	"icloudspace/internal/vault"
)

var (
	ErrInvalid        = errors.New("providersession: invalid input")
	ErrNotFound       = errors.New("providersession: source or request absent")
	ErrStale          = errors.New("providersession: source or capsule changed")
	ErrLoginRequired  = errors.New("providersession: authentication required")
	ErrBinding        = errors.New("providersession: capsule binding rejected")
	ErrOwner          = errors.New("providersession: request owner rejected")
	ErrReadOnly       = errors.New("providersession: installation writes disabled")
	ErrUnknown        = errors.New("providersession: persistence outcome unknown")
	ErrRequestUnknown = errors.New("providersession: provider action outcome unknown")
	ErrExpired        = errors.New("providersession: challenge expired")
	ErrAttempts       = errors.New("providersession: local challenge attempt limit reached")
	ErrGuard          = errors.New("providersession: held source guard required")
	ErrTimestampRange = errors.New("providersession: timestamp outside signed nanosecond range")
)

type Scope struct {
	SourceID             int64 `json:"source_id"`
	SourceRevision       int64 `json:"source_revision"`
	SourceGeneration     int64 `json:"source_generation"`
	CredentialGeneration int64 `json:"credential_generation"`
	PrincipalRevision    int64 `json:"principal_revision"`
}
type Actor struct {
	OperatorID   int64
	SessionEpoch int64
}
type SessionInfo struct {
	SourceID          int64
	PrincipalRevision int64
	Revision          int64
	Authenticated     bool
	SavedAt           int64
	LastValidatedAt   *int64
	ExpiresAt         *int64
}
type source struct {
	Scope                   Scope
	Enabled                 bool
	AppleID                 string
	Region                  apple.Region
	DSID                    string
	SessionExists           bool
	StoredPrincipalRevision int64
	Info                    SessionInfo
	Envelope                []byte
}
type Factory func(apple.SessionDocument, apple.Options) (*apple.Client, error)
type Config struct {
	InstallationID       string
	Registry             *sourceguard.Registry
	Vault                *vault.Vault
	Options              func(Scope) apple.Options
	Factory              Factory
	Clock                func() time.Time
	PersistenceTimeout   time.Duration
	ChallengeTTL         time.Duration
	MaxChallengeAttempts int
}

type Action string

const (
	Login               Action = "login"
	LoadChallenge       Action = "load_challenge"
	SendDeviceCode      Action = "send_device_code"
	VerifyDeviceCode    Action = "verify_device_code"
	SendSMS             Action = "send_sms"
	VerifySMS           Action = "verify_sms"
	VerifySecurityKey   Action = "verify_security_key"
	TrustBrowser        Action = "trust_browser"
	ExchangeToken       Action = "exchange_token"
	ValidateSession     Action = "validate_session"
	RestoreSession      Action = "restore_session"
	ClearAuthentication Action = "clear_authentication"
)

type Outcome string

const (
	Accepted Outcome = "accepted"
	Rejected Outcome = "rejected"
	Unknown  Outcome = "unknown"
	NotSent  Outcome = "not_sent"
)

type ActionReceipt struct {
	RequestKey string  `json:"request_key"`
	Action     Action  `json:"action"`
	Outcome    Outcome `json:"outcome"`
	ErrorCode  string  `json:"error_code,omitempty"`
	Prepared   bool    `json:"prepared"`
	StartedAt  int64   `json:"started_at"`
	FinishedAt *int64  `json:"finished_at,omitempty"`
	Target     string  `json:"target,omitempty"`
	Mode       string  `json:"mode,omitempty"`
}
type challengeDocument struct {
	Version         int             `json:"version"`
	Scope           Scope           `json:"scope"`
	OperatorEpoch   int64           `json:"operator_epoch"`
	Token           string          `json:"token"`
	SessionRevision int64           `json:"session_revision"`
	Receipts        []ActionReceipt `json:"receipts"`
}
type challenge struct {
	Hash              []byte
	OperatorID        int64
	PrincipalRevision int64
	Revision          int64
	SessionRevision   int64
	RequestKey        string
	State             string
	Attempts          int
	CreatedAt         int64
	ExpiresAt         int64
	Envelope          []byte
	Document          challengeDocument
}
type AuthResult struct {
	RequestKey             string
	ChallengeToken         string
	ChallengeRevision      int64
	State                  string
	Session                SessionInfo
	Receipt                ActionReceipt
	Options                *apple.AuthOptions
	NextAction             Action
	RequestSessionRevision int64
}
type AuthInput struct {
	SourceID       int64
	Actor          Actor
	ChallengeToken string
	RequestKey     string
	Action         Action
	Code           string
	PhoneID        string
	Mode           string
	Assertion      *apple.SecurityKeyAssertion
}

// PersistenceError keeps remote and SQL uncertainty separate. Neither error
// contains a capsule/password/code; callers must not replay the provider action.
type PersistenceError struct {
	Provider    error
	Persistence error
}

func (e *PersistenceError) Error() string {
	return "providersession: provider snapshot could not be acknowledged"
}
func (e *PersistenceError) Unwrap() []error { return []error{e.Provider, e.Persistence} }

func binding(installation string, s Scope) (vault.Binding, error) {
	return apple.SessionBinding(installation, s.SourceID, s.PrincipalRevision)
}
func challengeBinding(installation string, s Scope, operatorID int64, hash []byte) (vault.Binding, error) {
	if installation == "" || len(hash) != sha256.Size || s.SourceID < 1 || s.PrincipalRevision < 1 || operatorID < 1 {
		return vault.Binding{}, ErrBinding
	}
	return vault.Binding{InstallationID: installation, SubjectType: "apple_challenge", SubjectID: strconv.FormatInt(s.SourceID, 10) + ":" + strconv.FormatInt(operatorID, 10) + ":" + hex.EncodeToString(hash), Purpose: "auth_request", Revision: uint64(s.PrincipalRevision)}, nil
}
func instant(t time.Time) (int64, error) {
	n := t.UnixNano()
	if !time.Unix(0, n).Equal(t) {
		return 0, ErrTimestampRange
	}
	return n, nil
}
func text(v string, max int) bool {
	return len(v) > 0 && len(v) <= max && !strings.ContainsAny(v, "\x00\r\n")
}
func requestKey(v string) bool {
	if len(v) < 8 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-", c)) {
			return false
		}
	}
	return true
}
func actorValid(a Actor) bool { return a.OperatorID > 0 && a.SessionEpoch > 0 }
func scopeValid(s Scope) bool {
	return s.SourceID > 0 && s.SourceRevision > 0 && s.SourceGeneration > 0 && s.CredentialGeneration > 0 && s.PrincipalRevision > 0
}
func safeCode(err error) string {
	var provider *apple.Error
	if errors.As(err, &provider) {
		return string(provider.Kind)
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if err != nil {
		return "provider_failed"
	}
	return ""
}
func actionOutcome(err error) Outcome {
	if err == nil {
		return Accepted
	}
	var provider *apple.Error
	if errors.As(err, &provider) {
		if provider.Operation == "authorize_shell" {
			return NotSent
		}
		if provider.Unknown {
			return Unknown
		}
		if provider.Kind == apple.SecondFactorRequired {
			return Accepted
		}
		if provider.Kind == apple.Invalid {
			return NotSent
		}
	}
	return Rejected
}
func tokenHash(token string) ([]byte, error) {
	b, err := hex.DecodeString(token)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != token {
		return nil, ErrInvalid
	}
	h := sha256.Sum256(b)
	return h[:], nil
}
func plainChallenge(c challengeDocument) ([]byte, error) {
	if c.Version != 1 || !scopeValid(c.Scope) || c.OperatorEpoch < 1 || len(c.Token) != 64 || c.SessionRevision < 1 || len(c.Receipts) < 1 || len(c.Receipts) > 24 {
		return nil, ErrInvalid
	}
	seen := make(map[string]bool, len(c.Receipts))
	for _, r := range c.Receipts {
		if !requestKey(r.RequestKey) || seen[r.RequestKey] || len(r.ErrorCode) > 80 || len(r.Target) > 64 || len(r.Mode) > 16 {
			return nil, ErrInvalid
		}
		seen[r.RequestKey] = true
		switch r.Outcome {
		case Accepted, Rejected, Unknown, NotSent:
		default:
			return nil, ErrInvalid
		}
		if r.Prepared && r.Outcome != Unknown {
			return nil, ErrInvalid
		}
	}
	b, err := json.Marshal(c)
	if err != nil || len(b) > 32<<10 {
		return nil, ErrInvalid
	}
	return b, nil
}
