package addressauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"icloudspace/internal/pgschema"
	"icloudspace/internal/sourceguard"
	"icloudspace/internal/vault"
)

var (
	ErrUnauthenticated = errors.New("addressauth: authenticator rejected")
	ErrInvalid         = errors.New("addressauth: invalid request")
	ErrInstallation    = errors.New("addressauth: installation binding rejected")
	ErrStorage         = errors.New("addressauth: storage operation failed")
	ErrReadOnly        = errors.New("addressauth: installation writes are disabled")
	ErrConflict        = errors.New("addressauth: request conflicts with current state")
	ErrOutcomeUnknown  = errors.New("addressauth: write acknowledgement unknown; query required")
	ErrUnavailable     = errors.New("addressauth: requested secret material unavailable")
)

type Purpose string

const (
	LatestRead  Purpose = "latest_read"
	MailRead    Purpose = "mail_read"
	MailConsume Purpose = "mail_consume"
	RawRead     Purpose = "raw_read"
	IMAPLogin   Purpose = "imap_login"
)

type Kind string

const (
	APIKey       Kind = "api_key"
	IMAPPassword Kind = "imap_password"
	Access       Kind = "opaque"
)

type Credential struct {
	Kind Kind
	Raw  string
}

func (Credential) String() string   { return "addressauth: private authenticator" }
func (Credential) GoString() string { return "addressauth: private authenticator" }

type Selector struct {
	AddressID int64
	Email     string
}
type Identity struct {
	SourceID, AddressID, SourceGeneration, Generation int64
	UIDValidity                                       int64
	Email                                             string
}

// Handle is the minimum verified connection binding. IMAP keeps this instead
// of raw credentials; every command obtains a new lease with Renew. It is not
// wire data and cannot be constructed outside this owner.
type Handle struct {
	identity Identity
	kind     Kind
	hash     [32]byte
	verified bool
}

func (Handle) String() string   { return "addressauth: private connection handle" }
func (Handle) GoString() string { return "addressauth: private connection handle" }

// Lease protects the whole sensitive operation against credential revocation.
// It deliberately holds no source/network lock or SQL transaction: local OTP
// reads must not wait for IMAP and consume must not self-deadlock on row writes.
type Lease struct {
	authority *Authority
	identity  Identity
	purpose   Purpose
	handle    Handle
	uidNext   uint64
	release   func()
	active    atomic.Bool
	once      sync.Once
}

// ValidFor binds a feature's injected authority to the still-active lease.
// Identity values alone cannot prove ownership by this installation instance.
func (l *Lease) ValidFor(authority *Authority) bool {
	return l != nil && authority != nil && l.authority == authority && l.active.Load()
}

// RevalidateTx refreshes natural expiry and eligibility after a caller's SQL
// lock wait. It reuses the existing admission lease rather than reacquiring a
// read barrier behind a queued rotation. The caller still owns and closes l.
func (l *Lease) RevalidateTx(ctx context.Context, tx *sql.Tx) error {
	if l == nil || tx == nil || !l.ValidFor(l.authority) {
		return ErrUnauthenticated
	}
	purpose := l.purpose
	if purpose == RecentConsume {
		purpose = LatestRead
	}
	identity, err := l.authority.resolveWith(ctx, tx, l.handle.kind, l.handle.hash, purpose,
		Selector{AddressID: l.identity.AddressID, Email: l.identity.Email}, l.authority.clock())
	if err != nil {
		return err
	}
	if identity != l.identity {
		return ErrUnauthenticated
	}
	return nil
}

func (l *Lease) Identity() Identity {
	if l == nil || !l.active.Load() {
		return Identity{}
	}
	return l.identity
}
func (l *Lease) Handle() Handle {
	if l == nil || !l.active.Load() {
		return Handle{}
	}
	return l.handle
}

// InitialUIDNext belongs to the same read snapshot that admitted this lease.
// IMAP may use it immediately after renewing a command, never as a later poll
// cache: SELECT's before/after reads and an existing command lease still need
// the mailbox view's fresh metadata query.
func (l *Lease) InitialUIDNext(authority *Authority) (uint64, bool) {
	if !l.ValidFor(authority) || l.purpose != IMAPLogin {
		return 0, false
	}
	return l.uidNext, true
}
func (l *Lease) Purpose() Purpose {
	if l == nil || !l.active.Load() {
		return ""
	}
	return l.purpose
}
func (l *Lease) Close() error {
	if l != nil {
		l.once.Do(func() {
			l.active.Store(false)
			if l.release != nil {
				l.release()
			}
		})
	}
	return nil
}
func (*Lease) String() string   { return "addressauth: sensitive read lease" }
func (*Lease) GoString() string { return "addressauth: sensitive read lease" }

// Authority must be constructed once by the application root and shared by
// HTTP, IMAP, issuers, reveal and rotation. The pool and Registry are injected
// and owned by the root; no per-transport Authority or hidden global exists.
type Authority struct {
	db             *sql.DB
	installationID string
	box            *vault.Vault
	guards         *sourceguard.Registry
	clock          func() int64
	gate           credentialGate
	commit         func(*sql.Tx) error
	uncertain      sync.Map
}

func (*Authority) String() string   { return "addressauth: credential authority" }
func (*Authority) GoString() string { return "addressauth: credential authority" }

func NewAuthority(ctx context.Context, db *sql.DB, installationID string, box *vault.Vault, guards *sourceguard.Registry, clock func() int64) (*Authority, error) {
	if db == nil || box == nil || guards == nil || installationID == "" || len(installationID) > 256 || !utf8.ValidString(installationID) {
		return nil, ErrInvalid
	}
	if pgschema.Check(ctx, db) != nil {
		return nil, ErrInstallation
	}
	var actual string
	var proof []byte
	if db.QueryRowContext(ctx, `SELECT i.installation_id,k.proof FROM space.installation i JOIN space.key_binding k ON k.singleton=i.singleton WHERE i.singleton AND k.binding_version=1`).Scan(&actual, &proof) != nil || actual != installationID {
		return nil, ErrInstallation
	}
	want, err := box.Fingerprint(installationID)
	if err != nil || subtle.ConstantTimeCompare(proof, want[:]) != 1 {
		return nil, ErrInstallation
	}
	if clock == nil {
		clock = func() int64 { return time.Now().UnixNano() }
	}
	return &Authority{db: db, installationID: installationID, box: box, guards: guards, clock: clock, commit: func(tx *sql.Tx) error { return tx.Commit() }}, nil
}

func validPurpose(p Purpose) bool {
	return p == LatestRead || p == MailRead || p == MailConsume || p == RawRead || p == IMAPLogin
}
func validKind(k Kind) bool { return k == APIKey || k == IMAPPassword || k == Access }
func normalizeSelector(s Selector) (Selector, error) {
	if s.AddressID < 0 || len(s.Email) > 320 || !utf8.ValidString(s.Email) || strings.ContainsAny(s.Email, "\x00\r\n") {
		return Selector{}, ErrInvalid
	}
	s.Email = strings.ToLower(strings.TrimSpace(s.Email))
	return s, nil
}

// No secret is normalized or parsed as an old token/codec. Kind is an explicit
// canonical transport choice; client ID and refresh token are never kinds.
func (a *Authority) Authenticate(ctx context.Context, credential Credential, purpose Purpose, selector Selector) (*Lease, error) {
	if a == nil || !validKind(credential.Kind) || !validPurpose(purpose) || !validSecret(credential.Raw) {
		return nil, ErrUnauthenticated
	}
	selector, err := normalizeSelector(selector)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	release, err := a.gate.read(ctx)
	if err != nil {
		return nil, err
	}
	if !a.readReady() {
		release()
		return nil, ErrOutcomeUnknown
	}
	state, err := a.resolveStateWith(ctx, a.db, credential.Kind, Hash(credential.Raw), purpose, selector, a.clock())
	if err != nil {
		release()
		return nil, err
	}
	return a.newLease(state, credential.Kind, Hash(credential.Raw), purpose, release), nil
}

func (a *Authority) Renew(ctx context.Context, handle Handle, purpose Purpose) (*Lease, error) {
	if a == nil || !handle.verified || !validKind(handle.kind) || !validPurpose(purpose) {
		return nil, ErrUnauthenticated
	}
	release, err := a.gate.read(ctx)
	if err != nil {
		return nil, err
	}
	if !a.readReady() {
		release()
		return nil, ErrOutcomeUnknown
	}
	state, err := a.resolveStateWith(ctx, a.db, handle.kind, handle.hash, purpose, Selector{AddressID: handle.identity.AddressID, Email: handle.identity.Email}, a.clock())
	if err != nil || state.identity != handle.identity {
		release()
		if err != nil {
			return nil, err
		}
		return nil, ErrUnauthenticated
	}
	return a.newLease(state, handle.kind, handle.hash, purpose, release), nil
}

func (a *Authority) readReady() bool {
	ready := true
	a.uncertain.Range(func(_, _ any) bool { ready = false; return false })
	return ready
}

type grantState struct {
	identity Identity
	uidNext  uint64
}

func (a *Authority) newLease(state grantState, kind Kind, hash [32]byte, purpose Purpose, release func()) *Lease {
	lease := &Lease{authority: a, identity: state.identity, uidNext: state.uidNext, purpose: purpose, handle: Handle{identity: state.identity, kind: kind, hash: hash, verified: true}, release: release}
	lease.active.Store(true)
	return lease
}

type grantReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (a *Authority) resolveWith(ctx context.Context, reader grantReader, kind Kind, hash [32]byte, purpose Purpose, selector Selector, now int64) (Identity, error) {
	state, err := a.resolveStateWith(ctx, reader, kind, hash, purpose, selector, now)
	return state.identity, err
}

func (a *Authority) resolveStateWith(ctx context.Context, reader grantReader, kind Kind, hash [32]byte, purpose Purpose, selector Selector, now int64) (grantState, error) {
	rows, err := reader.QueryContext(ctx, `SELECT DISTINCT s.id,a.id,s.source_generation,a.auth_generation,a.uid_validity,a.normalized_email,a.uid_next
FROM space.address_grants g JOIN space.private_addresses a ON a.source_id=g.source_id AND a.id=g.address_id
JOIN space.mail_sources s ON s.id=a.source_id
WHERE g.authenticator_kind=$1 AND g.authenticator_hash=$2 AND g.hash_scheme=$3 AND g.hash_version=$4 AND g.purpose=$5
AND g.auth_generation=a.auth_generation AND g.revoked_at IS NULL AND g.issued_at<=$6 AND (g.expires_at IS NULL OR g.expires_at>$6)
AND a.lifecycle='confirmed' AND a.deleted_at IS NULL AND a.enabled AND s.enabled AND s.retired_at IS NULL
`+validAncestry("$6")+`
AND ($7::bigint=0 OR a.id=$7) AND ($8::text='' OR a.normalized_email=$8) LIMIT 2`, string(kind), hash[:], HashScheme, HashVersion, string(purpose), now, selector.AddressID, selector.Email)
	if err != nil {
		if ctx.Err() != nil {
			return grantState{}, ctx.Err()
		}
		return grantState{}, ErrStorage
	}
	defer rows.Close()
	var result grantState
	count := 0
	for rows.Next() {
		id := &result.identity
		if rows.Scan(&id.SourceID, &id.AddressID, &id.SourceGeneration, &id.Generation, &id.UIDValidity, &id.Email, &result.uidNext) != nil {
			return grantState{}, ErrStorage
		}
		count++
	}
	if rows.Err() != nil {
		if ctx.Err() != nil {
			return grantState{}, ctx.Err()
		}
		return grantState{}, ErrStorage
	}
	if count != 1 {
		return grantState{}, ErrUnauthenticated
	}
	return result, nil
}

// Callers validate the selected grant's generation, hash and time bounds first.
// A root has no parent edges to inspect. Derived grants remain subordinate to
// every ancestor; UNION terminates malformed cycles and requiring a root also
// rejects a cycle with no authority. Only static SQL placeholders enter here.
func validAncestry(now string) string {
	return `AND (g.parent_grant_id IS NULL OR (WITH RECURSIVE chain AS (
 SELECT id,source_id,address_id,parent_grant_id,auth_generation,hash_scheme,hash_version,authenticator_hash,issued_at,expires_at,revoked_at FROM space.address_grants WHERE id=g.id
 UNION SELECT p.id,p.source_id,p.address_id,p.parent_grant_id,p.auth_generation,p.hash_scheme,p.hash_version,p.authenticator_hash,p.issued_at,p.expires_at,p.revoked_at FROM space.address_grants p JOIN chain c ON p.id=c.parent_grant_id AND p.source_id=c.source_id AND p.address_id=c.address_id)
	 SELECT COALESCE(bool_and(auth_generation=a.auth_generation AND hash_scheme='sha256-raw' AND hash_version=1 AND octet_length(authenticator_hash)=32 AND revoked_at IS NULL AND issued_at<=` + now + ` AND (expires_at IS NULL OR expires_at>` + now + `)) AND bool_or(parent_grant_id IS NULL),false) FROM chain))`
}

// CurrentGrantMetadataSQL is a fixed projection predicate for the repository's
// trusted alias g. It keeps advertised capabilities aligned with authentication
// without exposing hashes or introducing a per-address authentication query.
func CurrentGrantMetadataSQL() string {
	return currentGrantFactsSQL("space.clock_ns()") + `
` + validAncestry("space.clock_ns()")
}

func currentGrantFactsSQL(now string) string {
	return `g.auth_generation=a.auth_generation AND g.hash_scheme='sha256-raw' AND g.hash_version=1 AND octet_length(g.authenticator_hash)=32
AND g.issued_at<=` + now + ` AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>` + now + `)`
}

// CurrentGrantSetMetadataSQL validates the grant forest once for the caller's
// materialized selected_addresses relation. Root traversal excludes orphaned
// cycles; each non-root grant has one parent, so a rooted path cannot cycle.
// The names and SQL are fixed and accept no external identifier or expression.
func CurrentGrantSetMetadataSQL() string {
	// Metadata is one read snapshot at one database clock point. Actual access
	// continues through Authenticate/Renew; this projection never grants access.
	return `metadata_clock AS MATERIALIZED (SELECT space.clock_ns() AS now),` + currentGrantSetSQL("(SELECT now FROM metadata_clock)")
}

// Only the two fixed clock expressions above and in export.go are used here.
// Effective expiry includes every parent and is rechecked before export emits.
func currentGrantSetSQL(now string) string {
	// Let root/child predicates reach the grant scan. Materializing all eligible
	// roots first copies their full rows even when the child forest is empty.
	return `eligible_grants AS NOT MATERIALIZED (
 SELECT g.id,g.source_id,g.address_id,g.parent_grant_id,g.purpose,g.authenticator_kind,g.authenticator_hash,g.expires_at
 FROM space.address_grants g JOIN selected_addresses a ON a.source_id=g.source_id AND a.id=g.address_id
 WHERE a.lifecycle='confirmed' AND a.deleted_at IS NULL AND ` + currentGrantFactsSQL(now) + `),
 grant_children AS MATERIALIZED (SELECT * FROM eligible_grants WHERE parent_grant_id IS NOT NULL),
 valid_descendants AS (
 SELECT g.id,g.source_id,g.address_id,g.parent_grant_id,g.purpose,g.authenticator_kind,g.authenticator_hash,least(g.expires_at,p.expires_at) AS expires_at
 FROM grant_children g JOIN eligible_grants p ON p.id=g.parent_grant_id AND p.source_id=g.source_id AND p.address_id=g.address_id AND p.parent_grant_id IS NULL
 UNION ALL
 SELECT g.id,g.source_id,g.address_id,g.parent_grant_id,g.purpose,g.authenticator_kind,g.authenticator_hash,least(g.expires_at,p.expires_at)
 FROM grant_children g JOIN valid_descendants p ON p.id=g.parent_grant_id AND p.source_id=g.source_id AND p.address_id=g.address_id
 ),
 current_grants AS NOT MATERIALIZED (
 SELECT * FROM eligible_grants WHERE parent_grant_id IS NULL
 UNION ALL SELECT * FROM valid_descendants
 )`
}
