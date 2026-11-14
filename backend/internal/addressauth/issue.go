package addressauth

import (
	"context"
	"database/sql"
	"strconv"
	"sync"

	"icloudspace/internal/operationlog"
	"icloudspace/internal/sourceguard"
)

type Profile string

const (
	APIOnly Profile = "api_key_only"
	Mailbox Profile = "mailbox"
)

type IssueRequest struct {
	SourceID, AddressID, Generation int64
	Profile                         Profile
	OwnerKey                        string
}

// IssueScope is acquired after the caller's sourceguard and before opening its
// address transaction. Close is required only after COMMIT/ROLLBACK (including
// COMMIT-unknown handling); releasing after Stage would allow full rotation to
// overlook an uncommitted new address. It must not span remote provider I/O.
type IssueScope struct {
	authority *Authority
	mu        sync.Mutex
	release   func()
	closed    bool
}

func (a *Authority) BeginIssue(ctx context.Context) (*IssueScope, error) {
	if a == nil {
		return nil, ErrInvalid
	}
	r, e := a.gate.read(ctx)
	if e != nil {
		return nil, e
	}
	if !a.readReady() {
		r()
		return nil, ErrOutcomeUnknown
	}
	return &IssueScope{authority: a, release: r}, nil
}
func (s *IssueScope) Close() error {
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.closed {
			s.closed = true
			s.release()
		}
	}
	return nil
}

// TransferReveal retains the same admission lease across a committed issue and
// its response. The caller must end its SQL transaction first. There is no
// second read admission that could deadlock behind an already queued rotation.
func (s *IssueScope) TransferReveal() (*RevealScope, error) {
	if s == nil {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.authority.readReady() {
		return nil, ErrOutcomeUnknown
	}
	out := &RevealScope{a: s.authority, release: s.release}
	s.closed = true
	s.release = nil
	return out, nil
}

// MarkSourceUncertain prevents fresh authority admission until a query has
// waited for the original source transaction to settle. It does not retry or
// roll back an unacknowledged registration.
func (s *IssueScope) MarkSourceUncertain(held *sourceguard.Lease) error {
	if s == nil || held == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !held.ValidFor(s.authority.guards, held.SourceID()) {
		return ErrInvalid
	}
	s.authority.uncertain.Store(sourceChangeKey{held.SourceID()}, true)
	return nil
}

// Stage writes only canonical grant facts and owner-bound secret documents in
// the caller's transaction. Nothing is revealed here. Pending delivery remains
// explicitly unacknowledged until the management owner confirms receipt.
func (s *IssueScope) Stage(ctx context.Context, tx *sql.Tx, r IssueRequest) error {
	if s == nil || tx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrInvalid
	}
	if r.SourceID < 1 || r.AddressID < 1 || r.Generation < 1 || !validKey(r.OwnerKey) || (r.Profile != APIOnly && r.Profile != Mailbox) {
		return ErrInvalid
	}
	a := s.authority
	if e := a.checkWritable(ctx, tx); e != nil {
		return e
	}
	var source, address, generation int64
	if tx.QueryRowContext(ctx, `SELECT source_id,id,auth_generation FROM space.private_addresses WHERE source_id=$1 AND id=$2 FOR UPDATE`, r.SourceID, r.AddressID).Scan(&source, &address, &generation) != nil || generation != r.Generation {
		return ErrConflict
	}
	var existing int
	if tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM space.address_grants WHERE address_id=$1)+(SELECT count(*) FROM space.address_credential_bundles WHERE address_id=$1)+(SELECT count(*) FROM space.pending_reveals WHERE address_id=$1)`, address).Scan(&existing) != nil {
		return storageError(ctx)
	}
	if existing != 0 {
		return ErrConflict
	}
	b, e := Generate()
	if e != nil {
		return e
	}
	now := a.clock()
	owner := Owner{InstallationID: a.installationID, AddressID: address, Generation: generation}
	if r.Profile == Mailbox {
		envelope, e := SealBundle(a.box, owner, b)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO space.address_credential_bundles(address_id,source_id,bundle_envelope,bundle_version,auth_generation,updated_at) VALUES($1,$2,$3,$4,$5,$6)`, address, source, envelope, DocumentVersion, generation, now); e != nil {
			return storageError(ctx)
		}
		for _, g := range []struct{ purpose, kind, raw string }{{"imap_login", "imap_password", b.IMAP.Password}, {"oauth_client", "client_id", b.OAuth.ClientID}, {"oauth_refresh", "refresh_token", b.OAuth.RefreshToken}} {
			hash := Hash(g.raw)
			if e = insertGrant(ctx, tx, source, address, generation, g.purpose, g.kind, hash[:], now, nil); e != nil {
				return e
			}
		}
	}
	for _, p := range []Purpose{MailRead, MailConsume, RawRead} {
		hash := Hash(b.API.Key)
		if e = insertGrant(ctx, tx, source, address, generation, string(p), string(APIKey), hash[:], now, nil); e != nil {
			return e
		}
	}
	_, e = a.stagePending(ctx, tx, source, address, generation, b.API.Key, r.OwnerKey, now)
	if e != nil {
		return e
	}
	if e = operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: now, Action: "credentials.issue", ResourceKind: "address", ResourceRef: strconv.FormatInt(address, 10), Outcome: "success", SourceID: &source, Fields: map[string]string{"operation_kind": string(r.Profile)}})); e != nil {
		return storageError(ctx)
	}
	return nil
}

func validKey(s string) bool { return len(s) <= 256 && validSecret(s) }
func (a *Authority) stagePending(ctx context.Context, tx *sql.Tx, source, address, generation int64, key, ownerKey string, now int64) (string, error) {
	envelope, e := SealPending(a.box, Owner{InstallationID: a.installationID, AddressID: address, Generation: generation}, Pending{Version: 1, APIKey: key})
	if e != nil {
		return "", e
	}
	delivery, e := opaque("delivery_")
	if e != nil {
		return "", e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO space.pending_reveals(source_id,address_id,delivery_key,owner_key,secret_envelope,auth_generation,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, source, address, delivery, ownerKey, envelope, generation, now)
	if e != nil {
		return "", storageError(ctx)
	}
	return delivery, nil
}
