package providersession

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"math"
	"strings"
	"time"

	"icloudspace/internal/provider/apple"
	"icloudspace/internal/sourceguard"
)

type Repository struct {
	DB     *sql.DB
	cfg    Config
	commit func(*sql.Tx) error
}

func New(ctx context.Context, db *sql.DB, cfg Config) (*Service, error) {
	if db == nil || cfg.Registry == nil || cfg.Vault == nil || !text(cfg.InstallationID, 256) {
		return nil, ErrInvalid
	}
	if cfg.Factory == nil {
		cfg.Factory = apple.New
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Options == nil {
		cfg.Options = func(Scope) apple.Options { return apple.Options{} }
	}
	if cfg.PersistenceTimeout == 0 {
		cfg.PersistenceTimeout = 3 * time.Second
	}
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = 10 * time.Minute
	}
	if cfg.MaxChallengeAttempts == 0 {
		cfg.MaxChallengeAttempts = 10
	}
	if cfg.PersistenceTimeout < time.Millisecond || cfg.ChallengeTTL < time.Second || cfg.ChallengeTTL > time.Hour || cfg.MaxChallengeAttempts < 1 || cfg.MaxChallengeAttempts > 20 {
		return nil, ErrInvalid
	}
	if _, err := instant(cfg.Clock()); err != nil {
		return nil, err
	}
	r := &Repository{DB: db, cfg: cfg, commit: (*sql.Tx).Commit}
	if err := r.checkInstallation(ctx, db, false); err != nil {
		return nil, err
	}
	return &Service{repo: r, cfg: cfg}, nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (r *Repository) checkInstallation(ctx context.Context, q queryRower, lock bool) error {
	query := `SELECT i.installation_id,i.writes_enabled,k.proof FROM space.installation i JOIN space.key_binding k USING(singleton) WHERE i.singleton AND k.binding_version=1`
	if lock {
		query += ` FOR SHARE OF i,k`
	}
	var actual string
	var writes bool
	var proof []byte
	if err := q.QueryRowContext(ctx, query).Scan(&actual, &writes, &proof); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrBinding
		}
		return err
	}
	if actual != r.cfg.InstallationID {
		return ErrBinding
	}
	expected, err := r.cfg.Vault.Fingerprint(r.cfg.InstallationID)
	if err != nil || subtle.ConstantTimeCompare(proof, expected[:]) != 1 {
		return ErrBinding
	}
	if lock && !writes {
		return ErrReadOnly
	}
	return nil
}

func readSource(ctx context.Context, tx *sql.Tx, id int64, lock bool) (s source, err error) {
	query := `SELECT s.id,s.revision,s.source_generation,s.credential_generation,s.enabled,p.revision,p.apple_id,p.region,coalesce(p.dsid,''),
 a.source_id,a.principal_revision,a.revision,a.session_envelope,a.authenticated,a.last_validated_at,a.saved_at,a.expires_at
 FROM space.mail_sources s JOIN space.apple_principals p ON p.source_id=s.id LEFT JOIN space.apple_sessions a ON a.source_id=s.id WHERE s.id=$1 AND s.kind<>'custom'`
	if lock {
		query += ` FOR UPDATE OF s,p`
	}
	var storedID, principalRevision, revision, saved sql.NullInt64
	var authenticated sql.NullBool
	err = tx.QueryRowContext(ctx, query, id).Scan(&s.Scope.SourceID, &s.Scope.SourceRevision, &s.Scope.SourceGeneration, &s.Scope.CredentialGeneration, &s.Enabled, &s.Scope.PrincipalRevision, &s.AppleID, &s.Region, &s.DSID,
		&storedID, &principalRevision, &revision, &s.Envelope, &authenticated, &s.Info.LastValidatedAt, &saved, &s.Info.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, err
	}
	s.SessionExists = storedID.Valid
	s.StoredPrincipalRevision = principalRevision.Int64
	s.Info.SourceID = id
	s.Info.PrincipalRevision = s.Scope.PrincipalRevision
	s.Info.Revision = revision.Int64
	s.Info.Authenticated = authenticated.Bool && principalRevision.Int64 == s.Scope.PrincipalRevision
	s.Info.SavedAt = saved.Int64
	return s, nil
}
func (r *Repository) load(ctx context.Context, id int64) (source, error) {
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return source{}, err
	}
	defer tx.Rollback()
	if err = r.checkInstallation(ctx, tx, false); err != nil {
		return source{}, err
	}
	s, err := readSource(ctx, tx, id, false)
	if err != nil {
		return s, err
	}
	if err = tx.Commit(); err != nil {
		return s, err
	}
	return s, nil
}
func sameSource(a, b source) bool {
	return a.Scope == b.Scope && strings.EqualFold(a.AppleID, b.AppleID) && a.Region == b.Region && a.DSID == b.DSID && a.SessionExists == b.SessionExists && a.StoredPrincipalRevision == b.StoredPrincipalRevision && a.Info.Revision == b.Info.Revision && bytes.Equal(a.Envelope, b.Envelope)
}
func actorCheck(ctx context.Context, tx *sql.Tx, actor Actor) error {
	var epoch int64
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT session_epoch,enabled FROM space.operators WHERE id=$1 FOR SHARE`, actor.OperatorID).Scan(&epoch, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrOwner
		}
		return err
	}
	if !enabled || epoch != actor.SessionEpoch {
		return ErrOwner
	}
	return nil
}

type sessionWrite struct {
	expected source
	info     SessionInfo
	envelope []byte
	document apple.SessionDocument
}

func (r *Repository) encodeSession(expected source, document apple.SessionDocument, authenticated bool) (sessionWrite, error) {
	w := sessionWrite{expected: expected, document: document}
	if expected.Info.Revision == math.MaxInt64 {
		return w, ErrStale
	}
	if !strings.EqualFold(document.Principal.AppleID, expected.AppleID) || document.Principal.Region != expected.Region || expected.DSID != "" && document.Principal.DSID != expected.DSID {
		return w, ErrBinding
	}
	plain, err := apple.EncodeSession(document)
	if err != nil {
		return w, ErrBinding
	}
	aad, err := binding(r.cfg.InstallationID, expected.Scope)
	if err != nil {
		return w, err
	}
	encoded, err := r.cfg.Vault.Seal(aad, plain)
	if err != nil {
		return w, ErrBinding
	}
	now, err := instant(r.cfg.Clock())
	if err != nil {
		return w, err
	}
	w.envelope = []byte(encoded)
	w.info = SessionInfo{SourceID: expected.Scope.SourceID, PrincipalRevision: expected.Scope.PrincipalRevision, Revision: expected.Info.Revision + 1, Authenticated: authenticated, SavedAt: now, LastValidatedAt: document.ValidatedAtUnixNano}
	// Only this actual auth cookie supplies an expiry. Analytics/trust-cookie
	// dates cannot silently shorten or extend the authenticated web session.
	for _, cookie := range document.Cookies {
		if cookie.Name != "X-APPLE-WEBAUTH-TOKEN" || cookie.ExpiresAt == "" {
			continue
		}
		at, e := time.Parse(time.RFC3339Nano, cookie.ExpiresAt)
		if e != nil {
			continue
		}
		n, e := instant(at)
		if e == nil && (w.info.ExpiresAt == nil || n < *w.info.ExpiresAt) {
			n := n
			w.info.ExpiresAt = &n
		}
	}
	return w, nil
}
func applySession(ctx context.Context, tx *sql.Tx, w sessionWrite) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO space.apple_sessions(source_id,principal_revision,revision,session_envelope,authenticated,last_validated_at,saved_at,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(source_id) DO UPDATE SET principal_revision=EXCLUDED.principal_revision,revision=EXCLUDED.revision,session_envelope=EXCLUDED.session_envelope,authenticated=EXCLUDED.authenticated,last_validated_at=EXCLUDED.last_validated_at,saved_at=EXCLUDED.saved_at,expires_at=EXCLUDED.expires_at`,
		w.info.SourceID, w.info.PrincipalRevision, w.info.Revision, w.envelope, w.info.Authenticated, w.info.LastValidatedAt, w.info.SavedAt, w.info.ExpiresAt)
	return err
}

func (r *Repository) save(ctx context.Context, gate *sourceguard.Lease, w sessionWrite, actor *Actor, expectedChallenge, nextChallenge *challenge, expireOthers bool) error {
	if !gate.ValidFor(r.cfg.Registry, w.expected.Scope.SourceID) {
		return ErrGuard
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = r.checkInstallation(ctx, tx, true); err != nil {
		return err
	}
	current, err := readSource(ctx, tx, w.expected.Scope.SourceID, true)
	if err != nil {
		return err
	}
	if !sameSource(current, w.expected) {
		return ErrStale
	}
	if actor != nil {
		if err = actorCheck(ctx, tx, *actor); err != nil {
			return err
		}
	}
	if expectedChallenge != nil {
		var revision int64
		var envelope []byte
		err = tx.QueryRowContext(ctx, `SELECT revision,challenge_envelope FROM space.apple_challenges WHERE challenge_hash=$1 AND source_id=$2 FOR UPDATE`, expectedChallenge.Hash, w.expected.Scope.SourceID).Scan(&revision, &envelope)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		if err != nil {
			return err
		}
		if revision != expectedChallenge.Revision || !bytes.Equal(envelope, expectedChallenge.Envelope) {
			return ErrStale
		}
	}
	if err = applySession(ctx, tx, w); err != nil {
		return err
	}
	if w.document.ValidatedAtUnixNano != nil && w.expected.DSID == "" && w.document.Principal.DSID != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE space.apple_principals SET dsid=$2 WHERE source_id=$1 AND revision=$3 AND (dsid IS NULL OR dsid='')`, w.info.SourceID, w.document.Principal.DSID, w.info.PrincipalRevision); err != nil {
			return err
		}
	}
	if expireOthers {
		_, err = tx.ExecContext(ctx, `UPDATE space.apple_challenges SET state='expired',revision=revision+1 WHERE source_id=$1 AND state IN ('password','mfa')`, w.info.SourceID)
		if err != nil {
			return err
		}
	}
	if nextChallenge != nil {
		if err = writeChallenge(ctx, tx, *nextChallenge, w.info.SourceID); err != nil {
			return err
		}
	}
	commit := r.commit
	if commit == nil {
		commit = (*sql.Tx).Commit
	}
	if err = commit(tx); err == nil {
		return nil
	}
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.cfg.PersistenceTimeout)
	defer cancel()
	if r.confirm(lookup, w, nextChallenge) == nil {
		return nil
	}
	return ErrUnknown
}
func (r *Repository) confirm(ctx context.Context, w sessionWrite, expectedChallenge *challenge) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A plain read could see the old capsule while an unacknowledged COMMIT
	// still owns its source lock. Join that owner before interpreting evidence.
	current, err := readSource(ctx, tx, w.info.SourceID, true)
	if err != nil {
		return err
	}
	if current.Scope != w.expected.Scope || current.Info.Revision != w.info.Revision || current.StoredPrincipalRevision != w.info.PrincipalRevision || !bytes.Equal(current.Envelope, w.envelope) || current.Info.Authenticated != w.info.Authenticated {
		return ErrUnknown
	}
	if expectedChallenge != nil {
		var revision int64
		var envelope []byte
		err = tx.QueryRowContext(ctx, `SELECT revision,challenge_envelope FROM space.apple_challenges WHERE challenge_hash=$1 AND source_id=$2`, expectedChallenge.Hash, w.info.SourceID).Scan(&revision, &envelope)
		if err != nil || revision != expectedChallenge.Revision || !bytes.Equal(envelope, expectedChallenge.Envelope) {
			return ErrUnknown
		}
	}
	return tx.Commit()
}
