package adminauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"icloudspace/internal/operationlog"
)

// SQLRepository uses the canonical space schema and an externally owned pool.
// Constructing it does not open a connection or create any schema/operator.
type SQLRepository struct {
	db *sql.DB
}

func NewSQLRepository(db *sql.DB) (*SQLRepository, error) {
	if db == nil {
		return nil, errors.New("adminauth: nil database pool")
	}
	return &SQLRepository{db: db}, nil
}

type passwordSnapshot struct {
	operator Operator
	password string
	epoch    int64
	enabled  bool
}

func (r *SQLRepository) passwordForLogin(ctx context.Context, username string) (passwordSnapshot, bool, error) {
	var result passwordSnapshot
	err := r.db.QueryRowContext(ctx, `
SELECT id,login_name,password_encoding,session_epoch,enabled
FROM space.operators WHERE lower(login_name)=lower($1::text)`, username).Scan(
		&result.operator.ID, &result.operator.Username, &result.password, &result.epoch, &result.enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return passwordSnapshot{}, false, nil
	}
	if err != nil {
		return passwordSnapshot{}, false, fmt.Errorf("read management credential: %w", err)
	}
	return result, true, nil
}

func (r *SQLRepository) activeSession(ctx context.Context, hash []byte) (Session, error) {
	var result Session
	var expiry int64
	err := r.db.QueryRowContext(ctx, `
SELECT o.id,o.login_name,s.expires_at,s.csrf_hash,s.session_epoch
FROM space.operator_sessions s JOIN space.operators o ON o.id=s.operator_id
WHERE s.session_hash=$1 AND s.hash_version=$2 AND s.revoked_at IS NULL
  AND s.expires_at>space.clock_ns() AND o.enabled AND s.session_epoch=o.session_epoch`,
		hash, SessionHashVersion).Scan(&result.Operator.ID, &result.Operator.Username, &expiry, &result.csrfHash, &result.epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrUnauthenticated
	}
	if err != nil {
		return Session{}, fmt.Errorf("read management session: %w", err)
	}
	result.ExpiresAt = time.Unix(0, expiry).UTC()
	result.verified = true
	return result, nil
}

func (r *SQLRepository) passwordForSession(ctx context.Context, hash []byte) (passwordSnapshot, error) {
	var result passwordSnapshot
	err := r.db.QueryRowContext(ctx, `
SELECT o.id,o.login_name,o.password_encoding,o.session_epoch,o.enabled
FROM space.operator_sessions s JOIN space.operators o ON o.id=s.operator_id
WHERE s.session_hash=$1 AND s.hash_version=$2 AND s.revoked_at IS NULL
  AND s.expires_at>space.clock_ns() AND o.enabled AND s.session_epoch=o.session_epoch`,
		hash, SessionHashVersion).Scan(&result.operator.ID, &result.operator.Username, &result.password, &result.epoch, &result.enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return passwordSnapshot{}, ErrUnauthenticated
	}
	if err != nil {
		return passwordSnapshot{}, fmt.Errorf("read session password binding: %w", err)
	}
	return result, nil
}

func (r *SQLRepository) issueSession(ctx context.Context, expected passwordSnapshot, sessionHash, csrfHash []byte, created, expires time.Time) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin management session issuance: %w", err)
	}
	defer tx.Rollback()
	if err = lockExpectedOperator(ctx, tx, expected); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO space.operator_sessions
 (session_hash,hash_version,operator_id,session_epoch,csrf_hash,created_at,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)`, sessionHash, SessionHashVersion,
		expected.operator.ID, expected.epoch, csrfHash, created.UnixNano(), expires.UnixNano())
	if err != nil {
		return fmt.Errorf("store management session: %w", err)
	}
	// The locked credential check establishes the successful login's actor.
	// Keep the boundary's origin/request metadata without copying any bearer.
	actor := operationlog.ContextActor(ctx)
	actor.Kind, actor.Ref = "operator", strconv.FormatInt(expected.operator.ID, 10)
	auditContext, err := operationlog.WithActor(ctx, actor)
	if err != nil {
		return fmt.Errorf("bind management session audit: %w", err)
	}
	if err = operationlog.RecordAuditTx(auditContext, tx, operationlog.ActorRecord(auditContext, operationlog.Record{
		OccurredAt: created.UnixNano(), Action: "management.session_issued", ResourceKind: "operator",
		ResourceRef: actor.Ref, Outcome: "success",
	})); err != nil {
		return fmt.Errorf("record management session issuance: %w", err)
	}
	return commitWrite(tx, "issue management session")
}

func (r *SQLRepository) revokeSession(ctx context.Context, hash []byte) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin management session revocation: %w", err)
	}
	defer tx.Rollback()
	var operatorID, revokedAt int64
	err = tx.QueryRowContext(ctx, `
UPDATE space.operator_sessions SET revoked_at=space.clock_ns()
WHERE session_hash=$1 AND hash_version=$2 AND revoked_at IS NULL
RETURNING operator_id,revoked_at`, hash, SessionHashVersion).Scan(&operatorID, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revoke management session: %w", err)
	}
	if err = operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{
		OccurredAt: revokedAt, Action: "management.logout", ResourceKind: "operator",
		ResourceRef: strconv.FormatInt(operatorID, 10), Outcome: "success",
	})); err != nil {
		return fmt.Errorf("record management session revocation: %w", err)
	}
	return commitWrite(tx, "revoke management session")
}

func (r *SQLRepository) replacePassword(ctx context.Context, sessionHash []byte, expected passwordSnapshot, replacement string) error {
	if expected.epoch == math.MaxInt64 {
		return fmt.Errorf("%w: management session epoch is exhausted", ErrConflict)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin management password change: %w", err)
	}
	defer tx.Rollback()
	if err = lockExpectedOperator(ctx, tx, expected); err != nil {
		return err
	}
	// Lock order is operator, then session. New session issuance takes the
	// operator lock too, so no old-epoch session can cross this commit.
	var revoked sql.NullInt64
	var expires, sessionEpoch int64
	err = tx.QueryRowContext(ctx, `
SELECT revoked_at,expires_at,session_epoch
FROM space.operator_sessions
WHERE session_hash=$1 AND hash_version=$2 AND operator_id=$3 FOR UPDATE`,
		sessionHash, SessionHashVersion, expected.operator.ID).Scan(&revoked, &expires, &sessionEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthenticated
	}
	if err != nil {
		return fmt.Errorf("lock management session: %w", err)
	}
	// Read the clock after both row locks have actually been acquired. A
	// session can expire while this transaction waits for a concurrent owner.
	var now int64
	if err = tx.QueryRowContext(ctx, `SELECT space.clock_ns()`).Scan(&now); err != nil {
		return fmt.Errorf("check locked management session expiry: %w", err)
	}
	if revoked.Valid || expires <= now || sessionEpoch != expected.epoch {
		return ErrUnauthenticated
	}
	result, err := tx.ExecContext(ctx, `
UPDATE space.operators SET password_encoding=$1,session_epoch=session_epoch+1,updated_at=space.clock_ns()
WHERE id=$2 AND password_encoding=$3 AND session_epoch=$4 AND enabled`,
		replacement, expected.operator.ID, expected.password, expected.epoch)
	if err != nil {
		return fmt.Errorf("replace management password: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect management password replacement: %w", err)
	}
	if affected != 1 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `
UPDATE space.operator_sessions SET revoked_at=coalesce(revoked_at,space.clock_ns()) WHERE operator_id=$1`, expected.operator.ID)
	if err != nil {
		return fmt.Errorf("revoke prior management sessions: %w", err)
	}
	if err = operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{
		OccurredAt: now, Action: "management.credential_changed", ResourceKind: "operator",
		ResourceRef: strconv.FormatInt(expected.operator.ID, 10), Outcome: "success",
	})); err != nil {
		return fmt.Errorf("record management credential change: %w", err)
	}
	return commitWrite(tx, "change management password")
}

func lockExpectedOperator(ctx context.Context, tx *sql.Tx, expected passwordSnapshot) error {
	var password string
	var epoch int64
	var enabled bool
	err := tx.QueryRowContext(ctx, `
SELECT password_encoding,session_epoch,enabled FROM space.operators WHERE id=$1 FOR UPDATE`,
		expected.operator.ID).Scan(&password, &epoch, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("lock management operator: %w", err)
	}
	if !enabled || password != expected.password || epoch != expected.epoch {
		return ErrConflict
	}
	return nil
}

func commitWrite(tx *sql.Tx, action string) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrOutcomeUnknown, action, err)
	}
	return nil
}
