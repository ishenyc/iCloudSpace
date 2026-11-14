package adminauth

import (
	"context"
	"database/sql"
	"errors"
	"math"

	"golang.org/x/crypto/bcrypt"
)

// RevokeForCredentialRotation is called after the credential authority's
// exclusive gate has drained readers. The caller owns tx: password/session
// verification, epoch advancement and credential mutation commit together.
// Nothing is committed here and the current password is never persisted.
func (s *Service) RevokeForCredentialRotation(ctx context.Context, tx *sql.Tx, rawSession, currentPassword string) error {
	if tx == nil || !validOpaqueInput(rawSession) {
		return ErrUnauthenticated
	}
	if currentPassword == "" || len(currentPassword) > MaxLoginPasswordBytes {
		return ErrInvalidInput
	}
	hash := tokenHash(rawSession)
	var owner int64
	if err := tx.QueryRowContext(ctx, `SELECT operator_id FROM space.operator_sessions WHERE session_hash=$1 AND hash_version=$2`, hash, SessionHashVersion).Scan(&owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthenticated
		}
		return err
	}
	// Match normal session issuance's operator-before-session order. Lock all
	// operators deterministically so a concurrent login cannot mint a session
	// using an epoch that this transaction is about to revoke.
	rows, err := tx.QueryContext(ctx, `SELECT id,session_epoch FROM space.operators ORDER BY id FOR UPDATE`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var id, epoch int64
		if err := rows.Scan(&id, &epoch); err != nil {
			rows.Close()
			return err
		}
		if epoch == math.MaxInt64 {
			rows.Close()
			return ErrConflict
		}
		found = found || id == owner
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !found {
		return ErrUnauthenticated
	}
	var encoding string
	var enabled bool
	var sessionEpoch, operatorEpoch, expires int64
	var revoked sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT o.password_encoding,o.enabled,o.session_epoch,s.session_epoch,s.expires_at,s.revoked_at
FROM space.operator_sessions s JOIN space.operators o ON o.id=s.operator_id
WHERE s.session_hash=$1 AND s.hash_version=$2 FOR UPDATE OF s`, hash, SessionHashVersion).Scan(&encoding, &enabled, &operatorEpoch, &sessionEpoch, &expires, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthenticated
		}
		return err
	}
	var now int64
	if err := tx.QueryRowContext(ctx, `SELECT space.clock_ns()`).Scan(&now); err != nil {
		return err
	}
	if !enabled || revoked.Valid || expires <= now || sessionEpoch != operatorEpoch {
		return ErrUnauthenticated
	}
	if bcrypt.CompareHashAndPassword([]byte(encoding), []byte(currentPassword)) != nil {
		return ErrInvalidCredentials
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE space.operators SET session_epoch=session_epoch+1,updated_at=greatest(updated_at+1,$1::bigint)`, now); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE space.operator_sessions SET revoked_at=$1 WHERE revoked_at IS NULL`, now)
	return err
}
