package adminauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
)

// VerifyLocalMutationTx checks the current browser authority on the caller's
// transaction after its business gates. It never borrows a second connection,
// commits, changes a password, or revokes a session.
func (s *Service) VerifyLocalMutationTx(ctx context.Context, tx *sql.Tx, rawSession, rawCSRF string, expectedOperatorID int64) error {
	if s == nil || tx == nil || expectedOperatorID < 1 || !validOpaqueInput(rawSession) || !validOpaqueInput(rawCSRF) {
		return ErrUnauthenticated
	}
	var operatorEpoch int64
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT session_epoch,enabled FROM space.operators WHERE id=$1 FOR SHARE`, expectedOperatorID).Scan(&operatorEpoch, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthenticated
		}
		return err
	}
	var owner, sessionEpoch, expires int64
	var revoked sql.NullInt64
	var csrfHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT operator_id,session_epoch,expires_at,revoked_at,csrf_hash FROM space.operator_sessions WHERE session_hash=$1 AND hash_version=$2 FOR SHARE`, tokenHash(rawSession), SessionHashVersion).Scan(&owner, &sessionEpoch, &expires, &revoked, &csrfHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthenticated
		}
		return err
	}
	var now int64
	if err := tx.QueryRowContext(ctx, `SELECT space.clock_ns()`).Scan(&now); err != nil {
		return err
	}
	if !enabled || owner != expectedOperatorID || operatorEpoch != sessionEpoch || revoked.Valid || expires <= now || subtle.ConstantTimeCompare(csrfHash, tokenHash(rawCSRF)) != 1 {
		return ErrUnauthenticated
	}
	return ctx.Err()
}
