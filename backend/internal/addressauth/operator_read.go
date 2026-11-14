package addressauth

import (
	"context"
	"database/sql"
	"errors"
)

// BeginOperatorRead is the management owner's read-only authorization port.
// It does not infer public mailbox authority from a retained bundle or mint a
// bearer. The root reauthenticates its management session in fresh after this
// barrier; callers retain the lease through the complete response.
func (a *Authority) BeginOperatorRead(ctx context.Context, addressID int64, purpose Purpose, fresh func(context.Context) error) (*Lease, error) {
	if a == nil || addressID < 1 || fresh == nil || purpose != MailRead && purpose != RawRead && purpose != LatestRead {
		return nil, ErrInvalid
	}
	release, err := a.gate.read(ctx)
	if err != nil {
		return nil, err
	}
	if !a.readReady() {
		release()
		return nil, ErrOutcomeUnknown
	}
	if err := fresh(ctx); err != nil {
		release()
		return nil, err
	}
	var identity Identity
	err = a.db.QueryRowContext(ctx, `SELECT s.id,a.id,s.source_generation,a.auth_generation,a.uid_validity,a.normalized_email
FROM space.private_addresses a JOIN space.mail_sources s ON s.id=a.source_id
WHERE a.id=$1 AND a.deleted_at IS NULL`, addressID).Scan(&identity.SourceID, &identity.AddressID, &identity.SourceGeneration, &identity.Generation, &identity.UIDValidity, &identity.Email)
	if err != nil {
		release()
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnavailable
		}
		return nil, storageError(ctx)
	}
	lease := &Lease{authority: a, identity: identity, purpose: purpose, release: release}
	lease.active.Store(true)
	return lease, nil
}
