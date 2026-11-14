package addresses

import (
	"context"
	"database/sql"
	"strings"

	"icloudspace/internal/sourceguard"
)

type ExternalRegistrationInput struct {
	SourceID          int64
	Address, OwnerKey string
}

// StageExternalRegistration is the deployment registration owner's narrow
// transaction port. Caller holds this source's guard and Authority IssueScope
// until SQL has ended. It cannot call any provider or infer Apple ownership.
func (s *Service) StageExternalRegistration(ctx context.Context, tx *sql.Tx, issue Issuer, in ExternalRegistrationInput) (Metadata, error) {
	input, err := localInput(CreateInput{SourceID: in.SourceID, Address: in.Address, OwnerKey: in.OwnerKey, Enabled: true, CredentialProfile: "mailbox"})
	if err != nil {
		return Metadata{}, err
	}
	if s == nil || tx == nil || issue == nil || !sourceguard.LeaseFromContext(ctx).ValidFor(s.guards, in.SourceID) {
		return Metadata{}, ErrInvalid
	}
	if err = sourceguard.CheckLocalMutation(ctx); err != nil {
		return Metadata{}, err
	}
	var src source
	err = tx.QueryRowContext(ctx, `SELECT id,kind,address_namespace,address_suffix,imap_username,revision,source_generation,enabled FROM space.mail_sources WHERE id=$1 AND retired_at IS NULL FOR UPDATE`, in.SourceID).Scan(&src.ID, &src.Kind, &src.Namespace, &src.Suffix, &src.Forward, &src.Revision, &src.Generation, &src.Enabled)
	if err != nil {
		return Metadata{}, classify(err)
	}
	if input.Address == strings.ToLower(strings.TrimSpace(src.Forward)) {
		return Metadata{}, ErrConflict
	}
	if src.Kind != "custom" {
		occupied, err := occupiedCapacity(ctx, tx, src.ID, "")
		if err != nil {
			return Metadata{}, err
		}
		if occupied >= 750 {
			return Metadata{}, ErrCapacity
		}
	}
	a, err := s.insertPolicy(ctx, tx, issue, src, input, "manual", nil, false)
	if err != nil {
		return Metadata{}, err
	}
	if err = auditAddressTx(ctx, tx, a.SourceID, a.ID, s.clock(), "address.external_registered"); err != nil {
		return Metadata{}, err
	}
	return a, nil
}
