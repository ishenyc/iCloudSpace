package mailview

import (
	"context"
	"database/sql"
	"errors"

	"icloudspace/internal/addressauth"
)

// PollMetadata is the monotonic local mailbox identity/high water, independent
// of history length. It contains no entry count, flag aggregate or body data.
type PollMetadata struct {
	UIDValidity int64
	UIDNext     uint64
}

const pollMetadataSQL = `SELECT a.uid_validity,a.uid_next
 FROM space.private_addresses a JOIN space.mail_sources m ON m.id=a.source_id
 WHERE a.source_id=$1 AND a.id=$2 AND m.source_generation=$3
 AND a.auth_generation=$4 AND a.uid_validity=$5
 AND m.enabled AND m.retired_at IS NULL AND a.enabled
 AND a.lifecycle='confirmed' AND a.deleted_at IS NULL`

// PollMetadata requires the caller's fresh IMAP lease for the whole response.
// Intake advances uid_next in the same transaction as local entries; quiet
// polling therefore needs only two indexed identity rows. Credential/source
// changes remain the authority's responsibility, not a local session cache.
func (s *Service) PollMetadata(ctx context.Context, lease *addressauth.Lease) (PollMetadata, error) {
	id, err := s.allow(lease, addressauth.IMAPLogin)
	if err != nil {
		return PollMetadata{}, err
	}
	var out PollMetadata
	err = s.db.QueryRowContext(ctx, pollMetadataSQL, id.SourceID, id.AddressID, id.SourceGeneration, id.Generation, id.UIDValidity).Scan(&out.UIDValidity, &out.UIDNext)
	if errors.Is(err, sql.ErrNoRows) {
		return PollMetadata{}, ErrStale
	}
	if err != nil {
		return PollMetadata{}, storage(ctx)
	}
	if out.UIDValidity != id.UIDValidity || out.UIDNext < 1 || out.UIDNext > 4294967296 {
		return PollMetadata{}, ErrStale
	}
	return out, nil
}
