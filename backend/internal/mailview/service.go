package mailview

import (
	"context"
	"database/sql"
	"icloudspace/internal/addressauth"
	"icloudspace/internal/blobstore"
	"icloudspace/internal/content"
	"icloudspace/internal/pgschema"
	"strings"
	"time"
	"unicode/utf8"
)

type Service struct {
	db           *sql.DB
	installation string
	authority    *addressauth.Authority
	blobs        *blobstore.Store
	options      Options
	commit       func(*sql.Tx) error
}

func New(ctx context.Context, db *sql.DB, installation string, authority *addressauth.Authority, blobs *blobstore.Store, options Options) (*Service, error) {
	if db == nil || authority == nil || blobs == nil || !validKey(installation) {
		return nil, ErrInvalid
	}
	if pgschema.Check(ctx, db) != nil {
		return nil, ErrStorage
	}
	var actual string
	if db.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual) != nil || actual != installation {
		return nil, ErrDenied
	}
	if options.Clock == nil {
		options.Clock = func() int64 { return time.Now().UnixNano() }
	}
	if options.Limits == (content.Limits{}) {
		options.Limits = DefaultLimits()
	}
	l := options.Limits
	if l.MessageBytes < 1 || l.HeaderBytes < 1 || l.BodyBytes < 1 || l.AttachmentBytes < 1 || l.Parts < 1 || l.Depth < 1 || l.Addresses < 1 || l.Attachments < 1 {
		return nil, ErrInvalid
	}
	return &Service{db: db, installation: installation, authority: authority, blobs: blobs, options: options, commit: func(tx *sql.Tx) error { return tx.Commit() }}, nil
}
func validKey(s string) bool {
	return s != "" && len(s) <= 256 && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func (s *Service) allow(lease *addressauth.Lease, purposes ...addressauth.Purpose) (addressauth.Identity, error) {
	if s == nil || !lease.ValidFor(s.authority) {
		return addressauth.Identity{}, ErrDenied
	}
	for _, p := range purposes {
		if lease.Purpose() == p {
			id := lease.Identity()
			if id.SourceID > 0 && id.AddressID > 0 {
				return id, nil
			}
		}
	}
	return addressauth.Identity{}, ErrDenied
}
func storage(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	return ErrStorage
}

// A local access observation neither modifies credential metadata revisions
// nor waits for an upstream source guard. Clock regressions cannot erase the
// last observed access. The root's wake callback is a bounded coalescer.
func (s *Service) observe(ctx context.Context, id addressauth.Identity) error {
	_, e := s.db.ExecContext(ctx, `UPDATE space.private_addresses a SET last_accessed_at=CASE WHEN a.last_accessed_at IS NULL OR a.last_accessed_at<$3 THEN $3 ELSE a.last_accessed_at END FROM space.mail_sources m,space.installation i WHERE a.source_id=$1 AND a.id=$2 AND a.source_id=m.id AND m.enabled AND a.enabled AND a.lifecycle='confirmed' AND a.deleted_at IS NULL AND a.auth_generation=$4 AND a.uid_validity=$5 AND m.source_generation=$6 AND i.singleton AND i.writes_enabled`, id.SourceID, id.AddressID, s.options.Clock(), id.Generation, id.UIDValidity, id.SourceGeneration)
	if e != nil {
		return storage(ctx)
	}
	if s.options.Wake != nil {
		s.options.Wake(id.SourceID)
	}
	return nil
}
func (s *Service) writable(ctx context.Context, tx *sql.Tx) error {
	var id string
	var enabled bool
	if tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton`).Scan(&id, &enabled) != nil {
		return storage(ctx)
	}
	if id != s.installation {
		return ErrDenied
	}
	if !enabled {
		return ErrReadOnly
	}
	return nil
}
