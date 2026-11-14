package localcleanup

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"icloudspace/internal/blobstore"
	"icloudspace/internal/pgschema"
	"icloudspace/internal/sourceguard"
)

type Service struct {
	db           *sql.DB
	installation string
	files        *blobstore.Store
	guards       *sourceguard.Registry
	options      Options
	worker       atomic.Bool
	running      atomic.Bool
	commit       func(*sql.Tx) error
}

func New(ctx context.Context, db *sql.DB, installation string, files *blobstore.Store, guards *sourceguard.Registry, options Options) (*Service, error) {
	if db == nil || files == nil || guards == nil || !text(installation, 256) || options.BeginFence == nil || options.ResolveFence == nil || options.BatchSize < 0 || options.BatchSize > 128 || options.Interval < 0 {
		return nil, ErrInvalid
	}
	if pgschema.Check(ctx, db) != nil {
		return nil, ErrStorage
	}
	var actual string
	if db.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual) != nil || actual != installation {
		return nil, ErrInvalid
	}
	if options.BatchSize == 0 {
		options.BatchSize = 32
	}
	if options.Interval == 0 {
		options.Interval = time.Minute
	}
	if options.Clock == nil {
		options.Clock = func() int64 { return time.Now().UnixNano() }
	}
	return &Service{db: db, installation: installation, files: files, guards: guards, options: options, commit: (*sql.Tx).Commit}, nil
}
func text(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}
func key(value string) bool {
	if !text(value, 128) {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func storage(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrStorage
}

// SQL diagnostics contain only a fixed operation label and SQLSTATE. Driver
// detail/messages may include bound values and never become service errors.
func sqlFailure(ctx context.Context, e error, stage string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var pg *pgconn.PgError
	if errors.As(e, &pg) {
		return fmt.Errorf("%w: %s SQLSTATE %s", ErrStorage, stage, pg.Code)
	}
	return storage(ctx)
}
func (s *Service) writable(ctx context.Context, tx *sql.Tx) error {
	var actual string
	var enabled bool
	if tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton FOR SHARE`).Scan(&actual, &enabled) != nil {
		return storage(ctx)
	}
	if actual != s.installation {
		return ErrInvalid
	}
	if !enabled {
		return ErrReadOnly
	}
	return nil
}
func validReceipt(r blobstore.Receipt) bool {
	refs, e := blobstore.Describe(r.Identity)
	if e != nil || r.Version != blobstore.ManifestVersion || r.ByteSize < 0 {
		return false
	}
	h, e := hex.DecodeString(r.SHA256)
	return e == nil && len(h) == 32 && hex.EncodeToString(h) == r.SHA256 && refs.ReceiptKey == r.ReceiptKey && refs.StagingRef == r.StagingRef && refs.StorageRef == r.StorageRef
}

// SQL row locks wait for an original unknown transaction to finish. An absent
// operation after this proof means no committed retirement, never replay.
func (s *Service) queryLocked(ctx context.Context, source int64, operation, owner string) (Receipt, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Receipt{}, storage(ctx)
	}
	defer tx.Rollback()
	var id int64
	if e = tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, source).Scan(&id); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return Receipt{}, ErrNotFound
		}
		return Receipt{}, storage(ctx)
	}
	r, e := readReceipt(ctx, tx, operation, owner)
	if e != nil {
		return r, e
	}
	if r.SourceID != source {
		return Receipt{}, ErrConflict
	}
	if e = tx.Commit(); e != nil {
		return Receipt{}, ErrUnknown
	}
	return r, nil
}
func (s *Service) Query(ctx context.Context, source int64, operation, owner string) (Receipt, error) {
	if s == nil || source < 1 || !key(operation) || !text(owner, 256) {
		return Receipt{}, ErrInvalid
	}
	g, e := s.guards.Acquire(ctx, source)
	if e != nil {
		return Receipt{}, e
	}
	defer g.Close()
	if e = s.options.ResolveFence(ctx, g); e != nil {
		return Receipt{}, e
	}
	return s.queryLocked(ctx, source, operation, owner)
}
