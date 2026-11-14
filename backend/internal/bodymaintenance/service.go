package bodymaintenance

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	"icloudspace/internal/blobstore"
	"icloudspace/internal/pgschema"
	"icloudspace/internal/sourceguard"
)

type Service struct {
	db                                     *sql.DB
	installation                           string
	files                                  *blobstore.Store
	guards                                 *sourceguard.Registry
	options                                Options
	worker                                 chan struct{}
	running                                atomic.Bool
	collectAfter, verifyAfter, orphanAfter string
	orphanOrdinal                          int64
	commit                                 func(*sql.Tx) error
	pageBusy                               map[int64]bool
}

func New(ctx context.Context, db *sql.DB, installation string, files *blobstore.Store, guards *sourceguard.Registry, options Options) (*Service, error) {
	if db == nil || files == nil || guards == nil || installation == "" || len(installation) > 256 || strings.ContainsAny(installation, "\r\n\x00") || options.CapacityBytes < 0 || options.BatchSize < 0 || options.BatchSize > 128 || options.Interval < 0 {
		return nil, ErrInvalid
	}
	if pgschema.Check(ctx, db) != nil {
		return nil, ErrStorage
	}
	var actual string
	if db.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual) != nil || actual != installation {
		return nil, ErrInvalid
	}
	if options.CapacityBytes == 0 {
		options.CapacityBytes = DefaultCapacityBytes
	}
	if options.BatchSize == 0 {
		options.BatchSize = DefaultBatchSize
	}
	if options.Interval == 0 {
		options.Interval = time.Minute
	}
	if options.Clock == nil {
		options.Clock = func() int64 { return time.Now().UnixNano() }
	}
	return &Service{db: db, installation: installation, files: files, guards: guards, options: options, worker: make(chan struct{}, 1), commit: (*sql.Tx).Commit}, nil
}
func storage(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	return ErrStorage
}
func (s *Service) enter(ctx context.Context) (func(), error) {
	if s == nil {
		return nil, ErrInvalid
	}
	select {
	case s.worker <- struct{}{}:
		return func() { <-s.worker }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrBusy
	}
}
func (s *Service) writable(ctx context.Context, tx *sql.Tx) error {
	var id string
	var writes bool
	if tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton FOR SHARE`).Scan(&id, &writes) != nil {
		return storage(ctx)
	}
	if id != s.installation {
		return ErrInvalid
	}
	if !writes {
		return ErrReadOnly
	}
	return nil
}
func (s *Service) lockSource(ctx context.Context, tx *sql.Tx, id int64) error {
	var actual int64
	if e := tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, id).Scan(&actual); errors.Is(e, sql.ErrNoRows) {
		return ErrStale
	} else if e != nil {
		return storage(ctx)
	}
	return nil
}
func (s *Service) Usage(ctx context.Context) (Usage, error) {
	if s == nil {
		return Usage{}, ErrInvalid
	}
	var size string
	if s.db.QueryRowContext(ctx, `SELECT coalesce(sum(byte_size),0)::text FROM space.content_objects WHERE state='available'`).Scan(&size) != nil {
		return Usage{}, storage(ctx)
	}
	return s.usage(size)
}
func (s *Service) usage(size string) (Usage, error) {
	n, ok := new(big.Int).SetString(size, 10)
	if !ok || n.Sign() < 0 {
		return Usage{}, ErrStorage
	}
	return Usage{AvailableBytes: n.String(), CapacityBytes: s.options.CapacityBytes, OverCapacity: n.Cmp(big.NewInt(s.options.CapacityBytes)) > 0}, nil
}

const objectColumns = `o.source_id,o.object_key,o.manifest_version,o.byte_size,encode(o.sha256,'hex'),o.storage_ref,o.state,o.publication_generation,o.retention_order_at,coalesce(p.owner_key,''),coalesce(p.receipt_key,''),coalesce(p.staging_ref,''),coalesce(p.state,'')`
const objectJoin = ` FROM space.content_objects o LEFT JOIN space.content_publications p ON p.source_id=o.source_id AND p.object_key=o.object_key AND p.publication_generation=o.publication_generation `

type scanner interface{ Scan(...any) error }

func scanObject(row scanner) (object, error) {
	var o object
	r := &o.Receipt
	e := row.Scan(&o.SourceID, &r.Identity.ObjectKey, &r.Version, &r.ByteSize, &r.SHA256, &r.StorageRef, &o.State, &r.Identity.Generation, &o.RetentionOrderAt, &r.Identity.OwnerKey, &r.ReceiptKey, &r.StagingRef, &o.PublicationState)
	return o, e
}
func validReference(r Reference) bool {
	if r.SourceID < 1 || r.Receipt.Version != blobstore.ManifestVersion || r.Receipt.ByteSize < 0 {
		return false
	}
	digest, e := hex.DecodeString(r.Receipt.SHA256)
	if e != nil || len(digest) != 32 || hex.EncodeToString(digest) != r.Receipt.SHA256 {
		return false
	}
	refs, e := blobstore.Describe(r.Receipt.Identity)
	return e == nil && refs.ReceiptKey == r.Receipt.ReceiptKey && refs.StagingRef == r.Receipt.StagingRef && refs.StorageRef == r.Receipt.StorageRef
}
func same(a, b Reference) bool {
	return a.SourceID == b.SourceID && a.Receipt.Version == b.Receipt.Version && a.Receipt.Identity == b.Receipt.Identity && a.Receipt.ReceiptKey == b.Receipt.ReceiptKey && a.Receipt.StagingRef == b.Receipt.StagingRef && a.Receipt.StorageRef == b.Receipt.StorageRef && a.Receipt.ByteSize == b.Receipt.ByteSize && a.Receipt.SHA256 == b.Receipt.SHA256
}

// An unresolved file/SQL publication is a protection, never collection proof.
// Prepared batches include unknown checkpoint outcomes after process restart.
const protectionSQL = `SELECT EXISTS(SELECT 1 FROM space.content_publications WHERE object_key=$1 AND state IN ('staged','published','sql_unknown')) OR EXISTS(
 SELECT 1 FROM space.intake_batches b JOIN space.content_objects o ON o.source_id=b.source_id WHERE b.state='prepared' AND o.object_key=$1)`

func protected(ctx context.Context, tx *sql.Tx, key string) (bool, error) {
	var yes bool
	e := tx.QueryRowContext(ctx, protectionSQL, key).Scan(&yes)
	return yes, e
}

// Run is deliberately one maintenance worker, not a task/retry platform. Each
// tick checks a bounded SQL page; the root handles error reporting/lifecycle.
func (s *Service) Run(ctx context.Context) error {
	if s == nil {
		return ErrInvalid
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrBusy
	}
	defer s.running.Store(false)
	ticker := time.NewTicker(s.options.Interval)
	defer ticker.Stop()
	for {
		result, e := s.Step(ctx)
		if e != nil && !errors.Is(e, ErrBusy) {
			if ctx.Err() != nil {
				return errors.Join(e, ctx.Err())
			}
			return e
		}
		// Continue real capacity progress one bounded batch at a time. Each Step
		// has already released its guards/transaction; a busy or unproductive
		// oldest item waits for the normal tick instead of spinning or skipping.
		if e == nil && result.After.OverCapacity && result.Evicted > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (s *Service) Step(ctx context.Context) (result Result, err error) {
	leave, e := s.enter(ctx)
	if e != nil {
		return result, e
	}
	defer leave()
	s.pageBusy = make(map[int64]bool)
	result.Before, e = s.Usage(ctx)
	if e != nil {
		return result, e
	}
	if e = s.recoverPage(ctx, &result); e != nil {
		return result, e
	}
	if e = s.orphanPage(ctx, &result); e != nil {
		return result, e
	}
	if e = s.verifyPage(ctx, &result); e != nil {
		return result, e
	}
	if e = s.evictPage(ctx, &result); e != nil {
		return result, e
	}
	result.After, e = s.Usage(ctx)
	return result, e
}
