package accounts

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"icloudspace/internal/sourceguard"
	"icloudspace/internal/vault"
)

// Service uses an already initialized canonical database. Construction checks
// the expected installation identity once; it does not initialize any schema,
// generate keys, authenticate upstream, or inspect historical account formats.
type Service struct {
	db             *sql.DB
	installationID string
	vault          *vault.Vault
	clock          func() int64
	guards         *sourceguard.Registry
	sourceFence    SourceChangeFence
	uncertain      sync.Map
}

func New(ctx context.Context, db *sql.DB, installationID string, cipher *vault.Vault, clock func() int64) (*Service, error) {
	return NewWithSourceGuards(ctx, db, installationID, cipher, sourceguard.New(), clock)
}

// NewWithSourceGuards retains metadata/credential administration for callers
// without a credential Authority. Source replacement fails closed here.
func NewWithSourceGuards(ctx context.Context, db *sql.DB, installationID string, cipher *vault.Vault, guards *sourceguard.Registry, clock func() int64) (*Service, error) {
	return NewWithSourceChangeFence(ctx, db, installationID, cipher, guards, clock, SourceChangeFence{})
}

// NewWithSourceChangeFence is the application root's constructor. The registry
// and Authority behind fence must be the same owners used by mail transports.
func NewWithSourceChangeFence(ctx context.Context, db *sql.DB, installationID string, cipher *vault.Vault, guards *sourceguard.Registry, clock func() int64, fence SourceChangeFence) (*Service, error) {
	if db == nil || cipher == nil || guards == nil || !boundedText(installationID, 256, true) {
		return nil, &FieldError{"service_configuration"}
	}
	if (fence.Begin == nil) != (fence.Resolve == nil) {
		return nil, &FieldError{"source_change_fence"}
	}
	var actual string
	if err := db.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual); err != nil {
		return nil, ErrInstallation
	}
	if actual != installationID {
		return nil, ErrInstallation
	}
	if clock == nil {
		clock = func() int64 { return time.Now().UnixNano() }
	}
	return &Service{db: db, installationID: installationID, vault: cipher, clock: clock, guards: guards, sourceFence: fence}, nil
}

func (s *Service) beginWrite(ctx context.Context) (*sql.Tx, error) {
	if err := sourceguard.CheckLocalMutation(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var installationID string
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton FOR SHARE`).Scan(&installationID, &enabled)
	if err != nil || installationID != s.installationID {
		tx.Rollback()
		return nil, ErrInstallation
	}
	if !enabled {
		tx.Rollback()
		return nil, ErrReadOnly
	}
	return tx, nil
}

func (s *Service) List(ctx context.Context, filter Filter, page Page) (MetadataPage, error) {
	filter, page, err := normalizeQuery(filter, page)
	if err != nil {
		return MetadataPage{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MetadataPage{}, err
	}
	defer tx.Rollback()
	result := MetadataPage{Items: make([]Metadata, 0), Limit: page.Limit, Offset: page.Offset}
	args := filterArgs(filter)
	if err = tx.QueryRowContext(ctx, `SELECT count(*)`+sourceJoin+sourceFilter, args...).Scan(&result.Total); err != nil {
		return MetadataPage{}, err
	}
	args = append(args, page.Limit, page.Offset)
	rows, err := tx.QueryContext(ctx, `SELECT `+metadataColumns+sourceJoin+sourceFilter+sourceOrder+`LIMIT $4 OFFSET $5`, args...)
	if err != nil {
		return MetadataPage{}, err
	}
	for rows.Next() {
		item, _, scanErr := scanSource(rows, false)
		if scanErr != nil {
			rows.Close()
			return MetadataPage{}, scanErr
		}
		result.Items = append(result.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return MetadataPage{}, err
	}
	if err = tx.Commit(); err != nil {
		return MetadataPage{}, err
	}
	return result, nil
}

func (s *Service) Get(ctx context.Context, id int64) (Metadata, error) {
	if id < 1 {
		return Metadata{}, &FieldError{"id"}
	}
	if _, pending := s.uncertain.Load(id); pending {
		lease := sourceguard.LeaseFromContext(ctx)
		if lease != nil {
			if !lease.ValidFor(s.guards, id) {
				return Metadata{}, ErrSourceChangeFence
			}
		} else {
			var err error
			lease, err = s.guards.Acquire(ctx, id)
			if err != nil {
				return Metadata{}, err
			}
			defer lease.Close()
		}
		if err := s.sourceFence.Resolve(ctx, lease); err != nil {
			return Metadata{}, err
		}
		s.uncertain.Delete(id)
	}
	item, _, err := scanSource(s.db.QueryRowContext(ctx,
		`SELECT `+metadataColumns+sourceJoin+`WHERE s.id=$1 AND s.retired_at IS NULL`, id), false)
	return item, classify(err)
}

func (s *Service) Reveal(ctx context.Context, id int64) (Revealed, error) {
	if id < 1 {
		return Revealed{}, &FieldError{"id"}
	}
	item, envelope, err := scanSource(s.db.QueryRowContext(ctx,
		`SELECT `+metadataColumns+`,s.credentials_envelope`+sourceJoin+`WHERE s.id=$1 AND s.retired_at IS NULL`, id), true)
	if err != nil {
		return Revealed{}, classify(err)
	}
	credentials, err := s.open(item, envelope)
	if err != nil {
		return Revealed{}, err
	}
	return Revealed{Source: item, Credentials: credentials}, nil
}

// Export visits the complete filtered snapshot in stable order, one credential
// document at a time. It ignores UI page state by accepting no pagination.
// Returning an error from visit cancels the export without further decrypts.
func (s *Service) Export(ctx context.Context, filter Filter, visit func(Revealed) error) error {
	if visit == nil {
		return &FieldError{"export_visitor"}
	}
	filter, _, err := normalizeQuery(filter, Page{})
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+metadataColumns+`,s.credentials_envelope`+
		sourceJoin+sourceFilter+sourceOrder, filterArgs(filter)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		item, envelope, err := scanSource(rows, true)
		if err != nil {
			return err
		}
		credentials, err := s.open(item, envelope)
		if err != nil {
			return err
		}
		if err = visit(Revealed{Source: item, Credentials: credentials}); err != nil {
			return err
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	rows.Close()
	return tx.Commit()
}

func (s *Service) seal(source Metadata, credentials Credentials) ([]byte, error) {
	return SealCredentials(s.vault, CredentialOwner{InstallationID: s.installationID, SourceID: source.ID, Revision: source.Revision}, credentials)
}

func (s *Service) open(source Metadata, envelope []byte) (Credentials, error) {
	return OpenCredentials(s.vault, CredentialOwner{InstallationID: s.installationID, SourceID: source.ID, Revision: source.Revision}, envelope)
}

func classify(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && (pgerr.Code == "23505" || pgerr.Code == "40001" || pgerr.Code == "40P01") {
		return ErrConflict
	}
	return err
}
