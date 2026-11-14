package addresses

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"icloudspace/internal/addressauth"
	"icloudspace/internal/sourceguard"
)

type Service struct {
	db           *sql.DB
	installation string
	guards       *sourceguard.Registry
	issue        IssueFactory
	clock        func() int64
	// LocalAppleCapacity is a local registration policy, never an Apple quota.
	// Zero disables the local policy; the composition root chooses explicitly.
	LocalAppleCapacity int64
}

func New(ctx context.Context, db *sql.DB, installation string, guards *sourceguard.Registry, issue IssueFactory, clock func() int64) (*Service, error) {
	if db == nil || guards == nil || !text(installation, 256, true) {
		return nil, &FieldError{"configuration"}
	}
	var actual string
	if err := db.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual); err != nil || actual != installation {
		return nil, ErrInstallation
	}
	if clock == nil {
		clock = func() int64 { return time.Now().UnixNano() }
	}
	return &Service{db: db, installation: installation, guards: guards, issue: issue, clock: clock}, nil
}

func (s *Service) beginIssue(ctx context.Context) (IssueScope, error) {
	if s.issue == nil {
		return IssueScope{Close: func() {}}, nil
	}
	scope, err := s.issue(ctx)
	if scope.Close == nil {
		scope.Close = func() {}
	}
	return scope, err
}

// A round may already own the source while fetching and applying a directory.
// Borrow that exact capability without releasing it at the inner boundary.
func (s *Service) enter(ctx context.Context, sourceID int64) (context.Context, func(), error) {
	if held := sourceguard.LeaseFromContext(ctx); held != nil {
		if !held.ValidFor(s.guards, sourceID) {
			return ctx, nil, sourceguard.ErrInvalid
		}
		if err := ctx.Err(); err != nil {
			return ctx, nil, err
		}
		return ctx, func() {}, nil
	}
	lease, err := s.guards.Acquire(ctx, sourceID)
	if err != nil {
		return ctx, nil, err
	}
	return sourceguard.WithLease(ctx, lease), func() { _ = lease.Close() }, nil
}

func (s *Service) begin(ctx context.Context) (*sql.Tx, error) {
	if err := sourceguard.CheckLocalMutation(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var id string
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton FOR SHARE`).Scan(&id, &enabled)
	if err != nil || id != s.installation {
		tx.Rollback()
		return nil, ErrInstallation
	}
	if !enabled {
		tx.Rollback()
		return nil, ErrReadOnly
	}
	return tx, nil
}

func commit(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) {
			return classify(err)
		}
		return ErrCommitUnknown
	}
	return nil
}
func classify(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23503" || pg.Code == "40001" || pg.Code == "40P01") {
		return ErrConflict
	}
	return err
}
func text(v string, max int, required bool) bool {
	if len(v) > max || !utf8.ValidString(v) || required && strings.TrimSpace(v) == "" {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func NormalizeAddress(v string) (string, error) {
	if !text(v, 320, true) || strings.TrimSpace(v) != v || strings.Count(v, "@") != 1 {
		return "", &FieldError{"address"}
	}
	p, err := mail.ParseAddress(v)
	if err != nil || p.Address != v || strings.ContainsAny(v, "<>\"(),; \\[]") {
		return "", &FieldError{"address"}
	}
	return strings.ToLower(v), nil
}
func validID(v *int64) bool { return v == nil || *v > 0 }
func normalizeFilter(f Filter, p Page) (Filter, Page, error) {
	if !validID(f.SourceID) || !validID(f.GroupID) || f.Ungrouped && f.GroupID != nil || !text(f.Query, 512, false) {
		return f, p, &FieldError{"filter"}
	}
	if f.Archive == "" {
		f.Archive = "all"
	}
	if f.Archive != "all" && f.Archive != "archived" && f.Archive != "unarchived" {
		return f, p, &FieldError{"archive"}
	}
	f.Query = strings.ToLower(strings.TrimSpace(f.Query))
	if p.Limit == 0 {
		p.Limit = DefaultLimit
	}
	if p.Limit < 1 || p.Limit > MaximumLimit || p.Offset < 0 {
		return f, p, &FieldError{"page"}
	}
	return f, p, nil
}

// The profile describes retained current material and independent grant facts,
// not whether the address/source is enabled. Listing never opens secret bytes.
var credentialProfileSQL = `CASE WHEN a.lifecycle='confirmed' AND a.deleted_at IS NULL AND (
 EXISTS(SELECT 1 FROM space.address_credential_bundles b WHERE b.source_id=a.source_id AND b.address_id=a.id AND b.auth_generation=a.auth_generation)
 OR EXISTS(SELECT 1 FROM space.pending_reveals p WHERE p.source_id=a.source_id AND p.address_id=a.id AND p.auth_generation=a.auth_generation AND p.owner_key<>''))
 THEN (SELECT CASE WHEN count(DISTINCT g.authenticator_hash) FILTER(WHERE g.authenticator_kind='api_key' AND g.purpose IN ('latest_read','mail_read','mail_consume','raw_read'))<>1 THEN 'unavailable'
 WHEN EXISTS(SELECT 1 FROM space.address_credential_bundles b WHERE b.source_id=a.source_id AND b.address_id=a.id AND b.auth_generation=a.auth_generation)
 AND bool_or(g.parent_grant_id IS NULL AND g.authenticator_kind='api_key' AND g.purpose IN ('latest_read','mail_read','mail_consume','raw_read'))
 AND bool_or(g.parent_grant_id IS NULL AND g.authenticator_kind='imap_password' AND g.purpose='imap_login')
 AND bool_or(g.parent_grant_id IS NULL AND g.authenticator_kind='client_id' AND g.purpose='oauth_client')
 AND bool_or(g.parent_grant_id IS NULL AND g.authenticator_kind='refresh_token' AND g.purpose='oauth_refresh') THEN 'mailbox'
 WHEN bool_or(g.authenticator_kind='api_key' AND g.purpose IN ('mail_read','raw_read')) THEN 'api_key_only'
 WHEN bool_or(g.authenticator_kind='api_key' AND g.purpose='latest_read') THEN 'legacy_latest' ELSE 'unavailable' END
 FROM space.address_grants g WHERE g.source_id=a.source_id AND g.address_id=a.id AND g.auth_generation=a.auth_generation AND ` + addressauth.CurrentGrantMetadataSQL() + `)
 ELSE 'unavailable' END`

const identityColumns = `a.id,a.source_id,a.email,a.kind,a.label,a.group_id,a.lifecycle,a.enabled,a.archived_at,a.archive_reason,a.deleted_at,a.provider_address_id,a.provider_owner,a.provider_active,a.forwarding_email,a.revision,a.auth_generation,a.uid_validity,a.uid_next`
const basicColumns = identityColumns + `,(a.latest_received_at IS NOT NULL),a.created_at,a.updated_at`
const syncColumns = `a.last_sync_state,a.last_sync_error,a.last_synced_at,a.last_accessed_at`
const evidenceColumns = `(SELECT e.detected_at FROM space.address_evidence e WHERE e.source_id=a.source_id AND e.address_id=a.id AND e.evidence_kind='trusted_ban'),
 a.latest_received_at`

var columns = basicColumns + `,CASE WHEN a.enabled AND a.lifecycle='confirmed' AND a.deleted_at IS NULL AND EXISTS(SELECT 1 FROM space.mail_sources s WHERE s.id=a.source_id AND s.enabled) THEN coalesce((SELECT jsonb_agg(DISTINCT g.purpose ORDER BY g.purpose) FROM space.address_grants g WHERE g.address_id=a.id AND g.auth_generation=a.auth_generation AND ` + addressauth.CurrentGrantMetadataSQL() + `),'[]'::jsonb) ELSE '[]'::jsonb END,` + syncColumns + `,` + credentialProfileSQL + `,` + evidenceColumns + `,(SELECT coalesce(nullif(s.display_name,''),s.address_namespace) FROM space.mail_sources s WHERE s.id=a.source_id),(SELECT s.kind FROM space.mail_sources s WHERE s.id=a.source_id)`

const predicate = ` FROM space.private_addresses a WHERE a.deleted_at IS NULL AND ($1::bigint IS NULL OR a.source_id=$1) AND ($2::bigint IS NULL OR a.group_id=$2) AND (NOT $3::boolean OR a.group_id IS NULL) AND ($4::text='' OR strpos(lower(a.email),$4)>0 OR strpos(lower(a.label),$4)>0) AND ($5::boolean IS NULL OR a.enabled=$5) AND ($6::boolean IS NULL OR (a.latest_received_at IS NOT NULL)=$6) AND ($7::text='all' OR ($7='archived')=(a.lifecycle='archived'))`

func filterArgs(f Filter) []any {
	return []any{f.SourceID, f.GroupID, f.Ungrouped, f.Query, f.Enabled, f.HasMail, f.Archive}
}

type scanner interface{ Scan(...any) error }

func scan(row scanner) (Metadata, error) {
	var a Metadata
	var capabilities []byte
	err := row.Scan(&a.ID, &a.SourceID, &a.Address, &a.Kind, &a.Label, &a.GroupID, &a.Lifecycle, &a.Enabled, &a.ArchivedAt, &a.ArchiveReason, &a.DeletedAt, &a.ProviderID, &a.ProviderOwner, &a.ProviderActive, &a.ForwardingEmail, &a.Revision, &a.AuthGeneration, &a.UIDValidity, &a.UIDNext, &a.HasMail, &a.CreatedAt, &a.UpdatedAt, &capabilities, &a.LastSyncState, &a.LastSyncError, &a.LastSyncedAt, &a.LastAccessedAt, &a.CredentialProfile, &a.RegistrationBannedAt, &a.LatestReceivedAt, &a.SourceLabel, &a.SourceKind)
	a.RegistrationBanned = a.RegistrationBannedAt != nil
	a.Capabilities = []string{}
	if err == nil {
		err = json.Unmarshal(capabilities, &a.Capabilities)
	}
	return a, classify(err)
}

func (s *Service) Get(ctx context.Context, id int64) (Metadata, error) {
	if id < 1 {
		return Metadata{}, &FieldError{"id"}
	}
	a, err := scan(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1 AND a.deleted_at IS NULL`, id))
	if err != nil {
		return Metadata{}, err
	}
	return a, nil
}
func (s *Service) List(ctx context.Context, f Filter, p Page) (MetadataPage, error) {
	f, p, err := normalizeFilter(f, p)
	if err != nil {
		return MetadataPage{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MetadataPage{}, err
	}
	defer tx.Rollback()
	out := MetadataPage{Items: []Metadata{}, Limit: p.Limit, Offset: p.Offset}
	args := filterArgs(f)
	if err = tx.QueryRowContext(ctx, `SELECT count(*)`+predicate, args...).Scan(&out.Total); err != nil {
		return MetadataPage{}, err
	}
	rows, err := tx.QueryContext(ctx, metadataQuery(predicate+` ORDER BY a.id ASC LIMIT $8 OFFSET $9`), append(args, p.Limit, p.Offset)...)
	if err != nil {
		return MetadataPage{}, err
	}
	for rows.Next() {
		a, e := scan(rows)
		if e != nil {
			rows.Close()
			return MetadataPage{}, e
		}
		out.Items = append(out.Items, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return MetadataPage{}, err
	}
	if err = tx.Commit(); err != nil {
		return MetadataPage{}, err
	}
	return out, nil
}

// ExportMetadata shares List's full filter, has no pagination ceiling and does
// not read encrypted fields. The transaction gives all rows one snapshot.
func (s *Service) ExportMetadata(ctx context.Context, f Filter, emit func(Metadata) error) error {
	return s.exportMetadata(ctx, f, emit, false)
}

// ExportEligibleMetadata first checks every selected address in the same
// snapshot, before invoking emit. A secret-export adapter must use this path:
// ordinary disabled addresses qualify, pending/archived/deleting rows fail the
// entire export instead of silently disappearing from a requested selection.
func (s *Service) ExportEligibleMetadata(ctx context.Context, f Filter, emit func(Metadata) error) error {
	return s.exportMetadata(ctx, f, emit, true)
}

func (s *Service) exportMetadata(ctx context.Context, f Filter, emit func(Metadata) error, eligible bool) error {
	f, _, err := normalizeFilter(f, Page{})
	if err != nil {
		return err
	}
	if emit == nil {
		return &FieldError{"emit"}
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if eligible {
		var invalid bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1`+predicate+` AND a.lifecycle<>'confirmed')`, filterArgs(f)...).Scan(&invalid); err != nil {
			return err
		}
		if invalid {
			return ErrIneligible
		}
	}
	rows, err := tx.QueryContext(ctx, metadataQuery(predicate), filterArgs(f)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		a, e := scan(rows)
		if e != nil {
			return e
		}
		if e = emit(a); e != nil {
			return e
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	rows.Close()
	return tx.Commit()
}
