package creationengine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"icloudspace/internal/addresses"
	"icloudspace/internal/sourceguard"
)

func New(ctx context.Context, db *sql.DB, installation string, guards *sourceguard.Registry, creator Creator, provider func(int64) addresses.Provider, options Options) (*Engine, error) {
	if db == nil || installation == "" || guards == nil || creator == nil || provider == nil {
		return nil, ErrInvalid
	}
	var actual string
	if err := db.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual); err != nil || actual != installation {
		return nil, ErrInstallation
	}
	if options.Clock == nil {
		options.Clock = func() int64 { return time.Now().UnixNano() }
	}
	if options.Random == nil {
		options.Random = secureRandom
	}
	if options.Workers == 0 {
		options.Workers = 3
	}
	if options.PollInterval == 0 {
		options.PollInterval = 30 * time.Second
	}
	if options.OperationTimeout == 0 {
		options.OperationTimeout = 90 * time.Second
	}
	if options.OverdueGrace == 0 {
		options.OverdueGrace = 2 * time.Minute
	}
	if options.CredentialProfile == "" {
		options.CredentialProfile = "mailbox"
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.Workers < 1 || options.Workers > 16 || options.PollInterval <= 0 || options.OperationTimeout <= 0 || options.OverdueGrace < 0 || options.CredentialProfile != "mailbox" && options.CredentialProfile != "api_key_only" {
		return nil, ErrInvalid
	}
	return &Engine{db: db, installation: installation, guards: guards, creator: creator, provider: provider, options: options, active: map[int64]bool{}, wake: make(chan struct{}, 1)}, nil
}
func (e *Engine) enter(ctx context.Context, source int64) (context.Context, func(), error) {
	if e == nil || source < 1 {
		return ctx, nil, ErrInvalid
	}
	if held := sourceguard.LeaseFromContext(ctx); held != nil {
		if !held.ValidFor(e.guards, source) {
			return ctx, nil, sourceguard.ErrInvalid
		}
		return ctx, func() {}, ctx.Err()
	}
	gate, err := e.guards.Acquire(ctx, source)
	if err != nil {
		return ctx, nil, err
	}
	return sourceguard.WithLease(ctx, gate), func() { _ = gate.Close() }, nil
}
func (e *Engine) begin(ctx context.Context) (*sql.Tx, error) {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storage(ctx)
	}
	var actual string
	var enabled bool
	if err = tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton FOR SHARE`).Scan(&actual, &enabled); err != nil || actual != e.installation {
		tx.Rollback()
		return nil, ErrInstallation
	}
	if !enabled {
		tx.Rollback()
		return nil, ErrReadOnly
	}
	return tx, nil
}
func storage(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrStorage
}
func commit(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) {
			if pg.Code == "40001" || pg.Code == "40P01" || pg.Code == "23505" {
				return ErrConflict
			}
			return ErrStorage
		}
		return ErrUnknown
	}
	return nil
}

type scanner interface{ Scan(...any) error }
type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const policyColumns = `source_id,enabled,revision,schedule_kind,interval_milliseconds,maximum_addresses,attempts_per_round,cooldown_until,paused_reason,last_attempted_at,last_confirmed_at,last_address,last_error_detail,created_at,updated_at`

func readPolicy(row scanner) (Policy, error) {
	var p Policy
	var interval, cooldown, last, confirmed sql.NullInt64
	err := row.Scan(&p.SourceID, &p.Enabled, &p.Revision, &p.ScheduleKind, &interval, &p.MaximumAddresses, &p.AttemptsPerRound, &cooldown, &p.PausedReason, &last, &confirmed, &p.LastAddress, &p.LastErrorDetail, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, ErrStorage
	}
	p.IntervalMilliseconds = nullable(interval)
	p.CooldownUntil = nullable(cooldown)
	p.LastAttemptedAt = nullable(last)
	p.LastConfirmedAt = nullable(confirmed)
	return p, nil
}
func nullable(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}
func ownerKey() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrStorage
	}
	return "creation-v1:" + hex.EncodeToString(b[:]), nil
}

// The owner and attempt ID are durable before CreateHME. Its deterministic
// operation key can be recovered even before the FK target has been inserted.
func operationKey(id int64, owner string) string {
	if id < 1 || !strings.HasPrefix(owner, "creation-v1:") || len(owner) != 60 {
		return ""
	}
	hash := sha256.Sum256([]byte("creation-operation-v1\x00" + strconv.FormatInt(id, 10) + "\x00" + owner))
	return "auto_" + hex.EncodeToString(hash[:])
}
func safeCode(code string) string {
	if len(code) > 80 {
		return "creation_failed"
	}
	for _, c := range code {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c)) {
			return "creation_failed"
		}
	}
	return code
}
func event(ctx context.Context, tx *sql.Tx, source int64, key, phase, outcome, code string, at int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO space.runtime_events(occurred_at,level,source_id,round_key,attempt,phase,outcome,error_code,message) VALUES($1,$2,$3,$4,1,$5,$6,$7,$5)`, at, map[bool]string{true: "warn", false: "info"}[outcome == "failed"], source, key, phase, outcome, safeCode(code))
	return err
}
func audit(ctx context.Context, tx *sql.Tx, source int64, key, action, outcome string, at int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO space.audit_records(occurred_at,actor_kind,actor_ref,action,resource_kind,resource_ref,outcome,source_id,correlation_key,origin,detail) VALUES($1,'system','creationengine',$2,'creation_policy',$3,$4,$5,$6,'creationengine','')`, at, action, strconv.FormatInt(source, 10), outcome, source, key)
	return err
}
