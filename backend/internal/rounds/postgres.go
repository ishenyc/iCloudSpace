package rounds

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"icloudspace/internal/sourceguard"
)

type Postgres struct {
	DB       *sql.DB
	Registry *sourceguard.Registry
	commit   func(*sql.Tx) error
}

func NewPostgres(db *sql.DB, registry *sourceguard.Registry) *Postgres {
	return &Postgres{DB: db, Registry: registry, commit: (*sql.Tx).Commit}
}
func (r *Postgres) valid(gate *sourceguard.Lease, id int64) bool {
	return r != nil && r.DB != nil && r.Registry != nil && gate.ValidFor(r.Registry, id)
}

func readConfiguration(ctx context.Context, tx *sql.Tx, lock bool) (int64, time.Duration, error) {
	query := `SELECT i.configuration_revision,s.sync_rest_milliseconds FROM space.installation i JOIN space.installation_settings s USING(singleton) WHERE i.singleton`
	if lock {
		query += ` FOR SHARE OF i,s`
	}
	var revision, ms int64
	if err := tx.QueryRowContext(ctx, query).Scan(&revision, &ms); err != nil {
		return 0, 0, err
	}
	if revision < 1 || ms < 0 || ms > math.MaxInt64/int64(time.Millisecond) {
		return 0, 0, ErrInvalid
	}
	return revision, time.Duration(ms) * time.Millisecond, nil
}

const projection = `id,revision,source_generation,credential_generation,enabled,kind IN ('apple_direct','apple_forwarded'),automatic_sync_after,last_terminal_sync_at`

func scanSource(scan interface{ Scan(...any) error }, configuration int64, rest time.Duration) (s Source, err error) {
	err = scan.Scan(&s.Scope.SourceID, &s.Scope.Revision, &s.Scope.Generation, &s.Scope.CredentialGeneration, &s.Enabled, &s.HasDirectory, &s.AutomaticAfter, &s.LastTerminal)
	s.Scope.ConfigurationRevision = configuration
	s.RestInterval = rest
	return
}

func (r *Postgres) LoadCatalog(ctx context.Context, limit int) ([]Source, error) {
	if r == nil || r.DB == nil || limit < 1 {
		return nil, ErrInvalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	revision, rest, err := readConfiguration(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+projection+` FROM space.mail_sources WHERE retired_at IS NULL ORDER BY id LIMIT $1`, limit+1)
	if err != nil {
		return nil, err
	}
	var out []Source
	for rows.Next() {
		s, e := scanSource(rows, revision, rest)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, ErrCapacity
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
func (r *Postgres) CurrentSource(ctx context.Context, id int64) (Source, error) {
	if r == nil || r.DB == nil || id < 1 {
		return Source{}, ErrInvalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Source{}, err
	}
	defer tx.Rollback()
	revision, rest, err := readConfiguration(ctx, tx, false)
	if err != nil {
		return Source{}, err
	}
	s, err := scanSource(tx.QueryRowContext(ctx, `SELECT `+projection+` FROM space.mail_sources WHERE id=$1`, id), revision, rest)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrStale
	}
	if err != nil {
		return s, err
	}
	if err = tx.Commit(); err != nil {
		return s, err
	}
	return s, nil
}

func validTerminal(t Terminal) bool {
	if !validScope(t.Source.Scope) || !t.Source.Enabled || t.Source.RestInterval < 0 || t.RoundID == "" {
		return false
	}
	if t.Trigger != Automatic && t.Trigger != Manual && t.Trigger != Public {
		return false
	}
	if t.Outcome != Succeeded && t.Outcome != Degraded && t.Outcome != Failed && t.Outcome != Unknown {
		return false
	}
	if safeCode(t.ErrorCode) != t.ErrorCode || safeCode(t.DirectoryErrorCode) != t.DirectoryErrorCode {
		return false
	}
	if t.Outcome == Succeeded && t.ErrorCode != "" || t.Outcome != Succeeded && t.ErrorCode == "" {
		return false
	}
	if t.Source.LastTerminal != nil && t.At <= *t.Source.LastTerminal {
		return false
	}
	if t.Trigger != Automatic {
		return t.AutomaticAfter == nil
	}
	if t.AutomaticAfter == nil {
		return false
	}
	after, err := ns(time.Unix(0, t.At).Add(t.Source.RestInterval))
	return err == nil && after == *t.AutomaticAfter
}
func terminalState(t Terminal) string {
	state := string(t.Outcome)
	if t.Trigger == Public {
		state = "mail_" + state
	}
	return state
}
func equalNS(a, b *int64) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func (r *Postgres) RecordTerminal(ctx context.Context, gate *sourceguard.Lease, t Terminal) error {
	if !r.valid(gate, t.Source.Scope.SourceID) || !validTerminal(t) {
		return ErrInvalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Same lock order as other canonical source owners: source, then global
	// configuration/settings. No network lease or IMAP permit is held here.
	actual, err := scanSource(tx.QueryRowContext(ctx, `SELECT `+projection+` FROM space.mail_sources WHERE id=$1 FOR UPDATE`, t.Source.Scope.SourceID), t.Source.Scope.ConfigurationRevision, t.Source.RestInterval)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStale
	}
	if err != nil {
		return err
	}
	revision, rest, err := readConfiguration(ctx, tx, true)
	if err != nil {
		return err
	}
	actual.Scope.ConfigurationRevision = revision
	actual.RestInterval = rest
	if actual.Scope != t.Source.Scope || !actual.Enabled || actual.RestInterval != t.Source.RestInterval || actual.HasDirectory != t.Source.HasDirectory {
		return ErrStale
	}
	if !equalNS(actual.LastTerminal, t.Source.LastTerminal) || !equalNS(actual.AutomaticAfter, t.Source.AutomaticAfter) {
		tx.Rollback()
		resolution, e := r.ResolveTerminal(ctx, gate, t)
		if e == nil && resolution == Recorded {
			return nil
		}
		return ErrStale
	}
	_, err = tx.ExecContext(ctx, `UPDATE space.mail_sources SET
 automatic_sync_after=CASE WHEN $2::text='automatic' THEN $3::bigint ELSE automatic_sync_after::bigint END,
 last_terminal_sync_at=$4::bigint,last_sync_state=$5,last_sync_error=$6,
 last_synced_at=CASE WHEN $7::boolean THEN $4::bigint ELSE last_synced_at::bigint END
 WHERE id=$1`, t.Source.Scope.SourceID, string(t.Trigger), t.AutomaticAfter, t.At, terminalState(t), t.ErrorCode, t.MailComplete)
	if err != nil {
		return err
	}
	commit := r.commit
	if commit == nil {
		commit = (*sql.Tx).Commit
	}
	if err = commit(tx); err == nil {
		return nil
	}
	// Query the exact stable terminal facts after waiting for its source lock.
	// An unknown result never causes this method to repeat the UPDATE.
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	resolution, e := r.ResolveTerminal(lookup, gate, t)
	if e == nil && resolution == Recorded {
		return nil
	}
	if e == nil && resolution == NotRecorded {
		return ErrNotRecorded
	}
	return ErrUnknown
}

func (r *Postgres) ResolveTerminal(ctx context.Context, gate *sourceguard.Lease, t Terminal) (Resolution, error) {
	if !r.valid(gate, t.Source.Scope.SourceID) || !validTerminal(t) {
		return Unresolved, ErrInvalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return Unresolved, err
	}
	defer tx.Rollback()
	var revision, generation, credential int64
	var enabled bool
	var automatic, last, synced *int64
	var state, code string
	err = tx.QueryRowContext(ctx, `SELECT revision,source_generation,credential_generation,enabled,automatic_sync_after,last_terminal_sync_at,last_sync_state,last_sync_error,last_synced_at FROM space.mail_sources WHERE id=$1 FOR SHARE`, t.Source.Scope.SourceID).Scan(&revision, &generation, &credential, &enabled, &automatic, &last, &state, &code, &synced)
	if errors.Is(err, sql.ErrNoRows) {
		return Unresolved, ErrStale
	}
	if err != nil {
		return Unresolved, err
	}
	configuration, rest, err := readConfiguration(ctx, tx, true)
	if err != nil {
		return Unresolved, err
	}
	if !enabled || revision != t.Source.Scope.Revision || generation != t.Source.Scope.Generation || credential != t.Source.Scope.CredentialGeneration || configuration != t.Source.Scope.ConfigurationRevision || rest != t.Source.RestInterval {
		return Unresolved, ErrStale
	}
	expectedAutomatic := t.Source.AutomaticAfter
	if t.Trigger == Automatic {
		expectedAutomatic = t.AutomaticAfter
	}
	if last != nil && *last == t.At && equalNS(automatic, expectedAutomatic) && state == terminalState(t) && code == t.ErrorCode && (!t.MailComplete || synced != nil && *synced == t.At) {
		if err = tx.Commit(); err != nil {
			return Unresolved, err
		}
		return Recorded, nil
	}
	if equalNS(last, t.Source.LastTerminal) && equalNS(automatic, t.Source.AutomaticAfter) {
		if err = tx.Commit(); err != nil {
			return Unresolved, err
		}
		return NotRecorded, nil
	}
	return Unresolved, nil
}
