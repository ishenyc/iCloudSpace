package seenworker

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"math"

	"icloudspace/internal/accounts"
)

const jobColumns = `source_id,source_generation,mailbox_name,uid_validity,remote_uid,state,owner_key,attempts,last_error_code,created_at,next_attempt_at`
const jobWhere = `source_id=$1 AND source_generation=$2 AND mailbox_name=$3 AND uid_validity=$4 AND remote_uid=$5`

type scanner interface{ Scan(...any) error }

func scanJob(row scanner) (job, error) {
	var j job
	var owner sql.NullString
	e := row.Scan(&j.SourceID, &j.SourceGeneration, &j.Mailbox, &j.UIDValidity, &j.UID, &j.State, &owner, &j.Attempts, &j.LastError, &j.CreatedAt, &j.NextAttemptAt)
	j.Owner = owner.String
	j.HasOwner = owner.Valid
	return j, e
}
func (j job) args() []any {
	return []any{j.SourceID, j.SourceGeneration, j.Mailbox, j.UIDValidity, j.UID}
}
func (j job) owner() any {
	if j.HasOwner {
		return j.Owner
	}
	return nil
}
func (j job) equal(other job) bool {
	return j.Identity == other.Identity && j.State == other.State && j.Owner == other.Owner && j.HasOwner == other.HasOwner && j.Attempts == other.Attempts && j.CreatedAt == other.CreatedAt
}
func (s *Service) due(ctx context.Context) ([]job, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT `+jobColumns+` FROM space.seen_jobs WHERE next_attempt_at<=$1 ORDER BY next_attempt_at,source_id,source_generation,mailbox_name,uid_validity,remote_uid LIMIT $2`, s.options.Clock(), s.options.BatchSize)
	if e != nil {
		return nil, storage(ctx)
	}
	defer rows.Close()
	var jobs []job
	for rows.Next() {
		j, e := scanJob(rows)
		if e != nil {
			return nil, storage(ctx)
		}
		if !validIdentity(j.Identity) {
			return nil, ErrInvalid
		}
		jobs = append(jobs, j)
	}
	if rows.Err() != nil {
		return nil, storage(ctx)
	}
	return jobs, nil
}
func (s *Service) scope(ctx context.Context, tx *sql.Tx, j job) (Source, error) {
	var source Source
	var enabled bool
	var port int
	var envelope []byte
	e := tx.QueryRowContext(ctx, `SELECT id,revision,source_generation,credential_generation,enabled,imap_host,imap_port,imap_username,credentials_envelope FROM space.mail_sources WHERE id=$1 FOR UPDATE`, j.SourceID).Scan(&source.ID, &source.Revision, &source.Generation, &source.CredentialGeneration, &enabled, &source.Host, &port, &source.Username, &envelope)
	if errors.Is(e, sql.ErrNoRows) {
		return source, ErrStale
	}
	if e != nil {
		return source, storage(ctx)
	}
	if !enabled {
		return source, ErrDisabled
	}
	if source.Generation != j.SourceGeneration {
		return source, ErrStale
	}
	if port < 1 || port > 65535 {
		return source, ErrInvalid
	}
	source.Port = uint16(port)
	var installation string
	var writes bool
	if tx.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton FOR SHARE`).Scan(&installation, &writes) != nil {
		return source, storage(ctx)
	}
	if installation != s.installation {
		return source, ErrInvalid
	}
	if !writes {
		return source, ErrReadOnly
	}
	var cursorUIDV uint32
	e = tx.QueryRowContext(ctx, `SELECT uid_validity FROM space.mailbox_cursors WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3 FOR SHARE`, j.SourceID, j.SourceGeneration, j.Mailbox).Scan(&cursorUIDV)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return source, storage(ctx)
	}
	if e == nil && cursorUIDV != j.UIDValidity {
		return source, ErrStale
	}
	credentials, e := accounts.OpenCredentials(s.box, accounts.CredentialOwner{InstallationID: s.installation, SourceID: source.ID, Revision: source.Revision}, envelope)
	if e != nil {
		return source, ErrCredentials
	}
	source.Password = credentials.IMAPPassword
	return source, nil
}
func (s *Service) load(ctx context.Context, original job) (Source, job, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Source{}, job{}, storage(ctx)
	}
	defer tx.Rollback()
	source, e := s.scope(ctx, tx, original)
	if e != nil {
		return source, job{}, e
	}
	fresh, e := scanJob(tx.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM space.seen_jobs WHERE `+jobWhere+` FOR UPDATE`, original.args()...))
	if errors.Is(e, sql.ErrNoRows) {
		return source, job{}, ErrStale
	}
	if e != nil {
		return source, job{}, storage(ctx)
	}
	if !fresh.equal(original) || fresh.NextAttemptAt > s.options.Clock() {
		return source, fresh, ErrStale
	}
	if tx.Commit() != nil {
		return source, fresh, ErrUnknown
	}
	return source, fresh, nil
}
func opaque() (string, error) {
	var bytes [24]byte
	if _, e := rand.Read(bytes[:]); e != nil {
		return "", ErrStorage
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}
func (s *Service) claim(ctx context.Context, source Source, j job) (job, error) {
	if j.State != "pending" || j.Attempts == math.MaxInt32 {
		return j, ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return j, storage(ctx)
	}
	defer tx.Rollback()
	fresh, e := s.scope(ctx, tx, j)
	if e != nil {
		return j, e
	}
	if fresh != source {
		return j, ErrStale
	}
	owner := j.Owner
	if !j.HasOwner {
		owner, e = opaque()
		if e != nil {
			return j, e
		}
	}
	args := append(j.args(), j.Attempts, j.owner(), owner, add(s.options.Clock(), s.options.QueryDelay))
	res, e := tx.ExecContext(ctx, `UPDATE space.seen_jobs SET state='claimed',owner_key=$8,attempts=attempts+1,last_error_code='store_inflight',next_attempt_at=$9 WHERE `+jobWhere+` AND state='pending' AND attempts=$6 AND owner_key IS NOT DISTINCT FROM $7::text`, args...)
	if e != nil {
		return j, storage(ctx)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return j, ErrStale
	}
	j.State = "claimed"
	j.HasOwner = true
	j.Owner = owner
	j.Attempts++
	j.NextAttemptAt = add(s.options.Clock(), s.options.QueryDelay)
	if s.commit(tx) != nil {
		return j, ErrUnknown
	}
	return j, nil
}
func (s *Service) complete(ctx context.Context, source Source, j job) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return storage(ctx)
	}
	defer tx.Rollback()
	fresh, e := s.scope(ctx, tx, j)
	if e != nil {
		return e
	}
	if fresh != source {
		return ErrStale
	}
	args := append(j.args(), j.State, j.Attempts, j.owner())
	res, e := tx.ExecContext(ctx, `DELETE FROM space.seen_jobs WHERE `+jobWhere+` AND state=$6 AND attempts=$7 AND owner_key IS NOT DISTINCT FROM $8::text`, args...)
	if e != nil {
		return storage(ctx)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrStale
	}
	if s.commit(tx) != nil {
		return ErrUnknown
	}
	return nil
}
func (s *Service) deferJob(ctx context.Context, j job, code string, pending bool) error {
	state := j.State
	when := s.retryAt(j.Attempts)
	if pending {
		state = "pending"
	} else if state == "claimed" {
		when = add(s.options.Clock(), s.options.QueryDelay)
	}
	args := append(j.args(), j.State, j.Attempts, j.owner(), state, code, when, s.installation)
	res, e := s.db.ExecContext(ctx, `UPDATE space.seen_jobs SET state=$9,last_error_code=$10,next_attempt_at=greatest(next_attempt_at,$11) WHERE `+jobWhere+` AND state=$6 AND attempts=$7 AND owner_key IS NOT DISTINCT FROM $8::text AND EXISTS(SELECT 1 FROM space.installation WHERE singleton AND installation_id=$12 AND writes_enabled)`, args...)
	if e != nil {
		return storage(ctx)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		var installation string
		var writes bool
		if s.db.QueryRowContext(ctx, `SELECT installation_id,writes_enabled FROM space.installation WHERE singleton`).Scan(&installation, &writes) != nil {
			return storage(ctx)
		}
		if installation != s.installation {
			return ErrInvalid
		}
		if !writes {
			return ErrReadOnly
		}
		return ErrStale
	}
	return nil
}
