package operationlog

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"strings"
)

func New(ctx context.Context, db *sql.DB, installation string, options Options) (*Service, error) {
	if db == nil || installation == "" {
		return nil, ErrInvalid
	}
	var actual string
	if err := db.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual); err != nil || actual != installation {
		return nil, ErrBinding
	}
	ring, err := NewRing(options)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, installation: installation, ring: ring}, nil
}
func (s *Service) Ring() *Ring { return s.ring }
func like(query string) string {
	query = strings.ReplaceAll(query, `\`, `\\`)
	query = strings.ReplaceAll(query, `%`, `\%`)
	query = strings.ReplaceAll(query, `_`, `\_`)
	return "%" + query + "%"
}
func (s *Service) read(ctx context.Context) (*sql.Tx, error) {
	if s == nil {
		return nil, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, ErrStorage
	}
	var actual string
	if err = tx.QueryRowContext(ctx, `SELECT installation_id FROM space.installation WHERE singleton`).Scan(&actual); err != nil || actual != s.installation {
		tx.Rollback()
		return nil, ErrBinding
	}
	return tx, nil
}

// Runtime namespaces the process-local ring separately from retained SQL ids.
// History is paged directly in SQL, never loaded wholesale into the ring.
func (s *Service) Runtime(ctx context.Context, stream string, filter Filter, cursor Cursor) (RuntimePage, error) {
	if s == nil || !validateFilter(filter, cursor) {
		return RuntimePage{}, ErrInvalid
	}
	if stream == "live" {
		return s.ring.List(filter, cursor)
	}
	if stream != "history" {
		return RuntimePage{}, ErrInvalid
	}
	tx, err := s.read(ctx)
	if err != nil {
		return RuntimePage{}, err
	}
	defer tx.Rollback()
	page := RuntimePage{Stream: "history", Items: []Entry{}, Limit: cursor.Limit, BeforeID: cursor.BeforeID, AfterID: cursor.AfterID}
	args := []any{filter.Level, filter.SourceID, filter.RoundKey, filter.Query, like(filter.Query)}
	where := ` WHERE ($1='' OR level=$1) AND ($2::bigint IS NULL OR source_id=$2) AND ($3='' OR round_key=$3) AND ($4='' OR phase ILIKE $5 ESCAPE '\' OR outcome ILIKE $5 ESCAPE '\' OR error_code ILIKE $5 ESCAPE '\' OR round_key ILIKE $5 ESCAPE '\')`
	var earliest, latest sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT count(*),min(id),max(id) FROM space.runtime_events`+where, args...).Scan(&page.Total, &earliest, &latest); err != nil {
		return page, ErrStorage
	}
	if earliest.Valid {
		page.EarliestID = &earliest.Int64
		page.LatestID = &latest.Int64
	}
	args = append(args, cursor.BeforeID, cursor.AfterID, cursor.Limit+1)
	rows, err := tx.QueryContext(ctx, `SELECT id,occurred_at,left(level,32),source_id,left(round_key,129),attempt,left(phase,81),left(outcome,81),left(error_code,81) FROM space.runtime_events`+where+` AND ($6::bigint IS NULL OR id<$6) AND ($7::bigint IS NULL OR id>$7) ORDER BY id DESC LIMIT $8`, args...)
	if err != nil {
		return page, ErrStorage
	}
	for rows.Next() {
		var raw Event
		var id int64
		var source sql.NullInt64
		if err = rows.Scan(&id, &raw.OccurredAt, &raw.Level, &source, &raw.RoundKey, &raw.Attempt, &raw.Phase, &raw.Outcome, &raw.ErrorCode); err != nil {
			rows.Close()
			return page, ErrStorage
		}
		if source.Valid {
			raw.SourceID = &source.Int64
		}
		page.Items = append(page.Items, Entry{ID: id, Event: cleanEvent(raw, raw.OccurredAt)})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, ErrStorage
	}
	if len(page.Items) > cursor.Limit {
		next := page.Items[cursor.Limit-1].ID
		page.NextBeforeID = &next
		page.Items = page.Items[:cursor.Limit]
	}
	if err = tx.Commit(); err != nil {
		return page, ErrStorage
	}
	return page, nil
}

// RecordAuditTx participates in a caller-owned local transaction. It neither
// commits nor retries, and must not be used to reinterpret an external result.
func RecordAuditTx(ctx context.Context, tx *sql.Tx, record Record) error {
	if tx == nil || record.OccurredAt <= 0 || !validActor(record.ActorKind) || !validOutcome(record.Outcome) || token(record.ActorRef, 128) != record.ActorRef || record.ActorRef == "" || token(record.Action, 80) != record.Action || record.Action == "" || token(record.ResourceKind, 80) != record.ResourceKind || record.ResourceKind == "" || token(record.ResourceRef, 128) != record.ResourceRef || record.ResourceRef == "" || record.SourceID != nil && *record.SourceID < 1 || record.CorrelationKey != "" && token(record.CorrelationKey, 128) != record.CorrelationKey {
		return ErrInvalid
	}
	r := cleanRecord(record)
	if r.Origin != record.Origin {
		return ErrInvalid
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO space.audit_records(occurred_at,actor_kind,actor_ref,actor_display,action,resource_kind,resource_ref,outcome,source_id,correlation_key,origin,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, r.OccurredAt, r.ActorKind, r.ActorRef, r.ActorKind+" "+r.ActorRef, r.Action, r.ResourceKind, r.ResourceRef, r.Outcome, r.SourceID, r.CorrelationKey, r.Origin, encodedFields(r.Fields))
	if err != nil {
		return ErrStorage
	}
	return nil
}

func (s *Service) Audits(ctx context.Context, filter AuditFilter, page Page) (AuditPage, error) {
	result := AuditPage{Items: []Audit{}}
	if !validText(filter.Query, 200) || filter.SourceID != nil && *filter.SourceID < 1 || filter.Action != "" && token(filter.Action, 80) != filter.Action || filter.Outcome != "" && !validOutcome(filter.Outcome) || page.Limit < 1 || page.Limit > 100 || page.Offset < 0 || page.Offset > math.MaxInt64-int64(page.Limit) {
		return result, ErrInvalid
	}
	tx, err := s.read(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	args := []any{filter.SourceID, filter.Action, filter.Outcome, filter.Query, like(filter.Query)}
	where := ` WHERE ($1::bigint IS NULL OR source_id=$1) AND ($2='' OR action=$2) AND ($3='' OR outcome=$3) AND ($4='' OR action ILIKE $5 ESCAPE '\' OR resource_kind ILIKE $5 ESCAPE '\' OR resource_ref ILIKE $5 ESCAPE '\' OR actor_ref ILIKE $5 ESCAPE '\' OR correlation_key ILIKE $5 ESCAPE '\')`
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM space.audit_records`+where, args...).Scan(&result.Total); err != nil {
		return result, ErrStorage
	}
	args = append(args, page.Limit, page.Offset)
	rows, err := tx.QueryContext(ctx, `SELECT id,occurred_at,left(actor_kind,32),left(actor_ref,129),left(action,81),left(resource_kind,81),left(resource_ref,129),left(outcome,32),source_id,left(correlation_key,129),left(origin,129),left(detail,8193) FROM space.audit_records`+where+` ORDER BY id DESC LIMIT $6 OFFSET $7`, args...)
	if err != nil {
		return result, ErrStorage
	}
	for rows.Next() {
		var id int64
		var raw Record
		var source sql.NullInt64
		var detail string
		if err = rows.Scan(&id, &raw.OccurredAt, &raw.ActorKind, &raw.ActorRef, &raw.Action, &raw.ResourceKind, &raw.ResourceRef, &raw.Outcome, &source, &raw.CorrelationKey, &raw.Origin, &detail); err != nil {
			rows.Close()
			return result, ErrStorage
		}
		if source.Valid {
			raw.SourceID = &source.Int64
		}
		if len(detail) <= 8192 {
			_ = json.Unmarshal([]byte(detail), &raw.Fields)
		}
		result.Items = append(result.Items, presentAudit(id, raw))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, ErrStorage
	}
	if err = tx.Commit(); err != nil {
		return result, ErrStorage
	}
	return result, nil
}
