package addressauth

import (
	"context"
	"strconv"

	"icloudspace/internal/operationlog"
)

type ExportAudit struct {
	Kind, Format, Selection, Stage, Outcome, Reason string
	Count                                           uint64
	SessionEpoch                                    int64
}

// RecordExportAudit records a phase fact, never client delivery or secret bytes.
// The caller closes its read transaction first, allowing a one-connection pool.
func (s *RevealScope) RecordExportAudit(ctx context.Context, record ExportAudit) error {
	if s == nil || record.Kind != "api_key" && record.Kind != "mailbox" || record.Format != "csv" && record.Format != "jsonl" || record.Selection != "filter" && record.Selection != "selection" || record.Stage != "authorized" && record.Stage != "prepared" && record.Stage != "failed" || record.Outcome != "success" && record.Outcome != "failure" && record.Outcome != "unknown" || record.SessionEpoch < 1 {
		return ErrInvalid
	}
	if record.Stage == "failed" {
		if record.Outcome != "failure" || record.Reason != "material_unavailable" && record.Reason != "cancelled" && record.Reason != "stream_write_failed" {
			return ErrInvalid
		}
	} else if record.Outcome != "success" || record.Reason != "" || record.Stage == "authorized" && record.Count != 0 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrInvalid
	}
	actor := operationlog.ContextActor(ctx)
	if actor.Kind != "operator" {
		return ErrInvalid
	}
	tx, e := s.a.db.BeginTx(ctx, nil)
	if e != nil {
		return storageError(ctx)
	}
	defer tx.Rollback()
	e = operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: s.a.clock(), Action: "credential_export", ResourceKind: "address_set", ResourceRef: record.Selection, Outcome: record.Outcome, Fields: map[string]string{"component": "credential_export", "operation_kind": record.Stage + "." + record.Kind + "." + record.Format, "scope": record.Selection + ":epoch:" + strconv.FormatInt(record.SessionEpoch, 10), "stored": strconv.FormatUint(record.Count, 10), "skipped": "0", "reason_code": record.Reason}}))
	if e != nil {
		return ErrStorage
	}
	if s.a.commit(tx) != nil {
		return ErrOutcomeUnknown
	}
	return nil
}
