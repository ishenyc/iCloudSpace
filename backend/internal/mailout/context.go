package mailout

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"icloudspace/internal/vault"
	"io"
	"strings"
	"time"
)

const routeScheme = "mailout-route/v1"

type contextRow struct {
	Evidence
	sourceID, addressID int64
	envelope            []byte
	referenceID         string
	code                string
	diagnostic          *Diagnostic
}
type contextDocument struct {
	Version            int           `json:"version"`
	Source             Source        `json:"source"`
	Address            Address       `json:"address"`
	Plan               BootstrapPlan `json:"plan"`
	Reference          *Reference    `json:"reference,omitempty"`
	CandidateConfirmed bool          `json:"candidate_confirmed"`
	Candidate          *Candidate    `json:"candidate,omitempty"`
	Diagnostic         *Diagnostic   `json:"diagnostic,omitempty"`
}

const contextColumns = `context_key,source_id,address_id,route_recipient,route_fingerprint,fingerprint_scheme,query_only,owner_key,nonce,state,candidate_id,candidate_message_id,candidate_uid_validity,seed_id,seed_message_id,append_outcome,seed_outcome,reference_id,context_envelope,error_code`

type scanner interface{ Scan(...any) error }

func scanContext(q scanner) (contextRow, error) {
	var row contextRow
	var candidate, message, seed, seedMessage, appendOutcome, seedOutcome, reference sql.NullString
	var uidv sql.NullInt64
	e := q.Scan(&row.ContextKey, &row.sourceID, &row.addressID, &row.Recipient, &row.Fingerprint, &row.FingerprintScheme, &row.QueryOnly, &row.OwnerKey, &row.Nonce, &row.State, &candidate, &message, &uidv, &seed, &seedMessage, &appendOutcome, &seedOutcome, &reference, &row.envelope, &row.code)
	if errors.Is(e, sql.ErrNoRows) {
		return row, ErrNotFound
	}
	if e != nil {
		return row, ErrStorage
	}
	row.CandidateID = candidate.String
	row.CandidateMessageID = message.String
	row.CandidateUIDValidity = uint32(uidv.Int64)
	row.SeedID = seed.String
	row.SeedMessageID = seedMessage.String
	row.referenceID = reference.String
	row.ReferenceID = reference.String
	if appendOutcome.Valid {
		o := Outcome(appendOutcome.String)
		row.AppendOutcome = &o
	}
	if seedOutcome.Valid {
		o := Outcome(seedOutcome.String)
		row.SeedOutcome = &o
	}
	return row, nil
}
func (s *Service) context(ctx context.Context, key string) (contextRow, error) {
	return s.lookupContext(ctx, s.db, key)
}
func (s *Service) loadContext(ctx context.Context, q rowQuery, key string) (contextRow, error) {
	row, e := scanContext(q.QueryRowContext(ctx, `SELECT `+contextColumns+` FROM space.compose_contexts WHERE context_key=$1`, key))
	if e != nil {
		return row, e
	}
	if !row.QueryOnly {
		doc, e := s.openContext(row)
		if e != nil {
			return row, e
		}
		row.Draft = &doc.Plan.Draft
		row.diagnostic = doc.Diagnostic
	}
	return row, nil
}
func (s *Service) contexts(ctx context.Context, q contextQuery, address int64, recipient string) ([]contextRow, error) {
	rows, e := q.QueryContext(ctx, `SELECT `+contextColumns+` FROM space.compose_contexts WHERE address_id=$1 AND lower(btrim(route_recipient))=lower(btrim($2::text)) ORDER BY updated_at DESC,context_key`, address, recipient)
	if e != nil {
		return nil, storage(ctx)
	}
	defer rows.Close()
	out := []contextRow{}
	for rows.Next() {
		row, e := scanContext(rows)
		if e != nil {
			return nil, e
		}
		if !row.QueryOnly {
			doc, e := s.openContext(row)
			if e != nil {
				return nil, e
			}
			row.Draft = &doc.Plan.Draft
			row.diagnostic = doc.Diagnostic
		}
		out = append(out, row)
	}
	if rows.Err() != nil {
		return nil, storage(ctx)
	}
	return out, nil
}
func (s *Service) contextBinding(key string) vault.Binding {
	return vault.Binding{InstallationID: s.installation, SubjectType: "compose_context", SubjectID: key, Purpose: "provider_reference", Revision: 1}
}
func (s *Service) sealContext(key string, doc contextDocument) ([]byte, error) {
	// Encrypted context documents have a fixed diagnostic shape. Extended
	// attempt facts belong to send_submissions.error_detail, whose reader
	// accepts additional fields.
	if doc.Diagnostic != nil {
		legacy := *doc.Diagnostic
		legacy.Operation, legacy.TransportPhase, legacy.TransportReason, legacy.Attempts = "", "", "", 0
		doc.Diagnostic = &legacy
	}
	raw, e := json.Marshal(doc)
	if e != nil {
		return nil, ErrStorage
	}
	envelope, e := s.box.Seal(s.contextBinding(key), raw)
	clear(raw)
	if e != nil {
		return nil, ErrStorage
	}
	return []byte(envelope), nil
}
func (s *Service) openContext(row contextRow) (contextDocument, error) {
	if row.QueryOnly {
		return contextDocument{}, ErrReference
	}
	raw, e := s.box.Open(s.contextBinding(row.ContextKey), string(row.envelope))
	if e != nil {
		return contextDocument{}, ErrStorage
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc contextDocument
	if decoder.Decode(&doc) != nil || doc.Version != 1 && doc.Version != 2 || doc.Source.ID != row.sourceID || doc.Address.ID != row.addressID || doc.Plan.ContextKey != row.ContextKey || doc.Plan.OwnerKey != row.OwnerKey || doc.Plan.Nonce != row.Nonce {
		return contextDocument{}, ErrStorage
	}
	if doc.Plan.Draft.Subject != row.Nonce || !sameAddress(doc.Plan.Draft.From, doc.Source.PrimaryAddress) || !sameAddress(doc.Plan.Draft.To, doc.Address.Email) || !sameAddress(doc.Plan.Draft.ReplyTo, row.Recipient) {
		return contextDocument{}, ErrStorage
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return contextDocument{}, ErrStorage
	}
	return doc, nil
}
func routeFingerprint(scope Scope, recipient string) [32]byte {
	raw, _ := json.Marshal(struct {
		Version   string
		Source    Source
		Address   Address
		Recipient string
	}{routeScheme, scope.Source, scope.Address, strings.ToLower(strings.TrimSpace(recipient))})
	return sha256.Sum256(raw)
}
func (s *Service) ensureContext(ctx context.Context, scope Scope, key, recipient string) ([]contextRow, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, storage(ctx)
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return nil, e
	}
	current, e := s.loadScope(ctx, tx, scope.Source.ID, scope.Address.ID, scope.Gate)
	if e != nil {
		return nil, e
	}
	if current.Source != scope.Source || current.Address != scope.Address {
		return nil, ErrConflict
	}
	if key != "" {
		if row, e := s.lookupContext(ctx, tx, key); e == nil {
			if e = s.contextScope(row, scope, recipient); e != nil {
				return nil, e
			}
			if e = s.rememberContextRequest(ctx, tx, key, row); e != nil {
				return nil, e
			}
			if s.commit(tx) != nil {
				return nil, ErrUnknown
			}
			return []contextRow{row}, nil
		} else if !errors.Is(e, ErrNotFound) {
			return nil, e
		}
	}
	rows, e := s.contexts(ctx, tx, scope.Address.ID, recipient)
	if e != nil {
		return nil, e
	}
	eligible := rows[:0]
	for _, row := range rows {
		matches, e := s.contextRouteMatches(row, scope, recipient)
		if e != nil {
			return nil, e
		}
		if matches {
			var unresolved bool
			if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.send_submissions WHERE context_key=$1 AND route_outcome='unknown')`, row.ContextKey).Scan(&unresolved) != nil {
				return nil, ErrStorage
			}
			if !unresolved && replaceableContext(row) {
				continue
			}
			eligible = append(eligible, row)
		}
	}
	rows = eligible
	if len(rows) != 0 {
		if key != "" && len(rows) == 1 {
			if e = s.rememberContextRequest(ctx, tx, key, rows[0]); e != nil {
				return nil, e
			}
		}
		if s.commit(tx) != nil {
			return nil, ErrUnknown
		}
		return rows, nil
	}
	if key == "" {
		id, e := randomID()
		if e != nil {
			return nil, e
		}
		key = "context." + id
	}
	if !validNativeKey(key) {
		return nil, ErrInvalid
	}
	owner, e := randomID()
	if e != nil {
		return nil, e
	}
	var entropy [24]byte
	_, e = rand.Read(entropy[:])
	if e != nil {
		return nil, e
	}
	nonce := "hme-route-" + hex.EncodeToString(entropy[:])
	rpc, e := randomID()
	if e != nil {
		return nil, e
	}
	plan := BootstrapPlan{ContextKey: key, OwnerKey: owner, Nonce: nonce, RPCID: rpc, Draft: DraftIntent{From: scope.Source.PrimaryAddress, To: scope.Address.Email, ReplyTo: recipient, Subject: nonce, Text: "Private route initialization for your selected Hide My Email address.\r\n"}}
	doc := contextDocument{Version: 2, Source: scope.Source, Address: scope.Address, Plan: plan}
	envelope, e := s.sealContext(key, doc)
	if e != nil {
		return nil, e
	}
	fingerprint := routeFingerprint(scope, recipient)
	now := s.options.Clock()
	_, e = tx.ExecContext(ctx, `INSERT INTO space.compose_contexts(context_key,source_id,address_id,route_recipient,route_fingerprint,fingerprint_scheme,query_only,owner_key,nonce,state,context_envelope,error_code,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,false,$7,$8,'reserved',$9,'',$10,$10)`, key, scope.Source.ID, scope.Address.ID, strings.ToLower(strings.TrimSpace(recipient)), fingerprint[:], routeScheme, owner, nonce, envelope, now)
	if e != nil {
		return nil, ErrConflict
	}
	row, e := s.loadContext(ctx, tx, key)
	if e != nil {
		return nil, e
	}
	if e = s.rememberContextRequest(ctx, tx, key, row); e != nil {
		return nil, e
	}
	if s.commit(tx) != nil {
		return nil, ErrUnknown
	}
	return []contextRow{row}, nil
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func outcomeValue(o *Outcome) any {
	if o == nil {
		return nil
	}
	return string(*o)
}
func (s *Service) writeContext(ctx context.Context, row *contextRow, doc contextDocument, state, code string) error {
	if row.QueryOnly {
		return ErrConflict
	}
	doc.Version = 2
	envelope, e := s.sealContext(row.ContextKey, doc)
	if e != nil {
		return e
	}
	var uidv any
	if row.CandidateUIDValidity != 0 {
		uidv = row.CandidateUIDValidity
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return storage(ctx)
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return e
	}
	r, e := tx.ExecContext(ctx, `UPDATE space.compose_contexts SET state=$3,candidate_id=$4,candidate_message_id=$5,candidate_uid_validity=$6,seed_id=$7,seed_message_id=$8,append_outcome=$9,seed_outcome=$10,reference_id=$11,context_envelope=$12,error_code=$13,updated_at=$14 WHERE context_key=$1 AND owner_key=$2 AND NOT query_only`, row.ContextKey, row.OwnerKey, state, nullable(row.CandidateID), nullable(row.CandidateMessageID), uidv, nullable(row.SeedID), nullable(row.SeedMessageID), outcomeValue(row.AppendOutcome), outcomeValue(row.SeedOutcome), nullable(row.referenceID), envelope, code, s.options.Clock())
	if e != nil {
		return storage(ctx)
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return ErrConflict
	}
	if s.commit(tx) != nil {
		return ErrUnknown
	}
	row.State = state
	row.code = code
	row.diagnostic = doc.Diagnostic
	row.envelope = envelope
	row.ReferenceID = row.referenceID
	return nil
}

func (s *Service) recordContext(ctx context.Context, row *contextRow, doc contextDocument, state, code string) error {
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.writeContext(persist, row, doc, state, code)
}
func contextStatus(row contextRow) ContextStatus {
	return ContextStatus{Evidence: row.Evidence, ReadOnly: row.QueryOnly, Ready: row.State == "ready", Code: row.code, Diagnostic: row.diagnostic}
}
func replaceableContext(row contextRow) bool {
	if row.QueryOnly || row.State != "failed" || row.AppendOutcome == nil {
		return false
	}
	return ((*row.AppendOutcome == NotSent || *row.AppendOutcome == Rejected) && row.SeedOutcome == nil) || (*row.AppendOutcome == Accepted && row.SeedOutcome != nil && (*row.SeedOutcome == Rejected || *row.SeedOutcome == NotSent))
}
func (s *Service) QueryContext(ctx context.Context, address int64, key string) (ContextStatus, error) {
	if address < 1 || !validQueryKey(key) {
		return ContextStatus{}, ErrInvalid
	}
	row, e := s.context(ctx, key)
	if e != nil {
		return ContextStatus{}, e
	}
	if row.addressID != address {
		return ContextStatus{}, ErrNotFound
	}
	return contextStatus(row), nil
}
func validCandidate(c Candidate, e Evidence) bool {
	return token(c.ID, 2048) && (c.MessageID == "" || token(c.MessageID, 2048)) && c.Nonce == e.Nonce && (e.CandidateID == "" || c.ID == e.CandidateID) && (e.CandidateMessageID == "" || c.MessageID == e.CandidateMessageID) && (e.CandidateUIDValidity == 0 || c.UIDValidity == e.CandidateUIDValidity)
}
func (s *Service) RefreshContext(ctx context.Context, address int64, key string) (result ContextStatus, retErr error) {
	if address < 1 || !validQueryKey(key) {
		return ContextStatus{}, ErrInvalid
	}
	row, e := s.context(ctx, key)
	if e != nil {
		return ContextStatus{}, e
	}
	if row.addressID != address {
		return ContextStatus{}, ErrNotFound
	}
	source, e := s.sourceID(ctx, address)
	if e != nil {
		return ContextStatus{}, e
	}
	ctx, gate, close, e := s.enter(ctx, source)
	if e != nil {
		return ContextStatus{}, e
	}
	defer close()
	scope, e := s.scope(ctx, source, address, gate)
	if e != nil {
		return contextStatus(row), e
	}
	if e = s.contextScope(row, scope, row.Recipient); e != nil {
		return contextStatus(row), e
	}
	op, e := s.provider.Open(ctx, scope)
	if e != nil {
		return contextStatus(row), ErrProvider
	}
	defer func() {
		if op.Close() != nil {
			result.Code = "session_persist_failed"
			if retErr == nil {
				retErr = ErrUnknown
			}
		}
	}()
	route, e := op.ValidateRoute(ctx, row.Recipient)
	if e != nil || !s.route(scope, row.Recipient, route) {
		return contextStatus(row), ErrProvider
	}
	return s.refreshContext(ctx, op, scope, route, &row)
}
func (s *Service) refreshContext(ctx context.Context, op Operation, scope Scope, route Route, row *contextRow) (ContextStatus, error) {
	status := contextStatus(*row)
	status.Ready = false
	ref, ready, e := s.readReference(ctx, op, scope, route, row.Evidence)
	if e != nil {
		return status, e
	}
	if e == nil && ready {
		status.Ready = true
		status.Reference = &ref
		pendingBootstrap := row.AppendOutcome != nil || row.SeedOutcome != nil || row.State == "preparing" || row.State == "candidate_unknown" || row.State == "candidate_confirmed" || row.State == "draft_ready" || row.State == "seed_unknown"
		if (ref.Kind == IncomingReference || ref.Kind == RouteReference) && pendingBootstrap {
			status.Code = "alternate_reference_available"
			return status, nil
		}
		if !row.QueryOnly {
			doc, e := s.openContext(*row)
			if e != nil {
				return status, e
			}
			doc.Reference = &ref
			row.referenceID = ref.ID
			if row.SeedOutcome != nil && row.SeedMessageID == "" {
				row.SeedMessageID = ref.MessageID
			}
			if row.State == "failed" {
				return status, nil
			}
			if e = s.writeContext(ctx, row, doc, "ready", ""); e != nil {
				return status, e
			}
			status.Evidence = row.Evidence
		}
		return status, nil
	}
	if row.QueryOnly {
		status.Code = "reference_pending"
		return status, nil
	}
	if row.SeedOutcome == nil && row.AppendOutcome != nil && (row.State == "candidate_unknown" || row.State == "preparing") {
		candidate, found, e := op.FindCandidate(ctx, route, row.Evidence)
		if e != nil {
			return status, ErrReference
		}
		if found {
			if !validCandidate(candidate, row.Evidence) {
				return status, ErrProvider
			}
			doc, e := s.openContext(*row)
			if e != nil {
				return status, e
			}
			row.CandidateID = candidate.ID
			row.CandidateMessageID = candidate.MessageID
			row.CandidateUIDValidity = candidate.UIDValidity
			doc.CandidateConfirmed = true
			doc.Candidate = &candidate
			if e = s.writeContext(ctx, row, doc, "draft_ready", ""); e != nil {
				return status, e
			}
			status.Evidence = row.Evidence
		}
	}
	status.Code = "reference_pending"
	return status, nil
}
