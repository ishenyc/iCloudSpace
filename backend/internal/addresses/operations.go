package addresses

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// This document contains only stable command inputs and identity generations.
// No provider capsule, password, key or raw upstream JSON is stored here.
type operationRequest struct {
	Version           int    `json:"version"`
	SourceRevision    int64  `json:"source_revision"`
	PrincipalRevision int64  `json:"principal_revision"`
	SourceGeneration  int64  `json:"source_generation"`
	Label             string `json:"label"`
	GroupID           *int64 `json:"group_id"`
	Forward           string `json:"forward"`
	Profile           string `json:"profile"`
	AddressID         int64  `json:"address_id"`
	AddressRevision   int64  `json:"address_revision"`
	ConfirmAddress    string `json:"confirm_address"`
}

func opaque() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func operationKey(v string) bool {
	if len(v) < 1 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

const operationColumns = `operation_key,source_id,address_id,kind,owner_key,nonce,candidate_email,candidate_id,state,error_code,created_at,updated_at,request_document,request_digest`

func scanOperation(row scanner) (Operation, operationRequest, []byte, error) {
	var op Operation
	var data, digest []byte
	var request operationRequest
	err := row.Scan(&op.Key, &op.SourceID, &op.AddressID, &op.Kind, &op.OwnerKey, &op.Nonce, &op.CandidateAddress, &op.CandidateID, &op.State, &op.ErrorCode, &op.CreatedAt, &op.UpdatedAt, &data, &digest)
	if err != nil {
		return op, request, nil, classify(err)
	}
	if len(digest) != sha256.Size || len(data) == 0 || json.Unmarshal(data, &request) != nil || request.Version != 1 {
		return op, request, digest, ErrConflict
	}
	// JSONB reorders keys, so verify the semantic v1 document through its fixed
	// struct encoding rather than hashing PostgreSQL's presentation bytes.
	canonical, err := json.Marshal(request)
	if err != nil {
		return op, request, digest, ErrConflict
	}
	want := sha256.Sum256(canonical)
	if !bytes.Equal(digest, want[:]) {
		return op, request, digest, ErrConflict
	}
	op.QueryOnly = true
	return op, request, digest, nil
}
func (s *Service) operation(ctx context.Context, key, kind, owner string) (Operation, operationRequest, error) {
	op, r, _, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM space.address_operations WHERE operation_key=$1`, key))
	if err != nil {
		return op, r, err
	}
	if op.Kind != kind || op.OwnerKey != owner {
		return Operation{}, r, ErrConflict
	}
	return op, r, nil
}

func (s *Service) sourceRetired(ctx context.Context, id int64) (bool, error) {
	var retired bool
	err := s.db.QueryRowContext(ctx, `SELECT retired_at IS NOT NULL FROM space.mail_sources WHERE id=$1`, id).Scan(&retired)
	return retired, classify(err)
}
func (s *Service) claim(ctx context.Context, tx *sql.Tx, src source, key, kind, owner string, address *int64, request operationRequest) (Operation, bool, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return Operation{}, false, err
	}
	digest := sha256.Sum256(data)
	op, _, existing, e := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM space.address_operations WHERE operation_key=$1 FOR UPDATE`, key))
	if e == nil {
		if op.Kind != kind || op.SourceID != src.ID || op.OwnerKey != owner || !bytes.Equal(existing, digest[:]) {
			return Operation{}, false, ErrConflict
		}
		return op, false, nil
	}
	if e != ErrNotFound {
		return Operation{}, false, e
	}
	if address != nil {
		var pending bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_operations WHERE address_id=$1 AND state NOT IN ('confirmed','failed'))`, *address).Scan(&pending); err != nil {
			return Operation{}, false, err
		}
		if pending {
			return Operation{}, false, ErrConflict
		}
	}
	nonce, err := opaque()
	if err != nil {
		return Operation{}, false, err
	}
	now := s.clock()
	_, err = tx.ExecContext(ctx, `INSERT INTO space.address_operations(operation_key,source_id,address_id,kind,owner_key,nonce,state,error_code,created_at,updated_at,request_document,request_digest) VALUES($1,$2,$3,$4,$5,$6,'reserved','',$7,$7,$8,$9)`, key, src.ID, address, kind, owner, nonce, now, data, digest[:])
	if err != nil {
		return Operation{}, false, classify(err)
	}
	return Operation{Key: key, SourceID: src.ID, AddressID: address, Kind: kind, OwnerKey: owner, Nonce: nonce, State: "reserved", CreatedAt: now, UpdatedAt: now, QueryOnly: true}, true, nil
}
func (s *Service) stage(ctx context.Context, op *Operation, from, to string, candidate *Candidate, code string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var result sql.Result
	if candidate != nil {
		result, err = tx.ExecContext(ctx, `UPDATE space.address_operations SET state=$4,candidate_email=$5,candidate_id=nullif($6,''),error_code=$7,updated_at=greatest(updated_at+1,$8) WHERE operation_key=$1 AND owner_key=$2 AND nonce=$3 AND state=$9`, op.Key, op.OwnerKey, op.Nonce, to, candidate.Address, candidate.ID, code, s.clock(), from)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE space.address_operations SET state=$4,error_code=$5,updated_at=greatest(updated_at+1,$6) WHERE operation_key=$1 AND owner_key=$2 AND nonce=$3 AND state=$7`, op.Key, op.OwnerKey, op.Nonce, to, code, s.clock(), from)
	}
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if err = commit(tx); err != nil {
		return err
	}
	op.State = to
	op.ErrorCode = code
	if candidate != nil {
		op.CandidateAddress = &candidate.Address
		if candidate.ID != "" {
			op.CandidateID = &candidate.ID
		}
	}
	return nil
}
func validHMEInput(in HMECreateInput) bool {
	return in.SourceID > 0 && operationKey(in.RequestKey) && in.ExpectedRevision > 0 && text(in.Label, 512, false) && validID(in.GroupID) && text(in.OwnerKey, 256, true) && (in.CredentialProfile == "api_key_only" || in.CredentialProfile == "mailbox")
}

// CreateHME owns the only generate/reserve path. Every external attempt is
// preceded by a durable state whose recovery is query-only, including crashes
// between that state and the network write. Conservative unknown is deliberate.
func (s *Service) CreateHME(ctx context.Context, in HMECreateInput, p Provider) (result Operation, resultErr error) {
	if !validHMEInput(in) || p == nil {
		return Operation{}, &FieldError{"hme_create"}
	}
	in.Label = strings.TrimSpace(in.Label)
	if existing, r, e := s.operation(ctx, in.RequestKey, "create", in.OwnerKey); e == nil {
		groupMatches := r.GroupID == nil && in.GroupID == nil || r.GroupID != nil && in.GroupID != nil && *r.GroupID == *in.GroupID
		if r.Version != 1 || existing.SourceID != in.SourceID || r.SourceRevision != in.ExpectedRevision || r.Label != in.Label || !groupMatches || r.Profile != in.CredentialProfile {
			return Operation{}, ErrConflict
		}
		return existing, nil
	} else if e != ErrNotFound {
		return Operation{}, e
	}
	ctx, release, err := s.enter(ctx, in.SourceID)
	if err != nil {
		return Operation{}, err
	}
	defer release()
	tx, err := s.begin(ctx)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	src, err := readSource(ctx, tx, in.SourceID)
	if err != nil {
		return Operation{}, err
	}
	if src.Kind == "custom" || !src.Enabled || src.Subject == "" {
		return Operation{}, ErrIneligible
	}
	forward, err := expectedForward(src)
	if err != nil {
		return Operation{}, ErrDirectory
	}
	request := operationRequest{Version: 1, SourceRevision: in.ExpectedRevision, PrincipalRevision: src.PrincipalRevision, SourceGeneration: src.Generation, Label: in.Label, GroupID: in.GroupID, Forward: forward, Profile: in.CredentialProfile}
	op, fresh, err := s.claim(ctx, tx, src, in.RequestKey, "create", in.OwnerKey, nil, request)
	if err != nil {
		return Operation{}, err
	}
	if !fresh {
		return op, nil
	}
	if src.Revision != in.ExpectedRevision {
		return Operation{}, ErrConflict
	}
	if err = lockGroup(ctx, tx, in.GroupID); err != nil {
		return Operation{}, err
	}
	if err = s.capacity(ctx, tx, src, 1); err != nil {
		return Operation{}, err
	}
	if err = commit(tx); err != nil {
		return op, err
	}
	p, closeProvider, err := openCreation(ctx, p)
	if err != nil {
		return s.failedPreflight(ctx, op, err)
	}
	defer func() {
		if e := closeProvider(); e != nil {
			resultErr = errors.Join(resultErr, e)
		}
	}()
	if err = s.creationPreflight(ctx, &op, src, p); err != nil {
		return s.failedPreflight(ctx, op, err)
	}
	if err = s.stage(ctx, &op, "reserved", "candidate_unknown", nil, ""); err != nil {
		return op, err
	}
	candidate, err := p.Generate(ctx)
	if err != nil {
		return s.providerFailure(ctx, op, err)
	}
	candidate.Address, err = NormalizeAddress(candidate.Address)
	if err != nil {
		return op, ErrProvider
	}
	if err = s.stage(ctx, &op, "candidate_unknown", "candidate_known", &candidate, ""); err != nil {
		return op, err
	}
	if err = s.stage(ctx, &op, "candidate_known", "confirming", nil, ""); err != nil {
		return op, err
	}
	if err = p.Reserve(ctx, candidate, in.Label, op.Nonce); err != nil {
		return s.providerFailure(ctx, op, err)
	}
	return s.confirmCreate(ctx, op, request, p)
}
func (s *Service) QueryCreate(ctx context.Context, sourceID int64, key, owner string, p Provider) (Operation, error) {
	if sourceID < 1 || !operationKey(key) || !text(owner, 256, true) || p == nil {
		return Operation{}, &FieldError{"hme_query"}
	}
	ctx, release, err := s.enter(ctx, sourceID)
	if err != nil {
		return Operation{}, err
	}
	defer release()
	op, request, err := s.operation(ctx, key, "create", owner)
	if err != nil {
		return op, err
	}
	if op.SourceID != sourceID {
		return Operation{}, ErrConflict
	}
	retired, err := s.sourceRetired(ctx, sourceID)
	if err != nil {
		return op, err
	}
	if retired {
		return op, nil
	}
	if request.Version == 1 && op.State == "reserved" && op.ErrorCode == forwardingUnknown {
		return s.queryForwarding(ctx, op, request, p)
	}
	if request.Version != 1 || op.State == "confirmed" || op.State == "failed" || op.CandidateAddress == nil {
		return op, nil
	}
	return s.confirmCreate(ctx, op, request, p)
}
func (s *Service) checkedDirectory(ctx context.Context, src source, p Provider) (Directory, error) {
	directory, err := p.Directory(ctx)
	if err != nil {
		return Directory{}, fmt.Errorf("%w: %w", ErrProvider, err)
	}
	forward, err := expectedForward(src)
	if err != nil {
		return Directory{}, ErrDirectory
	}
	return ValidateDirectory(directory, src.Subject, forward)
}
func sameSource(src source, r operationRequest) bool {
	return src.Revision == r.SourceRevision && src.PrincipalRevision == r.PrincipalRevision && src.Generation == r.SourceGeneration && src.Subject != ""
}
func (s *Service) confirmCreate(ctx context.Context, op Operation, r operationRequest, p Provider) (Operation, error) {
	// Read identity before the network call, then lock and compare again before
	// using its observation. The source lease spans both checks and provider IO.
	tx, err := s.begin(ctx)
	if err != nil {
		return op, err
	}
	src, err := readSource(ctx, tx, op.SourceID)
	tx.Rollback()
	if err != nil {
		return op, err
	}
	if !sameSource(src, r) {
		return op, ErrConflict
	}
	directory, err := s.checkedDirectory(ctx, src, p)
	if err != nil {
		return op, err
	}
	var found *RemoteAddress
	for i := range directory.Entries {
		x := &directory.Entries[i]
		if x.Address == *op.CandidateAddress {
			if op.CandidateID != nil && x.ID != *op.CandidateID {
				return op, ErrDirectory
			}
			if !x.Active || x.Forward != r.Forward {
				return op, ErrIneligible
			}
			found = x
			break
		}
	}
	if found == nil {
		return op, nil
	}
	issuance, err := s.beginIssue(ctx)
	if err != nil {
		return op, err
	}
	defer issuance.Close()
	tx, err = s.begin(ctx)
	if err != nil {
		return op, err
	}
	defer tx.Rollback()
	src, err = readSource(ctx, tx, op.SourceID)
	if err != nil {
		return op, err
	}
	if !sameSource(src, r) {
		return op, ErrConflict
	}
	if err = lockGroup(ctx, tx, r.GroupID); err != nil {
		return op, err
	}
	current, _, _, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM space.address_operations WHERE operation_key=$1 FOR UPDATE`, op.Key))
	if err != nil {
		return op, err
	}
	if current.State == "confirmed" {
		return current, nil
	}
	if current.Nonce != op.Nonce || current.CandidateAddress == nil || *current.CandidateAddress != found.Address {
		return op, ErrConflict
	}
	a, e := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.normalized_email=$1 FOR UPDATE`, found.Address))
	if e == ErrNotFound {
		if e = s.capacityExcept(ctx, tx, src, 1, op.Key); e != nil {
			return op, e
		}
		a, e = s.insert(ctx, tx, issuance.Stage, src, CreateInput{Address: found.Address, Label: r.Label, GroupID: r.GroupID, Enabled: true, OwnerKey: op.OwnerKey, CredentialProfile: r.Profile}, "apple", found)
	} else if e == nil && (a.SourceID != src.ID || a.Kind != "apple" || a.DeletedAt != nil || a.Lifecycle != "confirmed" || a.ProviderID == nil || *a.ProviderID != found.ID || a.ProviderOwner == nil || *a.ProviderOwner != src.Subject) {
		e = ErrConflict
	}
	if e != nil {
		return op, e
	}
	_, err = tx.ExecContext(ctx, `UPDATE space.address_operations SET address_id=$2,candidate_id=$3,state='confirmed',error_code='',updated_at=greatest(updated_at+1,$4) WHERE operation_key=$1`, op.Key, a.ID, found.ID, s.clock())
	if err != nil {
		return op, err
	}
	if err = commit(tx); err != nil {
		return op, err
	}
	op.AddressID = &a.ID
	op.CandidateID = &found.ID
	op.State = "confirmed"
	return op, nil
}

func (s *Service) DeleteHME(ctx context.Context, in HMEDeleteInput, p Provider) (Operation, error) {
	if in.AddressID < 1 || !operationKey(in.RequestKey) || in.ExpectedRevision < 1 || !text(in.OwnerKey, 256, true) || p == nil {
		return Operation{}, &FieldError{"hme_delete"}
	}
	// Existing durable requests remain queryable after the address tombstone.
	if existing, r, e := s.operation(ctx, in.RequestKey, "delete", in.OwnerKey); e == nil {
		if r.AddressID != in.AddressID || r.AddressRevision != in.ExpectedRevision || r.ConfirmAddress != in.ConfirmAddress {
			return Operation{}, ErrConflict
		}
		return existing, nil
	} else if e != ErrNotFound {
		return Operation{}, e
	}
	a, err := s.Get(ctx, in.AddressID)
	if err != nil {
		return Operation{}, err
	}
	ctx, release, err := s.enter(ctx, a.SourceID)
	if err != nil {
		return Operation{}, err
	}
	defer release()
	tx, err := s.begin(ctx)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	src, err := readSource(ctx, tx, a.SourceID)
	if err != nil {
		return Operation{}, err
	}
	a, err = scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1 AND a.deleted_at IS NULL FOR UPDATE`, in.AddressID))
	if err != nil {
		return Operation{}, err
	}
	if a.Revision != in.ExpectedRevision || a.Address != in.ConfirmAddress {
		return Operation{}, ErrConflict
	}
	if a.Kind != "apple" || a.Lifecycle != "confirmed" || a.ProviderID == nil || a.ProviderOwner == nil || *a.ProviderOwner != src.Subject {
		return Operation{}, ErrIneligible
	}
	forward, err := expectedForward(src)
	if err != nil {
		return Operation{}, ErrDirectory
	}
	r := operationRequest{Version: 1, SourceRevision: src.Revision, PrincipalRevision: src.PrincipalRevision, SourceGeneration: src.Generation, Forward: forward, AddressID: a.ID, AddressRevision: in.ExpectedRevision, ConfirmAddress: a.Address}
	op, fresh, err := s.claim(ctx, tx, src, in.RequestKey, "delete", in.OwnerKey, &a.ID, r)
	if err != nil {
		return Operation{}, err
	}
	if !fresh {
		return op, nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.private_addresses SET lifecycle='deletion_pending',enabled=false,revision=revision+1,updated_at=greatest(updated_at+1,$2) WHERE id=$1`, a.ID, s.clock()); err != nil {
		return Operation{}, err
	}
	if err = commit(tx); err != nil {
		return op, err
	}
	directory, err := s.checkedDirectory(ctx, src, p)
	if err != nil {
		return op, err
	}
	var remote *RemoteAddress
	for i := range directory.Entries {
		x := &directory.Entries[i]
		if x.ID == *a.ProviderID && x.Address == a.Address && x.Forward == forward {
			remote = x
			break
		}
	}
	if remote == nil {
		return op, ErrDirectory
	}
	if remote.Active {
		if err = s.stage(ctx, &op, "reserved", "deactivate_unknown", nil, ""); err != nil {
			return op, err
		}
		if err = p.Deactivate(ctx, remote.ID); err != nil {
			return s.providerFailure(ctx, op, err)
		}
		if err = s.stage(ctx, &op, "deactivate_unknown", "deactivated", nil, ""); err != nil {
			return op, err
		}
	} else {
		if err = s.stage(ctx, &op, "reserved", "deactivated", nil, ""); err != nil {
			return op, err
		}
	}
	if err = s.stage(ctx, &op, "deactivated", "delete_unknown", nil, ""); err != nil {
		return op, err
	}
	if err = p.Delete(ctx, remote.ID); err != nil {
		return s.providerFailure(ctx, op, err)
	}
	return s.confirmDelete(ctx, op, r, p)
}
func (s *Service) QueryDelete(ctx context.Context, addressID int64, key, owner string, p Provider) (Operation, error) {
	if addressID < 1 || !operationKey(key) || !text(owner, 256, true) || p == nil {
		return Operation{}, &FieldError{"hme_query"}
	}
	op, r, err := s.operation(ctx, key, "delete", owner)
	if err != nil {
		return op, err
	}
	if op.AddressID == nil || *op.AddressID != addressID {
		return Operation{}, ErrConflict
	}
	if r.Version != 1 || op.State == "confirmed" || op.State == "failed" {
		return op, nil
	}
	ctx, release, err := s.enter(ctx, op.SourceID)
	if err != nil {
		return op, err
	}
	defer release()
	// The writer may have finished while this query waited for the source.
	// Re-read its durable stage before deciding whether any readback is needed.
	op, r, err = s.operation(ctx, key, "delete", owner)
	if err != nil {
		return op, err
	}
	if op.State == "confirmed" || op.State == "failed" {
		return op, nil
	}
	retired, err := s.sourceRetired(ctx, op.SourceID)
	if err != nil {
		return op, err
	}
	if retired {
		return op, nil
	}
	return s.confirmDelete(ctx, op, r, p)
}
func (s *Service) confirmDelete(ctx context.Context, op Operation, r operationRequest, p Provider) (Operation, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return op, err
	}
	src, err := readSource(ctx, tx, op.SourceID)
	tx.Rollback()
	if err != nil {
		return op, err
	}
	if !sameSource(src, r) {
		return op, ErrConflict
	}
	directory, err := s.checkedDirectory(ctx, src, p)
	if err != nil {
		return op, err
	}
	// Absence after only a deactivate/reserved state does not prove this delete
	// chain ran. Such an operation stays unknown even if another actor deleted.
	if op.State != "delete_unknown" {
		return op, nil
	}
	for _, x := range directory.Entries {
		if x.Address == r.ConfirmAddress {
			return op, nil
		}
	}
	tx, err = s.begin(ctx)
	if err != nil {
		return op, err
	}
	defer tx.Rollback()
	src, err = readSource(ctx, tx, op.SourceID)
	if err != nil {
		return op, err
	}
	if !sameSource(src, r) {
		return op, ErrConflict
	}
	current, _, _, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM space.address_operations WHERE operation_key=$1 FOR UPDATE`, op.Key))
	if err != nil {
		return op, err
	}
	if current.State == "confirmed" {
		return current, nil
	}
	if current.State != "delete_unknown" || current.Nonce != op.Nonce {
		return op, ErrConflict
	}
	a, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1 FOR UPDATE`, r.AddressID))
	if err != nil {
		return op, err
	}
	if a.Address != r.ConfirmAddress || a.SourceID != op.SourceID || a.Lifecycle != "deletion_pending" {
		return op, ErrConflict
	}
	for _, x := range directory.Entries {
		if a.ProviderID != nil && x.ID == *a.ProviderID {
			return op, ErrDirectory
		}
	}
	// A confirmed remote disappearance remains visible as an archived address.
	// Only an explicit local purge may hide that retained administrative notice.
	if _, err = tx.ExecContext(ctx, `UPDATE space.private_addresses SET lifecycle='archived',enabled=false,archived_at=coalesce(archived_at,$2),archive_reason='remote_missing',provider_active=false,revision=revision+1,updated_at=greatest(updated_at+1,$2) WHERE id=$1`, a.ID, s.clock()); err != nil {
		return op, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.address_operations SET state='confirmed',updated_at=greatest(updated_at+1,$2) WHERE operation_key=$1`, op.Key, s.clock()); err != nil {
		return op, err
	}
	if err = commit(tx); err != nil {
		return op, err
	}
	op.State = "confirmed"
	return op, nil
}

func (s *Service) providerFailure(ctx context.Context, op Operation, cause error) (Operation, error) {
	wrapped := fmt.Errorf("%w: %w", ErrProvider, cause)
	var refusal ProviderRejection
	if !errors.As(cause, &refusal) || !refusal.DefinitiveRejection() {
		return op, wrapped
	}
	// Keep a complete remote verdict even if the browser stops reading. This
	// bounded local write holds the original source lease and makes no new call.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	code := refusal.FailureCode()
	if !text(code, 64, true) {
		code = "provider_rejected"
	}
	// A rejected deletion restores only local eligibility for a later explicit
	// command. It never re-enables the address or undoes a successful deactivate.
	tx, err := s.begin(ctx)
	if err != nil {
		return op, errors.Join(wrapped, err)
	}
	defer tx.Rollback()
	if _, err = readSource(ctx, tx, op.SourceID); err != nil {
		return op, errors.Join(wrapped, err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE space.address_operations SET state='failed',error_code=$5,updated_at=greatest(updated_at+1,$6) WHERE operation_key=$1 AND owner_key=$2 AND nonce=$3 AND state=$4`, op.Key, op.OwnerKey, op.Nonce, op.State, code, s.clock())
	if err != nil {
		return op, errors.Join(wrapped, err)
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return op, errors.Join(wrapped, ErrConflict)
	}
	if op.Kind == "delete" && op.AddressID != nil {
		result, err = tx.ExecContext(ctx, `UPDATE space.private_addresses SET lifecycle='confirmed',enabled=false,revision=revision+1,updated_at=greatest(updated_at+1,$3) WHERE id=$1 AND source_id=$2 AND lifecycle='deletion_pending' AND deleted_at IS NULL`, *op.AddressID, op.SourceID, s.clock())
		if err != nil {
			return op, errors.Join(wrapped, err)
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return op, errors.Join(wrapped, ErrConflict)
		}
	}
	if err = commit(tx); err != nil {
		return op, errors.Join(wrapped, err)
	}
	op.State = "failed"
	op.ErrorCode = code
	return op, wrapped
}
