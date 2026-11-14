package accounts

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"icloudspace/internal/operationlog"
)

func (s *Service) Create(ctx context.Context, input CreateInput) (Metadata, error) {
	input, err := normalizeInput(input)
	if err != nil {
		return Metadata{}, err
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return Metadata{}, err
	}
	defer tx.Rollback()
	now := s.clock()
	item := Metadata{Kind: input.Kind, DisplayName: input.DisplayName, AddressNamespace: input.AddressNamespace,
		Endpoint: input.Endpoint, AddressSuffix: input.AddressSuffix, Enabled: input.Enabled,
		Revision: 1, SourceGeneration: 1, CredentialGeneration: 1, CreatedAt: now, UpdatedAt: now}
	if err = tx.QueryRowContext(ctx, `SELECT nextval(pg_get_serial_sequence('space.mail_sources','id'))`).Scan(&item.ID); err != nil {
		return Metadata{}, err
	}
	envelope, err := s.seal(item, input.Credentials)
	if err != nil {
		return Metadata{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO space.mail_sources
(id,kind,display_name,address_namespace,imap_host,imap_port,imap_username,credentials_envelope,
address_suffix,enabled,revision,source_generation,credential_generation,created_at,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,1,1,$11,$11)`,
		item.ID, string(item.Kind), item.DisplayName, item.AddressNamespace, item.Endpoint.Host, item.Endpoint.Port,
		item.Endpoint.Username, envelope, item.AddressSuffix, item.Enabled, now)
	if err != nil {
		return Metadata{}, classify(err)
	}
	if input.Apple != nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO space.apple_principals(source_id,apple_id,region,revision) VALUES($1,$2,$3,1)`,
			item.ID, input.Apple.AppleID, input.Apple.Region)
		if err != nil {
			return Metadata{}, classify(err)
		}
		item.Apple = &ApplePrincipal{AppleID: input.Apple.AppleID, Region: input.Apple.Region, Revision: 1}
	}
	if err = auditAccountTx(ctx, tx, item.ID, now, "account.created"); err != nil {
		return Metadata{}, err
	}
	if err = tx.Commit(); err != nil {
		// Preserve the allocated ID even when the acknowledgement is lost. The
		// caller must query this identity; it must not create another source.
		return item, ErrCommitUnknown
	}
	return item, nil
}

func (s *Service) Patch(ctx context.Context, id, expectedRevision int64, patch Patch) (Change, error) {
	if id < 1 || expectedRevision < 1 {
		return Change{}, &FieldError{"id_or_revision"}
	}
	lease, err := s.guards.Acquire(ctx, id)
	if err != nil {
		return Change{}, err
	}
	defer lease.Close()
	if _, pending := s.uncertain.Load(id); pending {
		return Change{}, ErrConflict
	}
	// Decide whether this is a source replacement before taking row locks.
	// Existing consume/read leases may themselves need the source row; waiting
	// for the Authority barrier from inside that transaction would deadlock.
	previous, encrypted, err := scanSource(s.db.QueryRowContext(ctx,
		`SELECT `+metadataColumns+`,s.credentials_envelope`+sourceJoin+`WHERE s.id=$1`, id), true)
	if err != nil {
		return Change{}, classify(err)
	}
	if previous.Revision != expectedRevision {
		return Change{}, ErrConflict
	}
	credentials, err := s.open(previous, encrypted)
	if err != nil {
		return Change{}, err
	}
	input := inputFrom(previous, credentials)
	applyPatch(&input, patch)
	input, err = normalizeInput(input)
	if err != nil {
		return Change{}, err
	}
	principalChanged := !samePrincipal(previous.Apple, input.Apple)
	identityChanged := input.Kind != previous.Kind || input.AddressNamespace != previous.AddressNamespace ||
		input.AddressSuffix != previous.AddressSuffix || principalChanged
	sourceChanged := identityChanged || input.Endpoint != previous.Endpoint
	credentialChanged := credentials != input.Credentials
	result := Change{Source: previous, SourceChanged: sourceChanged, CredentialsChanged: credentialChanged,
		PreviousSourceGeneration: previous.SourceGeneration}
	if sourceChanged && !patch.RequireSourceChange {
		return Change{}, ErrSourceChangeRequired
	}
	var scope SourceChangeScope
	if sourceChanged {
		if s.sourceFence.Begin == nil {
			return Change{}, ErrSourceChangeFence
		}
		scope, err = s.sourceFence.Begin(ctx, lease)
		if err != nil {
			return Change{}, err
		}
		if scope == nil {
			return Change{}, ErrSourceChangeFence
		}
		defer scope.Close()
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return Change{}, err
	}
	defer tx.Rollback()
	locked, _, err := scanSource(tx.QueryRowContext(ctx,
		`SELECT `+metadataColumns+sourceJoin+`WHERE s.id=$1 FOR UPDATE OF s`, id), false)
	if err != nil {
		return Change{}, classify(err)
	}
	if locked.Revision != expectedRevision || locked.SourceGeneration != previous.SourceGeneration || locked.CredentialGeneration != previous.CredentialGeneration {
		return Change{}, ErrConflict
	}
	if identityChanged {
		var hasAddresses bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.private_addresses WHERE source_id=$1)`, id).Scan(&hasAddresses); err != nil {
			return Change{}, err
		}
		if hasAddresses {
			return Change{}, ErrIdentityLocked
		}
	}
	if !sourceChanged && !credentialChanged && previous.DisplayName == input.DisplayName && previous.Enabled == input.Enabled {
		return result, nil
	}
	next := previous
	next.Kind, next.DisplayName, next.AddressNamespace = input.Kind, input.DisplayName, input.AddressNamespace
	next.Endpoint, next.AddressSuffix, next.Enabled = input.Endpoint, input.AddressSuffix, input.Enabled
	if next.Revision, err = nextRevision(previous.Revision); err != nil {
		return Change{}, err
	}
	if next.UpdatedAt, err = nextInstant(s.clock(), previous.UpdatedAt); err != nil {
		return Change{}, err
	}
	if sourceChanged {
		if next.SourceGeneration, err = nextRevision(previous.SourceGeneration); err != nil {
			return Change{}, err
		}
	}
	if credentialChanged {
		if next.CredentialGeneration, err = nextRevision(previous.CredentialGeneration); err != nil {
			return Change{}, err
		}
	}
	if principalChanged {
		if err = changePrincipal(ctx, tx, &next, input.Apple); err != nil {
			return Change{}, err
		}
	}
	envelope, err := s.seal(next, input.Credentials)
	if err != nil {
		return Change{}, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE space.mail_sources SET kind=$3,display_name=$4,address_namespace=$5,
imap_host=$6,imap_port=$7,imap_username=$8,credentials_envelope=$9,address_suffix=$10,enabled=$11,
revision=$12,source_generation=$13,credential_generation=$14,updated_at=$15 WHERE id=$1 AND revision=$2`,
		id, expectedRevision, string(next.Kind), next.DisplayName, next.AddressNamespace,
		next.Endpoint.Host, next.Endpoint.Port, next.Endpoint.Username, envelope, next.AddressSuffix,
		next.Enabled, next.Revision, next.SourceGeneration, next.CredentialGeneration, next.UpdatedAt)
	if err != nil {
		return Change{}, classify(err)
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return Change{}, err
	}
	if count != 1 {
		return Change{}, ErrConflict
	}
	result.Source = next
	if err = auditAccountTx(ctx, tx, id, next.UpdatedAt, "account.updated"); err != nil {
		return Change{}, err
	}
	if err = tx.Commit(); err != nil {
		if scope != nil {
			scope.MarkUncertain()
			s.uncertain.Store(id, true)
			// A fresh conflicting lock proves the original backend finished.
			// Failure keeps Authority admission quarantined until explicit Get.
			settle, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if scope.Resolve(settle) == nil {
				s.uncertain.Delete(id)
			}
			cancel()
		}
		return result, ErrCommitUnknown
	}
	return result, nil
}

// SetEnabled uses the same source lock and revision CAS as every configuration
// change. Concurrent callers must reload state instead of bypassing a revision.
func (s *Service) SetEnabled(ctx context.Context, id, expectedRevision int64, enabled bool) (Change, error) {
	return s.Patch(ctx, id, expectedRevision, Patch{Enabled: &enabled})
}

func inputFrom(source Metadata, credentials Credentials) CreateInput {
	input := CreateInput{Kind: source.Kind, DisplayName: source.DisplayName, AddressNamespace: source.AddressNamespace,
		Endpoint: source.Endpoint, AddressSuffix: source.AddressSuffix, Enabled: source.Enabled, Credentials: credentials}
	if source.Apple != nil {
		input.Apple = &PrincipalInput{AppleID: source.Apple.AppleID, Region: source.Apple.Region}
	}
	return input
}

func applyPatch(input *CreateInput, patch Patch) {
	if patch.Kind != nil {
		input.Kind = *patch.Kind
		if input.Kind == Custom {
			input.Apple = nil
		}
	}
	if patch.DisplayName != nil {
		input.DisplayName = *patch.DisplayName
	}
	if patch.AddressNamespace != nil {
		input.AddressNamespace = *patch.AddressNamespace
	}
	if patch.Endpoint != nil {
		input.Endpoint = *patch.Endpoint
	}
	if patch.AddressSuffix != nil {
		input.AddressSuffix = *patch.AddressSuffix
	}
	if patch.Enabled != nil {
		input.Enabled = *patch.Enabled
	}
	if patch.Credentials != nil {
		input.Credentials = *patch.Credentials
	}
	if patch.Apple != nil {
		principal := *patch.Apple
		input.Apple = &principal
	}
}

func samePrincipal(previous *ApplePrincipal, next *PrincipalInput) bool {
	if previous == nil || next == nil {
		return previous == nil && next == nil
	}
	return previous.AppleID == next.AppleID && previous.Region == next.Region
}

func changePrincipal(ctx context.Context, tx *sql.Tx, source *Metadata, next *PrincipalInput) error {
	// Identity replacement invalidates sessions/challenges in this transaction.
	// A provider owner must also bind its writes to the principal revision.
	if source.Apple != nil {
		var revision int64
		if err := tx.QueryRowContext(ctx, `SELECT revision FROM space.apple_principals WHERE source_id=$1 FOR UPDATE`, source.ID).Scan(&revision); err != nil {
			return classify(err)
		}
		if revision != source.Apple.Revision {
			return ErrConflict
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM space.apple_challenges WHERE source_id=$1`, source.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM space.apple_sessions WHERE source_id=$1`, source.ID); err != nil {
		return err
	}
	if next == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM space.apple_principals WHERE source_id=$1`, source.ID); err != nil {
			return err
		}
		source.Apple = nil
		return nil
	}
	if source.Apple == nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO space.apple_principals(source_id,apple_id,region,revision) VALUES($1,$2,$3,1)`,
			source.ID, next.AppleID, next.Region); err != nil {
			return classify(err)
		}
		source.Apple = &ApplePrincipal{AppleID: next.AppleID, Region: next.Region, Revision: 1}
		return nil
	}
	revision, err := nextRevision(source.Apple.Revision)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE space.apple_principals SET apple_id=$2,region=$3,dsid=NULL,revision=$4 WHERE source_id=$1 AND revision=$5`,
		source.ID, next.AppleID, next.Region, revision, source.Apple.Revision)
	if err != nil {
		return classify(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	source.Apple = &ApplePrincipal{AppleID: next.AppleID, Region: next.Region, Revision: revision}
	return nil
}

// Delete removes only an empty source. A populated source requires the separate
// deletion owner and archive recovery protocol. OperationKey correlates this
// attempt; it is not a durable idempotency claim. On ErrCommitUnknown, Get(id)
// determines whether the source remains; the caller must not replay blindly.
func (s *Service) Delete(ctx context.Context, id, expectedRevision int64, operationKey string) (DeleteResult, error) {
	if id < 1 || expectedRevision < 1 || !boundedText(operationKey, 128, true) {
		return DeleteResult{}, &FieldError{"delete_identity"}
	}
	result := DeleteResult{OperationKey: operationKey, SourceID: id}
	lease, err := s.guards.Acquire(ctx, id)
	if err != nil {
		return result, err
	}
	defer lease.Close()
	if _, pending := s.uncertain.Load(id); pending {
		return result, ErrConflict
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var revision int64
	if err = tx.QueryRowContext(ctx, `SELECT revision FROM space.mail_sources WHERE id=$1 FOR UPDATE`, id).Scan(&revision); err != nil {
		return result, classify(err)
	}
	if revision != expectedRevision {
		return result, ErrConflict
	}
	// Apple session/challenge foreign keys target the principal, so lock that
	// parent as well before testing whether those dependent rows exist.
	if _, err = tx.ExecContext(ctx, `SELECT source_id FROM space.apple_principals WHERE source_id=$1 FOR UPDATE`, id); err != nil {
		return result, err
	}
	var dependent bool
	if err = tx.QueryRowContext(ctx, dependentStateSQL, id).Scan(&dependent); err != nil {
		return result, err
	}
	if dependent {
		return result, ErrDependentState
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM space.mail_sources WHERE id=$1 AND revision=$2`, id, expectedRevision); err != nil {
		return result, classify(err)
	}
	if err = auditAccountTx(ctx, tx, id, s.clock(), "account.deleted"); err != nil {
		return result, err
	}
	if err = tx.Commit(); err != nil {
		return result, ErrCommitUnknown
	}
	result.Deleted = true
	return result, nil
}

func auditAccountTx(ctx context.Context, tx *sql.Tx, source, now int64, action string) error {
	return operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: now, Action: action, ResourceKind: "source", ResourceRef: strconv.FormatInt(source, 10), Outcome: "success", SourceID: &source, Fields: map[string]string{"component": "accounts"}}))
}
