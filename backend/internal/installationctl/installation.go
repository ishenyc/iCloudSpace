package installationctl

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"icloudspace/internal/adminauth"
	"icloudspace/internal/installation"
	"icloudspace/internal/installationresources"
	"icloudspace/internal/operationlog"
	"icloudspace/internal/pgschema"
)

const initializeAction = "installation.initialized"
const writesAction = "installation.writes_changed"

func Initialize(ctx context.Context, specFile string) (Result, error) {
	spec, err := readSpec(specFile)
	if err != nil {
		return Result{}, err
	}
	password, err := privateFile(spec.PasswordFile, adminauth.MaxLoginPasswordBytes)
	if err != nil {
		return Result{}, err
	}
	defer clear(password)
	if len(password) < adminauth.MinNewPasswordBytes || len(password) > adminauth.MaxNewPasswordBytes {
		return Result{}, ErrPassword
	}
	o, err := open(ctx, spec.ProcessFile, false)
	if err != nil {
		return Result{}, err
	}
	defer o.close()
	if o.database != spec.ExpectedDatabase {
		return Result{}, ErrBinding
	}
	return initializeOpened(ctx, o, spec, password)
}
func initializeOpened(ctx context.Context, o *opened, spec Spec, password []byte) (Result, error) {
	result := Result{Operation: "initialize", State: "not_initialized"}
	settings, err := spec.settings(o.process)
	if err != nil {
		return result, err
	}
	if installationresources.ValidateResources(o.process, settings) != nil {
		return result, ErrResources
	}
	manifest, err := json.Marshal(struct {
		Process  installation.Process
		Settings installation.Settings
		Database string
		Login    string
		Password []byte
	}{o.process, settings, spec.ExpectedDatabase, spec.OperatorLogin, password})
	if err != nil {
		return result, ErrInput
	}
	result.OperationDigest = keyed(o.key, "initialization-spec", manifest)
	clear(manifest)
	schema, err := pgschema.Inspect(ctx, o.db)
	if err != nil {
		return result, ErrState
	}
	if schema.State != pgschema.Empty && schema.State != pgschema.Ready {
		return result, ErrState
	}
	if schema.State == pgschema.Empty {
		entries, err := os.ReadDir(o.process.BlobDirectory)
		if err != nil {
			return result, ErrPrivate
		}
		for _, entry := range entries {
			if entry.Name() != ".process-lock" {
				return result, ErrState
			}
		}
	}
	guard, err := acquire(ctx, o, schema.State == pgschema.Empty)
	if err != nil {
		return result, err
	}
	defer guard.close()
	schema, err = pgschema.InspectSettled(ctx, o.db)
	if err != nil {
		return result, ErrState
	}
	if schema.State == pgschema.Ready {
		actual, err := installation.ReadSettings(ctx, o.db, o.process.InstallationID, o.box)
		if err != nil {
			return result, ErrBinding
		}
		currentRevision, currentWrites := actual.Revision, actual.WritesEnabled
		actual.Revision = 1
		actual.WritesEnabled = false
		if actual != settings {
			return result, ErrConflict
		}
		var id int64
		var encoding string
		if o.db.QueryRowContext(ctx, `SELECT id,password_encoding FROM space.operators WHERE login_name=$1 AND enabled`, spec.OperatorLogin).Scan(&id, &encoding) != nil || bcrypt.CompareHashAndPassword([]byte(encoding), password) != nil {
			return result, ErrConflict
		}
		result.State = "already_initialized"
		result.OperatorID = decimal(id)
		result.CurrentRevision = decimal(currentRevision)
		result.CurrentWritesEnabled = boolRef(currentWrites)
		original, originalID, receiptErr := genesisReceipt(ctx, o)
		if receiptErr == nil {
			result.OperationDigest, result.OperatorID = original, decimal(originalID)
		} else if errors.Is(receiptErr, ErrNotFound) {
			result.State, result.OperationDigest = "bound_existing", ""
		} else {
			return result, receiptErr
		}
		return result, nil
	}
	if schema.State != pgschema.Empty {
		return result, ErrState
	}
	encoding, err := bcrypt.GenerateFromPassword(password, adminauth.PasswordCost)
	if err != nil {
		return result, ErrPassword
	}
	defer clear(encoding)
	var operatorID int64
	created, err := pgschema.InitializeAtomic(ctx, o.db, func(ctx context.Context, tx *sql.Tx) error {
		var now int64
		if tx.QueryRowContext(ctx, `SELECT space.clock_ns()`).Scan(&now) != nil || now <= 0 {
			return ErrDatabase
		}
		proof, e := o.box.Fingerprint(o.process.InstallationID)
		if e != nil {
			return ErrBinding
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO space.installation(installation_id,management_path,configuration_revision,created_at,writes_enabled) VALUES($1,$2,1,$3,false)`, settings.ID, settings.ManagementPath, now); e != nil {
			return ErrDatabase
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO space.key_binding(binding_version,key_id,proof,created_at) VALUES(1,'installation-master',$1,$2)`, proof[:], now); e != nil {
			return ErrDatabase
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO space.installation_settings(http_address,imaps_address,public_host,tls_certificate_ref,tls_private_key_ref,archive_capacity_bytes,sync_concurrency,sync_rest_milliseconds,allow_weak_recipient_evidence,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, settings.HTTPAddress, settings.IMAPSAddress, settings.PublicHost, settings.TLSCertificate, settings.TLSPrivateKey, settings.ArchiveCapacityBytes, settings.SyncConcurrency, int64(settings.SyncRest/time.Millisecond), settings.AllowWeakRecipientEvidence, now); e != nil {
			return ErrDatabase
		}
		if tx.QueryRowContext(ctx, `INSERT INTO space.operators(login_name,password_encoding,session_epoch,enabled,created_at,updated_at) VALUES($1,$2,1,true,$3,$3) RETURNING id`, spec.OperatorLogin, string(encoding), now).Scan(&operatorID) != nil {
			return ErrDatabase
		}
		return operationlog.RecordAuditTx(ctx, tx, operationlog.Record{OccurredAt: now, ActorKind: "system", ActorRef: "installationctl", Action: initializeAction, ResourceKind: "installation", ResourceRef: installationRef(o), Outcome: "success", CorrelationKey: result.OperationDigest, Origin: "offline_cli", Fields: map[string]string{"component": "installationctl", "operation_kind": "initialize", "scope": "v1:" + result.OperationDigest + ":" + decimal(operatorID)}})
	})
	if errors.Is(err, pgschema.ErrCommitUnknown) {
		result.State = "unknown"
		return result, ErrUnknown
	}
	if err != nil {
		return result, ErrDatabase
	}
	if !created {
		return result, ErrConflict
	}
	result.State = "initialized"
	result.OperatorID = decimal(operatorID)
	result.ResultRevision = "1"
	result.ResultEnabled = boolRef(false)
	return result, nil
}

// Inspect proves only the original bound SQL installation. It performs no
// resource repair and remains useful if a certificate or web asset is damaged.
func Inspect(ctx context.Context, processFile string) (Result, error) {
	o, err := open(ctx, processFile, true)
	if err != nil {
		return Result{}, err
	}
	defer o.close()
	guard, err := acquire(ctx, o, false)
	if err != nil {
		return Result{}, err
	}
	defer guard.close()
	result := Result{Operation: "inspect", State: "uninitialized"}
	schema, err := pgschema.InspectSettled(ctx, o.db)
	if err != nil {
		return result, ErrState
	}
	if schema.State == pgschema.Empty {
		return result, nil
	}
	if schema.State != pgschema.Ready {
		return result, ErrState
	}
	revision, writes, err := boundInstallation(ctx, o)
	if err != nil {
		return result, ErrBinding
	}
	var settingsCount int
	if o.db.QueryRowContext(ctx, `SELECT count(*) FROM space.installation_settings`).Scan(&settingsCount) != nil || settingsCount != 1 {
		return result, ErrState
	}
	id, err := enabledOperator(ctx, o.db)
	if err != nil {
		return result, ErrState
	}
	result.State = "bound_existing"
	digest, originalID, receiptErr := genesisReceipt(ctx, o)
	if receiptErr == nil {
		result.State = "initialized"
		result.OperationDigest = digest
		id = originalID
	} else if !errors.Is(receiptErr, ErrNotFound) {
		return result, receiptErr
	}
	result.OperatorID = decimal(id)
	result.CurrentRevision = decimal(revision)
	result.CurrentWritesEnabled = boolRef(writes)
	return result, nil
}

func SetWrites(ctx context.Context, processFile string, enabled bool, expectedRevision, operationKey string) (Result, error) {
	return setBooleanSetting(ctx, processFile, enabled, expectedRevision, operationKey, "set_writes")
}

// SetWeakRecipientEvidence is an explicit offline change. Omitted initialization
// and public HTTP settings keep their original false/default or existing value.
func SetWeakRecipientEvidence(ctx context.Context, processFile string, enabled bool, expectedRevision, operationKey string) (Result, error) {
	return setBooleanSetting(ctx, processFile, enabled, expectedRevision, operationKey, "set_weak_recipient_evidence")
}

func setBooleanSetting(ctx context.Context, processFile string, enabled bool, expectedRevision, operationKey, kind string) (Result, error) {
	expected, err := positive(expectedRevision)
	if err != nil || !validOperationKey(operationKey) {
		return Result{}, ErrInput
	}
	o, err := open(ctx, processFile, false)
	if err != nil {
		return Result{}, err
	}
	defer o.close()
	guard, err := acquire(ctx, o, false)
	if err != nil {
		return Result{}, err
	}
	defer guard.close()
	_, _, err = boundInstallation(ctx, o)
	if err != nil {
		return Result{}, ErrBinding
	}
	result := Result{Operation: kind, State: "not_changed", OperationDigest: settingDigest(o, operationKey, kind), ExpectedRevision: expectedRevision}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return result, ErrDatabase
	}
	defer tx.Rollback()
	revision, err := lockBinding(ctx, tx, o)
	if err != nil {
		return result, err
	}
	if previous, err := settingReceipt(ctx, tx, o, result.OperationDigest, kind); err == nil {
		if previous.ExpectedRevision != expectedRevision || previous.ResultEnabled == nil || *previous.ResultEnabled != enabled {
			return result, ErrConflict
		}
		previous.Operation = kind
		previous.State = "already_committed"
		return previous, nil
	} else if !errors.Is(err, ErrNotFound) {
		return result, err
	}
	if revision != expected || revision == math.MaxInt64 {
		return result, ErrConflict
	}
	if kind == "set_writes" && enabled {
		settings, err := installation.ReadSettings(ctx, o.db, o.process.InstallationID, o.box)
		if err != nil || installationresources.ValidateResources(o.process, settings) != nil {
			return result, ErrResources
		}
		if _, err := enabledOperator(ctx, tx); err != nil {
			return result, ErrState
		}
	}
	var now int64
	if tx.QueryRowContext(ctx, `SELECT space.clock_ns()`).Scan(&now) != nil || now <= 0 {
		return result, ErrDatabase
	}
	var updated sql.Result
	if kind == "set_writes" {
		updated, err = tx.ExecContext(ctx, `UPDATE space.installation SET writes_enabled=$1,configuration_revision=$2 WHERE singleton AND configuration_revision=$3`, enabled, revision+1, expected)
	} else {
		var writes bool
		if tx.QueryRowContext(ctx, `SELECT writes_enabled FROM space.installation WHERE singleton`).Scan(&writes) != nil {
			return result, ErrDatabase
		}
		if writes {
			return result, ErrState
		}
		changed, e := tx.ExecContext(ctx, `UPDATE space.installation_settings SET allow_weak_recipient_evidence=$1,updated_at=$2 WHERE singleton`, enabled, now)
		if e != nil {
			return result, ErrDatabase
		}
		if n, e := changed.RowsAffected(); e != nil || n != 1 {
			return result, ErrBinding
		}
		updated, err = tx.ExecContext(ctx, `UPDATE space.installation SET configuration_revision=$1 WHERE singleton AND configuration_revision=$2`, revision+1, expected)
	}
	if err != nil {
		return result, ErrDatabase
	}
	if n, e := updated.RowsAffected(); e != nil || n != 1 {
		return result, ErrConflict
	}
	scope := "v1:" + expectedRevision + ":" + decimal(revision+1) + ":" + strconvBool(enabled)
	if operationlog.RecordAuditTx(ctx, tx, operationlog.Record{OccurredAt: now, ActorKind: "system", ActorRef: "installationctl", Action: settingAction(kind), ResourceKind: "installation", ResourceRef: installationRef(o), Outcome: "success", CorrelationKey: result.OperationDigest, Origin: "offline_cli", Fields: map[string]string{"component": "installationctl", "operation_kind": kind, "scope": scope}}) != nil {
		return result, ErrDatabase
	}
	if tx.Commit() != nil {
		result.State = "unknown"
		return result, ErrUnknown
	}
	result.State = "committed"
	result.ResultRevision = decimal(revision + 1)
	result.ResultEnabled = boolRef(enabled)
	return result, nil
}

func QueryWriteChange(ctx context.Context, processFile, operationKey string) (Result, error) {
	return querySettingChange(ctx, processFile, operationKey, "set_writes", "query_write_change")
}

func QueryWeakRecipientChange(ctx context.Context, processFile, operationKey string) (Result, error) {
	return querySettingChange(ctx, processFile, operationKey, "set_weak_recipient_evidence", "query_weak_recipient_change")
}

func querySettingChange(ctx context.Context, processFile, operationKey, kind, queryKind string) (Result, error) {
	if !validOperationKey(operationKey) {
		return Result{}, ErrInput
	}
	o, err := open(ctx, processFile, false)
	if err != nil {
		return Result{}, err
	}
	defer o.close()
	guard, err := acquire(ctx, o, false)
	if err != nil {
		return Result{}, err
	}
	defer guard.close()
	if _, _, err = boundInstallation(ctx, o); err != nil {
		return Result{}, ErrBinding
	}
	result := Result{Operation: queryKind, State: "not_recorded", OperationDigest: settingDigest(o, operationKey, kind)}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return result, ErrDatabase
	}
	defer tx.Rollback()
	if _, err = lockBinding(ctx, tx, o); err != nil {
		return result, err
	}
	original, err := settingReceipt(ctx, tx, o, result.OperationDigest, kind)
	if err != nil {
		return result, err
	}
	original.Operation = queryKind
	return original, nil
}
func lockBinding(ctx context.Context, tx *sql.Tx, o *opened) (int64, error) {
	var id string
	var proof []byte
	var revision int64
	if tx.QueryRowContext(ctx, `SELECT i.installation_id,i.configuration_revision,k.proof FROM space.installation i JOIN space.key_binding k USING(singleton) WHERE i.singleton AND k.binding_version=1 FOR UPDATE OF i FOR SHARE OF k`).Scan(&id, &revision, &proof) != nil {
		return 0, ErrBinding
	}
	want, err := o.box.Fingerprint(o.process.InstallationID)
	if err != nil || id != o.process.InstallationID || subtle.ConstantTimeCompare(proof, want[:]) != 1 {
		return 0, ErrBinding
	}
	return revision, nil
}
func genesisReceipt(ctx context.Context, o *opened) (string, int64, error) {
	rows, err := o.db.QueryContext(ctx, `SELECT correlation_key,CASE WHEN octet_length(detail)<=4096 THEN detail END FROM space.audit_records WHERE action=$1 AND actor_kind='system' AND actor_ref='installationctl' AND resource_kind='installation' AND resource_ref=$2 AND origin='offline_cli' AND outcome='success' ORDER BY id LIMIT 2`, initializeAction, installationRef(o))
	if err != nil {
		return "", 0, ErrDatabase
	}
	var digest string
	var detail sql.NullString
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&digest, &detail) != nil {
			rows.Close()
			return "", 0, ErrDatabase
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", 0, ErrDatabase
	}
	if count == 0 {
		return "", 0, ErrNotFound
	}
	if count != 1 || !detail.Valid || len(digest) != 64 || !oneObject([]byte(detail.String)) {
		return "", 0, ErrConflict
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
		return "", 0, ErrConflict
	}
	var fields struct {
		Component string `json:"component"`
		Kind      string `json:"operation_kind"`
		Scope     string `json:"scope"`
	}
	decoder := json.NewDecoder(strings.NewReader(detail.String))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fields) != nil || decoder.Decode(new(any)) != io.EOF || fields.Component != "installationctl" || fields.Kind != "initialize" {
		return "", 0, ErrConflict
	}
	parts := strings.Split(fields.Scope, ":")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] != digest {
		return "", 0, ErrConflict
	}
	id, err := positive(parts[2])
	if err != nil {
		return "", 0, ErrConflict
	}
	var exists bool
	if o.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.operators WHERE id=$1)`, id).Scan(&exists) != nil || !exists {
		return "", 0, ErrState
	}
	return digest, id, nil
}
func boundInstallation(ctx context.Context, o *opened) (int64, bool, error) {
	if pgschema.Check(ctx, o.db) != nil {
		return 0, false, ErrBinding
	}
	var id string
	var proof []byte
	var revision int64
	var writes bool
	if o.db.QueryRowContext(ctx, `SELECT i.installation_id,i.configuration_revision,i.writes_enabled,k.proof FROM space.installation i JOIN space.key_binding k USING(singleton) WHERE i.singleton AND k.binding_version=1`).Scan(&id, &revision, &writes, &proof) != nil {
		return 0, false, ErrBinding
	}
	want, err := o.box.Fingerprint(o.process.InstallationID)
	if err != nil || id != o.process.InstallationID || revision < 1 || subtle.ConstantTimeCompare(proof, want[:]) != 1 {
		return 0, false, ErrBinding
	}
	return revision, writes, nil
}

type operatorReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func enabledOperator(ctx context.Context, reader operatorReader) (int64, error) {
	var id int64
	var encoding string
	if reader.QueryRowContext(ctx, `SELECT id,password_encoding FROM space.operators WHERE enabled ORDER BY id LIMIT 1`).Scan(&id, &encoding) != nil || id < 1 {
		return 0, ErrState
	}
	if _, err := bcrypt.Cost([]byte(encoding)); err != nil {
		return 0, ErrState
	}
	return id, nil
}
func settingReceipt(ctx context.Context, tx *sql.Tx, o *opened, digest, kind string) (Result, error) {
	result := Result{State: "committed", OperationDigest: digest}
	rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN octet_length(detail)<=4096 THEN detail END FROM space.audit_records WHERE action=$1 AND actor_kind='system' AND actor_ref='installationctl' AND resource_kind='installation' AND resource_ref=$2 AND correlation_key=$3 AND origin='offline_cli' AND outcome='success' ORDER BY id LIMIT 2`, settingAction(kind), installationRef(o), digest)
	if err != nil {
		return result, ErrDatabase
	}
	defer rows.Close()
	count := 0
	var raw sql.NullString
	for rows.Next() {
		count++
		if rows.Scan(&raw) != nil {
			return result, ErrDatabase
		}
	}
	if rows.Err() != nil {
		return result, ErrDatabase
	}
	if count == 0 {
		return result, ErrNotFound
	}
	if count != 1 || !raw.Valid || !oneObject([]byte(raw.String)) {
		return result, ErrConflict
	}
	var detail struct {
		Component string `json:"component"`
		Kind      string `json:"operation_kind"`
		Scope     string `json:"scope"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw.String))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&detail) != nil || decoder.Decode(new(any)) != io.EOF || detail.Component != "installationctl" || detail.Kind != kind {
		return result, ErrConflict
	}
	parts := strings.Split(detail.Scope, ":")
	if len(parts) != 4 || parts[0] != "v1" {
		return result, ErrConflict
	}
	expected, err := positive(parts[1])
	if err != nil || expected == math.MaxInt64 {
		return result, ErrConflict
	}
	next, err := positive(parts[2])
	if err != nil || next != expected+1 || parts[3] != "true" && parts[3] != "false" {
		return result, ErrConflict
	}
	result.ExpectedRevision = parts[1]
	result.ResultRevision = parts[2]
	result.ResultEnabled = boolRef(parts[3] == "true")
	return result, nil
}
func keyed(key []byte, domain string, value []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("iCloudSpace/installationctl/" + domain + "/v1\x00"))
	h.Write(value)
	return hex.EncodeToString(h.Sum(nil))
}
func installationRef(o *opened) string {
	sum := sha256.Sum256([]byte(o.process.InstallationID))
	return hex.EncodeToString(sum[:])
}
func writeDigest(o *opened, key string) string {
	return keyed(o.key, "write-change", []byte(o.process.InstallationID+"\x00"+key))
}
func settingDigest(o *opened, key, kind string) string {
	if kind == "set_writes" {
		return writeDigest(o, key)
	}
	return keyed(o.key, kind, []byte(o.process.InstallationID+"\x00"+key))
}
func settingAction(kind string) string {
	if kind == "set_writes" {
		return writesAction
	}
	return "installation.weak_recipient_evidence.changed"
}
func strconvBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
