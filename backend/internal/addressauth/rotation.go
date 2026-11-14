package addressauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"

	"icloudspace/internal/operationlog"
	"icloudspace/internal/sourceguard"
)

type RotationRequest struct {
	OperationKey, OwnerKey        string
	AddressID, ExpectedGeneration int64
	ExpectedScopeDigest           string
}
type RotationItem struct {
	SourceID            int64  `json:"source_id"`
	AddressID           int64  `json:"address_id"`
	PreviousGeneration  int64  `json:"previous_generation"`
	Generation          int64  `json:"generation"`
	DeliveryKey         string `json:"delivery_key"`
	PreviousUIDValidity int64  `json:"previous_uid_validity"`
	UIDValidity         int64  `json:"uid_validity"`
	Upgraded            bool   `json:"upgraded"`
}
type RotationResult struct {
	OperationKey string         `json:"operation_key"`
	Kind         string         `json:"kind"`
	State        string         `json:"state"`
	ScopeDigest  string         `json:"scope_digest"`
	Items        []RotationItem `json:"items"`
}
type rotationPlan struct {
	Version int            `json:"version"`
	Items   []RotationItem `json:"items"`
}

func (a *Authority) RotateKey(ctx context.Context, r RotationRequest) (RotationResult, error) {
	return a.rotate(ctx, "api_key", r, nil)
}
func (a *Authority) RotateBundle(ctx context.Context, r RotationRequest) (RotationResult, error) {
	return a.rotate(ctx, "bundle", r, nil)
}

// Fresh authorization is invoked only after source guards and the exclusive
// revocation barrier have been acquired. The application root supplies its
// management-session/password check; transport cannot pre-authorize the wait.
func (a *Authority) RotateAll(ctx context.Context, r RotationRequest, fresh func(context.Context, *sql.Tx) error) (RotationResult, error) {
	return a.rotate(ctx, "all", r, fresh)
}

func (a *Authority) rotate(ctx context.Context, kind string, r RotationRequest, fresh func(context.Context, *sql.Tx) error) (RotationResult, error) {
	if a == nil || !validKey(r.OperationKey) || !validKey(r.OwnerKey) {
		return RotationResult{}, ErrInvalid
	}
	if kind == "all" {
		decoded, e := hex.DecodeString(r.ExpectedScopeDigest)
		if e != nil || len(decoded) != 32 || r.ExpectedScopeDigest != strings.ToLower(r.ExpectedScopeDigest) || r.AddressID != 0 || r.ExpectedGeneration != 0 || fresh == nil {
			return RotationResult{}, ErrInvalid
		}
	} else if r.AddressID < 1 || r.ExpectedGeneration < 1 {
		return RotationResult{}, ErrInvalid
	}
	if kind == "api_key" {
		decoded, e := hex.DecodeString(r.ExpectedScopeDigest)
		if e != nil || len(decoded) != 32 {
			return RotationResult{}, ErrInvalid
		}
	}
	requestBytes, _ := json.Marshal(struct {
		Kind    string
		Request RotationRequest
	}{kind, r})
	requestDigest := sha256.Sum256(requestBytes)
	if existing, e := a.lookupRotation(ctx, r.OperationKey, requestDigest[:]); e == nil {
		if existing.State == "committed" {
			return existing, nil
		}
		return existing, ErrOutcomeUnknown
	} else if !errors.Is(e, sql.ErrNoRows) {
		return RotationResult{}, e
	}
	ids, e := a.rotationSources(ctx, r.AddressID)
	if e != nil {
		return RotationResult{}, e
	}
	var guards []*sourceguard.Lease
	defer func() {
		for i := len(guards) - 1; i >= 0; i-- {
			guards[i].Close()
		}
	}()
	for _, id := range ids {
		guard, e := a.guards.Acquire(ctx, id)
		if e != nil {
			return RotationResult{}, e
		}
		guards = append(guards, guard)
	}
	release, e := a.gate.write(ctx)
	if e != nil {
		return RotationResult{}, e
	}
	defer release()
	if !a.readReady() {
		return RotationResult{}, ErrOutcomeUnknown
	}
	if kind != "all" {
		if e = sourceguard.CheckLocalMutation(ctx); e != nil {
			return RotationResult{}, e
		}
	}
	// Another same-key request may have completed while this caller waited
	// for source guards/read leases. Reconcile again before testing stale CAS.
	if existing, e := a.lookupRotation(ctx, r.OperationKey, requestDigest[:]); e == nil {
		if existing.State == "committed" {
			return existing, nil
		}
		return existing, ErrOutcomeUnknown
	} else if !errors.Is(e, sql.ErrNoRows) {
		return RotationResult{}, e
	}
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return RotationResult{}, storageError(ctx)
	}
	defer tx.Rollback()
	if e = a.checkWritable(ctx, tx); e != nil {
		return RotationResult{}, e
	}
	now := a.clock()
	snapshot, e := readScope(ctx, tx, r.AddressID, now, true)
	if e != nil {
		return RotationResult{}, e
	}
	if len(snapshot.Sources) != len(ids) {
		return RotationResult{}, ErrConflict
	}
	for i, s := range snapshot.Sources {
		if s.ID != ids[i] {
			return RotationResult{}, ErrConflict
		}
	}
	digest := scopeDigest(snapshot)
	if kind == "all" {
		if digest != r.ExpectedScopeDigest {
			return RotationResult{}, ErrConflict
		}
	} else if len(snapshot.Addresses) != 1 || snapshot.Addresses[0].Generation != r.ExpectedGeneration {
		return RotationResult{}, ErrConflict
	}
	if kind != "all" && r.ExpectedScopeDigest != "" && digest != r.ExpectedScopeDigest {
		return RotationResult{}, ErrConflict
	}
	if kind != "all" && (snapshot.Addresses[0].Lifecycle != "confirmed" || snapshot.Addresses[0].Deleted.Valid) {
		return RotationResult{}, ErrConflict
	}
	if kind == "bundle" {
		if _, e = a.completeBundle(ctx, tx, snapshot.Addresses[0], now); e != nil {
			return RotationResult{}, e
		}
	}
	plan := rotationPlan{Version: 1}
	for _, address := range snapshot.Addresses {
		if kind == "all" && address.Deleted.Valid {
			continue
		}
		if kind != "api_key" && address.Generation == math.MaxInt64 {
			return RotationResult{}, ErrConflict
		}
		generation := address.Generation
		if kind != "api_key" {
			generation++
		}
		uidValidity := address.UIDValidity
		upgrade := kind == "all" && !address.Mailbox
		if upgrade {
			uidValidity, e = newUIDValidity(address.UIDValidity)
			if e != nil {
				return RotationResult{}, e
			}
		}
		plan.Items = append(plan.Items, RotationItem{SourceID: address.SourceID, AddressID: address.ID, PreviousGeneration: address.Generation, Generation: generation, PreviousUIDValidity: address.UIDValidity, UIDValidity: uidValidity, Upgraded: upgrade})
	}
	encoded, _ := json.Marshal(plan)
	scopeBytes, _ := hex.DecodeString(digest)
	var source, address any
	if r.AddressID != 0 {
		source = snapshot.Addresses[0].SourceID
		address = r.AddressID
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO space.credential_rotations(operation_key,kind,source_id,address_id,request_digest,scope_digest,plan,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,'prepared',$8)`, r.OperationKey, kind, source, address, requestDigest[:], scopeBytes, encoded, now)
	if e != nil {
		return RotationResult{}, ErrConflict
	}
	// The nonsecret prepared receipt is durable before generating any replacement
	// secret. A retry encountering it requires query/cancel, never auto replay.
	if a.commit(tx) != nil {
		return RotationResult{OperationKey: r.OperationKey, Kind: kind, State: "unknown", ScopeDigest: digest}, ErrOutcomeUnknown
	}
	tx, e = a.db.BeginTx(ctx, nil)
	if e != nil {
		return RotationResult{}, storageError(ctx)
	}
	defer tx.Rollback()
	if e = a.checkWritable(ctx, tx); e != nil {
		return RotationResult{}, e
	}
	var encodedState string
	if e = tx.QueryRowContext(ctx, `SELECT state FROM space.credential_rotations WHERE operation_key=$1 FOR UPDATE`, r.OperationKey).Scan(&encodedState); e != nil {
		return RotationResult{}, storageError(ctx)
	}
	if encodedState != "prepared" {
		return RotationResult{}, ErrConflict
	}
	if kind == "all" {
		if e = fresh(ctx, tx); e != nil {
			return RotationResult{}, e
		}
	}
	snapshot, e = readScope(ctx, tx, r.AddressID, a.clock(), true)
	if e != nil {
		return RotationResult{}, e
	}
	if scopeDigest(snapshot) != digest {
		return RotationResult{}, ErrConflict
	}
	result := RotationResult{OperationKey: r.OperationKey, Kind: kind, State: "committed", ScopeDigest: digest}
	now = a.clock()
	for _, item := range plan.Items {
		delivery, e := a.rotateAddress(ctx, tx, kind, r.OwnerKey, item, snapshot.Grants, now)
		if e != nil {
			return RotationResult{}, e
		}
		item.DeliveryKey = delivery
		result.Items = append(result.Items, item)
	}
	encoded, e = json.Marshal(result)
	if e != nil {
		return RotationResult{}, ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `UPDATE space.credential_rotations SET state='committed',result=$2::jsonb,committed_at=$3 WHERE operation_key=$1 AND state='prepared'`, r.OperationKey, encoded, now); e != nil {
		return RotationResult{}, storageError(ctx)
	}
	// Full rotation already records its audit in the caller's fresh-authorization
	// callback, in this same transaction. Do not duplicate it here.
	if kind != "all" {
		sourceID := snapshot.Addresses[0].SourceID
		if e = operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: now, Action: "credentials.rotate_" + kind, ResourceKind: "address", ResourceRef: strconv.FormatInt(r.AddressID, 10), Outcome: "success", SourceID: &sourceID, CorrelationKey: rotationAuditReference(r.OperationKey), Fields: map[string]string{"operation_kind": kind}})); e != nil {
			return RotationResult{}, storageError(ctx)
		}
	}
	a.uncertain.Store(r.OperationKey, true)
	if a.commit(tx) != nil {
		return RotationResult{OperationKey: r.OperationKey, Kind: kind, State: "unknown", ScopeDigest: digest}, ErrOutcomeUnknown
	}
	a.uncertain.Delete(r.OperationKey)
	return result, nil
}

func (a *Authority) rotationSources(ctx context.Context, address int64) ([]int64, error) {
	rows, e := a.db.QueryContext(ctx, `SELECT id FROM space.mail_sources WHERE ($1::bigint=0 OR id=(SELECT source_id FROM space.private_addresses WHERE id=$1)) ORDER BY id`, address)
	if e != nil {
		return nil, storageError(ctx)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) != nil {
			return nil, ErrStorage
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil {
		return nil, storageError(ctx)
	}
	if address != 0 && len(ids) != 1 {
		return nil, ErrConflict
	}
	return ids, nil
}

func (a *Authority) rotateAddress(ctx context.Context, tx *sql.Tx, kind, ownerKey string, item RotationItem, all []grantFact, now int64) (string, error) {
	var envelope []byte
	var bundleGeneration int64
	var old Bundle
	e := tx.QueryRowContext(ctx, `SELECT bundle_envelope,auth_generation FROM space.address_credential_bundles WHERE source_id=$1 AND address_id=$2 FOR UPDATE`, item.SourceID, item.AddressID).Scan(&envelope, &bundleGeneration)
	hasBundle := e == nil
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return "", storageError(ctx)
	}
	if hasBundle {
		if bundleGeneration != item.PreviousGeneration {
			return "", ErrConflict
		}
		old, e = OpenBundle(a.box, Owner{InstallationID: a.installationID, AddressID: item.AddressID, Generation: bundleGeneration}, envelope)
		if e != nil {
			return "", ErrCredentials
		}
	}
	replacement, e := Generate()
	if e != nil {
		return "", e
	}
	if kind == "api_key" && hasBundle {
		old.API = replacement.API
		replacement = old
	}
	if kind != "api_key" || hasBundle {
		envelope, e = SealBundle(a.box, Owner{InstallationID: a.installationID, AddressID: item.AddressID, Generation: item.Generation}, replacement)
		if e != nil {
			return "", e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO space.address_credential_bundles(address_id,source_id,bundle_envelope,bundle_version,auth_generation,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(address_id) DO UPDATE SET bundle_envelope=excluded.bundle_envelope,bundle_version=excluded.bundle_version,auth_generation=excluded.auth_generation,updated_at=excluded.updated_at`, item.AddressID, item.SourceID, envelope, DocumentVersion, item.Generation, now); e != nil {
			return "", storageError(ctx)
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE space.address_grants SET revoked_at=COALESCE(revoked_at,$3) WHERE source_id=$1 AND address_id=$2 AND auth_generation=$4 AND ($5::boolean OR authenticator_kind='api_key')`, item.SourceID, item.AddressID, now, item.PreviousGeneration, kind != "api_key"); e != nil {
		return "", storageError(ctx)
	}
	if _, e = tx.ExecContext(ctx, `UPDATE space.private_addresses SET auth_generation=$3,updated_at=$4,uid_validity=$6 WHERE source_id=$1 AND id=$2 AND auth_generation=$5`, item.SourceID, item.AddressID, item.Generation, now, item.PreviousGeneration, item.UIDValidity); e != nil {
		return "", storageError(ctx)
	}
	if kind == "all" {
		for _, g := range modernGrants(replacement) {
			hash := Hash(g.raw)
			if e = insertGrant(ctx, tx, item.SourceID, item.AddressID, item.Generation, g.purpose, g.kind, hash[:], now, nil); e != nil {
				return "", e
			}
		}
		return a.stagePending(ctx, tx, item.SourceID, item.AddressID, item.Generation, replacement.API.Key, ownerKey, now)
	}
	hashes := map[string][32]byte{"api_key": Hash(replacement.API.Key), "imap_password": Hash(replacement.IMAP.Password), "client_id": Hash(replacement.OAuth.ClientID), "refresh_token": Hash(replacement.OAuth.RefreshToken)}
	// A purpose's replacement has the union of its prior effective expiry
	// windows. Multiple old key hashes never create a new purpose. Unbounded
	// wins only where that same purpose already had an unbounded active grant.
	facts := make(map[string]grantFact)
	for _, g := range all {
		if g.AddressID != item.AddressID {
			continue
		}
		if kind == "api_key" && g.Kind != "api_key" {
			continue
		}
		key := g.Kind + "/" + g.Purpose
		if previous, ok := facts[key]; ok {
			if !previous.Expires.Valid {
				continue
			}
			if g.Expires.Valid && g.Expires.Int64 < previous.Expires.Int64 {
				continue
			}
		}
		facts[key] = g
	}
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		g := facts[key]
		hash := g.Hash
		if kind != "api_key" || g.Kind == "api_key" {
			v := hashes[g.Kind]
			hash = v[:]
		}
		var expires *int64
		if g.Expires.Valid {
			v := g.Expires.Int64
			expires = &v
		}
		if e = insertGrant(ctx, tx, item.SourceID, item.AddressID, item.Generation, g.Purpose, g.Kind, hash, now, expires); e != nil {
			return "", e
		}
	}
	return a.stagePending(ctx, tx, item.SourceID, item.AddressID, item.Generation, replacement.API.Key, ownerKey, now)
}

func newUIDValidity(previous int64) (int64, error) {
	for {
		var b [4]byte
		if _, e := rand.Read(b[:]); e != nil {
			return 0, ErrStorage
		}
		v := int64(binary.BigEndian.Uint32(b[:]))
		if v > 0 && v != previous {
			return v, nil
		}
	}
}

// QueryRotation locks the durable receipt in an independent transaction. It
// waits for an in-flight mutation's commit/rollback before reporting its state.
func (a *Authority) QueryRotation(ctx context.Context, key string) (RotationResult, error) {
	if a == nil || !validKey(key) {
		return RotationResult{}, ErrInvalid
	}
	return a.lookupRotation(ctx, key, nil)
}
func (a *Authority) lookupRotation(ctx context.Context, key string, expected []byte) (RotationResult, error) {
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return RotationResult{}, storageError(ctx)
	}
	defer tx.Rollback()
	var state, kind string
	var digest, request, result []byte
	e = tx.QueryRowContext(ctx, `SELECT kind,state,scope_digest,request_digest,result FROM space.credential_rotations WHERE operation_key=$1 FOR SHARE`, key).Scan(&kind, &state, &digest, &request, &result)
	if errors.Is(e, sql.ErrNoRows) {
		return RotationResult{}, sql.ErrNoRows
	}
	if e != nil {
		return RotationResult{}, storageError(ctx)
	}
	if expected != nil && !equalBytes(expected, request) {
		return RotationResult{}, ErrConflict
	}
	r := RotationResult{OperationKey: key, Kind: kind, State: state, ScopeDigest: hex.EncodeToString(digest)}
	if state == "committed" && json.Unmarshal(result, &r) != nil {
		return RotationResult{}, ErrStorage
	}
	if tx.Commit() != nil {
		return RotationResult{}, storageError(ctx)
	}
	a.uncertain.Delete(key)
	return r, nil
}
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// Rotation keys predate the metadata grammar. Keep their command/query bytes
// unchanged, while using a stable audit-only reference when projection requires it.
func rotationAuditReference(key string) string {
	valid := key != "" && len(key) <= 128
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c)) {
			valid = false
			break
		}
	}
	for _, word := range []string{"password", "secret", "authorization", "bearer", "cookie", "csrf", "access_token", "refresh_token", "session_token", "private_key"} {
		if strings.Contains(strings.ToLower(key), word) {
			valid = false
			break
		}
	}
	if valid {
		return key
	}
	digest := sha256.Sum256([]byte(key))
	return "rotation:" + hex.EncodeToString(digest[:])
}

// CancelRotation is explicit reconciliation of a prepared local intent. Since
// its row lock waits for the atomic mutation, it cannot cancel committed work.
func (a *Authority) CancelRotation(ctx context.Context, key string) (RotationResult, error) {
	if a == nil || !validKey(key) {
		return RotationResult{}, ErrInvalid
	}
	release, e := a.gate.write(ctx)
	if e != nil {
		return RotationResult{}, e
	}
	defer release()
	if e = sourceguard.CheckLocalMutation(ctx); e != nil {
		return RotationResult{}, e
	}
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return RotationResult{}, storageError(ctx)
	}
	defer tx.Rollback()
	if e = a.checkWritable(ctx, tx); e != nil {
		return RotationResult{}, e
	}
	var state string
	var source sql.NullInt64
	if e = tx.QueryRowContext(ctx, `SELECT state,source_id FROM space.credential_rotations WHERE operation_key=$1 FOR UPDATE`, key).Scan(&state, &source); e != nil {
		return RotationResult{}, storageError(ctx)
	}
	if state == "prepared" {
		now := a.clock()
		if _, e = tx.ExecContext(ctx, `UPDATE space.credential_rotations SET state='cancelled',cancelled_at=$2 WHERE operation_key=$1`, key, now); e != nil {
			return RotationResult{}, storageError(ctx)
		}
		var sourceID *int64
		if source.Valid {
			sourceID = &source.Int64
		}
		reference := rotationAuditReference(key)
		if e = operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: now, Action: "credentials.rotation_cancelled", ResourceKind: "credential_rotation", ResourceRef: reference, Outcome: "success", SourceID: sourceID, CorrelationKey: reference})); e != nil {
			return RotationResult{}, storageError(ctx)
		}
	}
	if a.commit(tx) != nil {
		return RotationResult{}, ErrOutcomeUnknown
	}
	return a.QueryRotation(ctx, key)
}
