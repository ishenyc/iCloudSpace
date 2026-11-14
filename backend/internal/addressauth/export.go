package addressauth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5/pgtype"
	"icloudspace/internal/vault"
)

// Envelopes are opened and released one row at a time. A prepared batch retains
// only validated bundles (four secrets of at most 4096 bytes) and grant windows.
const ExportBatchSize = 1024
const exportEnvelopeBytes = vault.MaxEncodedEnvelopeBytes

type ExportAddress struct {
	SourceID, AddressID, Generation int64
	Address                         string
}
type ExportSelection interface {
	InstallationID() string
	Validate(context.Context, *sql.Tx) error
	Next(context.Context, *sql.Tx, int64, int) ([]ExportAddress, error)
}
type ExportCredential struct {
	ExportAddress
	API    *APIKeyMaterial
	Bundle *Bundle
}

func (ExportCredential) String() string   { return "addressauth: private export credential" }
func (ExportCredential) GoString() string { return "addressauth: private export credential" }

// Export owns one snapshot and one SQL connection. All row queries are bounded
// batches; emit must not acquire SQL. The RevealScope remains held by the HTTP
// owner through both audits and the complete response, including terminal IO.
func (s *RevealScope) Export(ctx context.Context, kind string, selection ExportSelection, emit func(ExportCredential) error) (uint64, error) {
	return s.export(ctx, kind, selection, emit, false)
}

// ExportForCopy retains the same snapshot and disclosure owner. Incomplete
// credential profiles are skipped in text copy formats; credential backup
// requires every selected credential.
func (s *RevealScope) ExportForCopy(ctx context.Context, kind string, selection ExportSelection, emit func(ExportCredential) error) (uint64, error) {
	return s.export(ctx, kind, selection, emit, true)
}

func (s *RevealScope) export(ctx context.Context, kind string, selection ExportSelection, emit func(ExportCredential) error, copyFormat bool) (uint64, error) {
	if s == nil || selection == nil || emit == nil || (kind != "api_key" && kind != "mailbox") {
		return 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || selection.InstallationID() != s.a.installationID || !s.a.readReady() {
		return 0, ErrInvalid
	}
	tx, err := s.a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return 0, storageError(ctx)
	}
	defer tx.Rollback()
	if err = selection.Validate(ctx, tx); err != nil {
		return 0, err
	}
	var count uint64
	var after int64
	for {
		if err = ctx.Err(); err != nil {
			return count, err
		}
		items, e := selection.Next(ctx, tx, after, ExportBatchSize)
		if e != nil {
			return count, e
		}
		if len(items) == 0 {
			break
		}
		if len(items) > ExportBatchSize {
			return count, ErrInvalid
		}
		for _, item := range items {
			if item.SourceID < 1 || item.Generation < 1 || item.AddressID <= after {
				return count, ErrInvalid
			}
			after = item.AddressID
		}
		batch, e := s.a.exportBatch(ctx, tx, items, kind)
		if e != nil {
			return count, e
		}
		var pending *exportPendingCursor
		for _, item := range items {
			if e = ctx.Err(); e != nil {
				break
			}
			state := batch[item.AddressID]
			now := s.a.clock()
			if state == nil || now < state.checkedAt {
				e = ErrUnavailable
				break
			}
			if copyFormat {
				if kind == "mailbox" && (state.bundle == nil || !state.roots["api_key"].live(now) || !state.roots["imap_password"].live(now) || !state.roots["client_id"].live(now) || !state.roots["refresh_token"].live(now)) {
					continue
				}
				if kind == "api_key" && !state.purposes[MailRead].live(now) {
					continue
				}
			}
			if state.documentErr != nil {
				e = state.documentErr
				break
			}
			record := ExportCredential{ExportAddress: item}
			if kind == "mailbox" {
				if state.bundle == nil {
					e = ErrUnavailable
					break
				}
				valid := true
				for _, k := range []string{"api_key", "imap_password", "client_id", "refresh_token"} {
					if !state.roots[k].live(now) {
						valid = false
						break
					}
				}
				if !valid {
					e = ErrUnavailable
					break
				}
				record.Bundle = state.bundle
			} else {
				if len(state.apiHash) != 32 || state.ambiguousAPI {
					e = ErrUnavailable
					break
				}
				purposes := []Purpose{}
				for purpose, window := range state.purposes {
					if window.live(now) {
						purposes = append(purposes, purpose)
					}
				}
				sort.Slice(purposes, func(i, j int) bool { return purposes[i] < purposes[j] })
				if len(purposes) == 0 {
					e = ErrUnavailable
					break
				}
				key := ""
				if state.bundle != nil {
					h := Hash(state.bundle.API.Key)
					if bytes.Equal(h[:], state.apiHash) {
						key = state.bundle.API.Key
					}
				}
				if key == "" {
					if pending == nil {
						pending, e = openExportPending(ctx, tx, items, item.AddressID)
						if e != nil {
							break
						}
					}
					key, e = pending.key(s.a, item, state.apiHash)
					if e != nil {
						break
					}
				}
				record.API = &APIKeyMaterial{Key: key, Purposes: purposes}
			}
			// Pending material may require SQL and decryption after row admission.
			// Recheck the same absolute grant windows at the disclosure boundary.
			emitNow := s.a.clock()
			if emitNow < now {
				e = ErrUnavailable
				break
			}
			if record.API != nil {
				live := record.API.Purposes[:0]
				for _, purpose := range record.API.Purposes {
					if state.purposes[purpose].live(emitNow) {
						live = append(live, purpose)
					}
				}
				record.API.Purposes = live
				if len(live) == 0 {
					e = ErrUnavailable
					break
				}
			} else {
				for _, kind := range []string{"api_key", "imap_password", "client_id", "refresh_token"} {
					if !state.roots[kind].live(emitNow) {
						e = ErrUnavailable
						break
					}
				}
				if e != nil {
					break
				}
			}
			if e = emit(record); e != nil {
				break
			}
			count++
		}
		if pending != nil {
			if closeErr := pending.close(); e == nil {
				e = closeErr
			}
		}
		if e != nil {
			return count, e
		}
		if len(items) < ExportBatchSize {
			break
		}
	}
	if tx.Commit() != nil {
		return count, storageError(ctx)
	}
	return count, nil
}

type exportWindow struct {
	present, infinite bool
	expires           int64
}

func (w exportWindow) live(now int64) bool { return w.present && (w.infinite || now < w.expires) }
func (w exportWindow) add(expires sql.NullInt64) exportWindow {
	first := !w.present
	w.present = true
	if !expires.Valid {
		w.infinite = true
	} else if first || expires.Int64 > w.expires {
		w.expires = expires.Int64
	}
	return w
}

type exportMaterial struct {
	checkedAt    int64
	bundle       *Bundle
	documentErr  error
	apiHash      []byte
	ambiguousAPI bool
	purposes     map[Purpose]exportWindow
	roots        map[string]exportWindow
	hashes       map[string][32]byte
}

func (a *Authority) exportBatch(ctx context.Context, tx *sql.Tx, items []ExportAddress, kind string) (map[int64]*exportMaterial, error) {
	if kind == "mailbox" {
		return a.exportMailboxBatch(ctx, tx, items)
	}
	ids := make([]int64, len(items))
	expected := map[int64]ExportAddress{}
	for i, item := range items {
		ids[i] = item.AddressID
		expected[item.AddressID] = item
	}
	raw, _ := json.Marshal(ids)
	now := a.clock()
	states := map[int64]*exportMaterial{}
	rows, e := tx.QueryContext(ctx, `SELECT a.source_id,a.id,a.auth_generation,a.email,a.lifecycle,a.deleted_at,substring(b.bundle_envelope FROM 1 FOR $2)
 FROM space.private_addresses a LEFT JOIN space.address_credential_bundles b ON b.source_id=a.source_id AND b.address_id=a.id AND b.auth_generation=a.auth_generation
 WHERE a.id IN(SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb)) ORDER BY a.id`, string(raw), exportEnvelopeBytes+1)
	if e != nil {
		return nil, storageError(ctx)
	}
	for rows.Next() {
		var actual ExportAddress
		var lifecycle string
		var deleted sql.NullInt64
		var envelope []byte
		if e = rows.Scan(&actual.SourceID, &actual.AddressID, &actual.Generation, &actual.Address, &lifecycle, &deleted, &envelope); e != nil {
			rows.Close()
			return nil, storageError(ctx)
		}
		if actual != expected[actual.AddressID] || lifecycle != "confirmed" || deleted.Valid {
			rows.Close()
			return nil, ErrUnavailable
		}
		state := a.exportBundle(actual, envelope, now)
		clear(envelope)
		states[actual.AddressID] = state
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, storageError(ctx)
	}
	if len(states) != len(items) {
		return nil, ErrUnavailable
	}
	rows, e = tx.QueryContext(ctx, exportGrantSQL, string(raw), now)
	if e != nil {
		return nil, storageError(ctx)
	}
	for rows.Next() {
		var id int64
		var kind string
		var hash []byte
		var purpose Purpose
		var root bool
		var expires sql.NullInt64
		if e = rows.Scan(&id, &kind, &hash, &purpose, &root, &expires); e != nil {
			rows.Close()
			return nil, storageError(ctx)
		}
		state := states[id]
		if state == nil || len(hash) != 32 {
			rows.Close()
			return nil, ErrUnavailable
		}
		if kind == "api_key" {
			if state.apiHash == nil {
				state.apiHash = append([]byte(nil), hash...)
			} else if !bytes.Equal(state.apiHash, hash) {
				state.ambiguousAPI = true
			}
			if bytes.Equal(state.apiHash, hash) {
				state.purposes[purpose] = state.purposes[purpose].add(expires)
			}
		}
		if want, ok := state.hashes[kind]; ok && root && bytes.Equal(want[:], hash) {
			state.roots[kind] = state.roots[kind].add(expires)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, storageError(ctx)
	}
	return states, nil
}

func (a *Authority) exportBundle(item ExportAddress, envelope []byte, now int64) *exportMaterial {
	state := &exportMaterial{checkedAt: now, purposes: map[Purpose]exportWindow{}, roots: map[string]exportWindow{}, hashes: map[string][32]byte{}}
	if len(envelope) > exportEnvelopeBytes {
		state.documentErr = ErrCredentials
	} else if len(envelope) > 0 {
		b, err := OpenBundle(a.box, Owner{InstallationID: a.installationID, AddressID: item.AddressID, Generation: item.Generation}, envelope)
		state.documentErr = err
		if err == nil {
			state.bundle = &b
			state.hashes["api_key"] = Hash(b.API.Key)
			state.hashes["imap_password"] = Hash(b.IMAP.Password)
			state.hashes["client_id"] = Hash(b.OAuth.ClientID)
			state.hashes["refresh_token"] = Hash(b.OAuth.RefreshToken)
		}
	}
	return state
}

// Mailbox export discloses a bundle only when all four matching root material
// kinds exist. Returning their windows with the address avoids six scalar
// grant rows per ordinary mailbox; API export still consumes the full forest.
func (a *Authority) exportMailboxBatch(ctx context.Context, tx *sql.Tx, items []ExportAddress) (map[int64]*exportMaterial, error) {
	ids := make([]int64, len(items))
	expected := make(map[int64]ExportAddress, len(items))
	for i, item := range items {
		ids[i] = item.AddressID
		expected[item.AddressID] = item
	}
	raw, _ := json.Marshal(ids)
	now := a.clock()
	rows, err := tx.QueryContext(ctx, exportMailboxSQL, string(raw), now, exportEnvelopeBytes+1)
	if err != nil {
		return nil, storageError(ctx)
	}
	defer rows.Close()
	states := make(map[int64]*exportMaterial, len(items))
	types := pgtype.NewMap()
	for rows.Next() {
		var actual ExportAddress
		var lifecycle string
		var deleted sql.NullInt64
		var envelope []byte
		var kindsWire, hashesWire, expiriesWire []byte
		var kinds []string
		var hashes [][]byte
		var expiries []pgtype.Int8
		if err = rows.Scan(&actual.SourceID, &actual.AddressID, &actual.Generation, &actual.Address, &lifecycle, &deleted, &envelope, &kindsWire, &hashesWire, &expiriesWire); err != nil {
			clear(envelope)
			return nil, storageError(ctx)
		}
		// array_send preserves PostgreSQL's standard binary array representation.
		// bytea results avoid stdlib's text-array and hexadecimal-hash round trip.
		if types.Scan(pgtype.TextArrayOID, pgtype.BinaryFormatCode, kindsWire, &kinds) != nil ||
			types.Scan(pgtype.ByteaArrayOID, pgtype.BinaryFormatCode, hashesWire, &hashes) != nil ||
			types.Scan(pgtype.Int8ArrayOID, pgtype.BinaryFormatCode, expiriesWire, &expiries) != nil {
			clear(envelope)
			return nil, storageError(ctx)
		}
		if actual != expected[actual.AddressID] || lifecycle != "confirmed" || deleted.Valid || len(kinds) != len(hashes) || len(kinds) != len(expiries) {
			clear(envelope)
			return nil, ErrUnavailable
		}
		state := a.exportBundle(actual, envelope, now)
		clear(envelope)
		for i, kind := range kinds {
			if want, ok := state.hashes[kind]; ok && bytes.Equal(want[:], hashes[i]) {
				state.roots[kind] = state.roots[kind].add(sql.NullInt64{Int64: expiries[i].Int64, Valid: expiries[i].Valid})
			}
		}
		states[actual.AddressID] = state
	}
	if rows.Err() != nil {
		return nil, storageError(ctx)
	}
	if len(states) != len(items) {
		return nil, ErrUnavailable
	}
	return states, nil
}

var exportMailboxSQL = `WITH selected_addresses AS MATERIALIZED (
 SELECT a.source_id,a.id,a.auth_generation,a.email,a.lifecycle,a.deleted_at,substring(b.bundle_envelope FROM 1 FOR $3) AS envelope
 FROM space.private_addresses a LEFT JOIN space.address_credential_bundles b ON b.source_id=a.source_id AND b.address_id=a.id AND b.auth_generation=a.auth_generation
 WHERE a.id IN(SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb))
),
 mailbox_roots AS (
 SELECT g.address_id,g.authenticator_kind,g.authenticator_hash,
 CASE WHEN bool_or(g.expires_at IS NULL) THEN NULL ELSE max(g.expires_at) END AS expires_at
 FROM space.address_grants g JOIN selected_addresses a ON a.source_id=g.source_id AND a.id=g.address_id
 WHERE g.parent_grant_id IS NULL AND a.lifecycle='confirmed' AND a.deleted_at IS NULL AND ` + currentGrantFactsSQL("$2") + ` AND (
 (g.authenticator_kind='api_key' AND g.purpose IN('latest_read','mail_read','mail_consume','raw_read')) OR (g.authenticator_kind='imap_password' AND g.purpose='imap_login') OR (g.authenticator_kind='client_id' AND g.purpose='oauth_client') OR (g.authenticator_kind='refresh_token' AND g.purpose='oauth_refresh'))
 GROUP BY g.address_id,g.authenticator_kind,g.authenticator_hash
 ),
 mailbox_material AS (
 SELECT address_id,array_agg(authenticator_kind) AS kinds,array_agg(authenticator_hash) AS hashes,array_agg(expires_at::bigint) AS expiries
 FROM mailbox_roots GROUP BY address_id
 )
 SELECT a.source_id,a.id,a.auth_generation,a.email,a.lifecycle,a.deleted_at,a.envelope,
 pg_catalog.array_send(m.kinds),pg_catalog.array_send(m.hashes),pg_catalog.array_send(m.expiries)
 FROM selected_addresses a LEFT JOIN mailbox_material m ON m.address_id=a.id ORDER BY a.id`

// Use the same rooted forest as metadata, with the authority's explicit clock.
// Parent expiry is folded down each path and checked again before every emit.
var exportGrantSQL = `WITH RECURSIVE selected_addresses AS MATERIALIZED (
 SELECT a.source_id,a.id,a.auth_generation,a.lifecycle,a.deleted_at FROM space.private_addresses a
 WHERE a.id IN(SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb))
),` + currentGrantSetSQL("$2") + `
SELECT g.address_id,g.authenticator_kind,g.authenticator_hash,g.purpose,g.parent_grant_id IS NULL,g.expires_at FROM current_grants g
 WHERE (g.authenticator_kind='api_key' AND g.purpose IN('latest_read','mail_read','mail_consume','raw_read')) OR (g.authenticator_kind='imap_password' AND g.purpose='imap_login') OR (g.authenticator_kind='client_id' AND g.purpose='oauth_client') OR (g.authenticator_kind='refresh_token' AND g.purpose='oauth_refresh')
 ORDER BY g.address_id,g.authenticator_kind,g.purpose,g.id`

type exportPendingCursor struct {
	rows           *sql.Rows
	started, valid bool
	id             int64
	owner          bool
	envelope       []byte
}

func openExportPending(ctx context.Context, tx *sql.Tx, items []ExportAddress, first int64) (*exportPendingCursor, error) {
	ids := make([]int64, len(items))
	for i, item := range items {
		ids[i] = item.AddressID
	}
	raw, _ := json.Marshal(ids)
	rows, e := tx.QueryContext(ctx, `SELECT p.address_id,p.owner_key<>'',substring(p.secret_envelope FROM 1 FOR $3) FROM space.pending_reveals p JOIN space.private_addresses a ON a.source_id=p.source_id AND a.id=p.address_id AND a.auth_generation=p.auth_generation WHERE p.address_id IN(SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb)) AND p.address_id>=$2 ORDER BY p.address_id,p.id DESC`, string(raw), first, exportEnvelopeBytes+1)
	if e != nil {
		return nil, storageError(ctx)
	}
	return &exportPendingCursor{rows: rows}, nil
}
func (p *exportPendingCursor) next() error {
	clear(p.envelope)
	p.envelope = nil
	p.started = true
	p.valid = p.rows.Next()
	if !p.valid {
		return p.rows.Err()
	}
	return p.rows.Scan(&p.id, &p.owner, &p.envelope)
}
func (p *exportPendingCursor) key(a *Authority, item ExportAddress, expected []byte) (string, error) {
	if !p.started {
		if e := p.next(); e != nil {
			return "", ErrStorage
		}
	}
	for p.valid && p.id < item.AddressID {
		if e := p.next(); e != nil {
			return "", ErrStorage
		}
	}
	for p.valid && p.id == item.AddressID {
		if !p.owner {
			return "", ErrUnavailable
		}
		if len(p.envelope) > exportEnvelopeBytes {
			return "", ErrCredentials
		}
		pending, e := OpenPending(a.box, Owner{InstallationID: a.installationID, AddressID: item.AddressID, Generation: item.Generation}, p.envelope)
		if e != nil {
			return "", e
		}
		hash := Hash(pending.APIKey)
		if bytes.Equal(hash[:], expected) {
			return pending.APIKey, nil
		}
		if e = p.next(); e != nil {
			return "", ErrStorage
		}
	}
	return "", ErrUnavailable
}
func (p *exportPendingCursor) close() error {
	clear(p.envelope)
	p.envelope = nil
	e := p.rows.Err()
	if closeErr := p.rows.Close(); e == nil {
		e = closeErr
	}
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return ErrStorage
	}
	return nil
}
