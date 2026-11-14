package intake

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"icloudspace/internal/sourceguard"
)

type Repository struct {
	DB       *sql.DB
	Registry *sourceguard.Registry
	// This seam models a lost final COMMIT acknowledgement over a real PG
	// transaction. It is never used for Prepare or a business retry.
	commitCheckpoint  func(*sql.Tx) error
	commitPreparation func(*sql.Tx) error
}

func NewRepository(db *sql.DB, registry *sourceguard.Registry) *Repository {
	return &Repository{DB: db, Registry: registry, commitCheckpoint: (*sql.Tx).Commit, commitPreparation: (*sql.Tx).Commit}
}

func (r *Repository) valid(gate *sourceguard.Lease, id int64) bool {
	return r != nil && r.DB != nil && r.Registry != nil && gate.ValidFor(r.Registry, id)
}

// LoadSnapshot reads no credential envelope, grant, reveal or alias secret.
// pendingAfter is a caller-owned rotating metadata cursor, not a mail frontier.
func (r *Repository) LoadSnapshot(ctx context.Context, gate *sourceguard.Lease, id int64, mailbox string, pendingAfter int64) (Snapshot, error) {
	s := Snapshot{Mailbox: mailbox}
	if !r.valid(gate, id) || mailbox == "" || pendingAfter < 0 {
		return s, ErrInvalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return s, err
	}
	defer tx.Rollback()
	s.Source, err = readSource(ctx, tx, id, false)
	if err != nil {
		return s, err
	}
	s.Aliases, err = readAliases(ctx, tx, id, false)
	if err != nil {
		return s, err
	}
	s.Cursor, err = readCursor(ctx, tx, s)
	if err != nil {
		return s, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.address_id,a.message_id,m.source_generation,m.uid_validity,m.remote_uid,a.selected_at
 FROM space.address_snapshots a JOIN space.source_messages m ON m.id=a.message_id
 WHERE a.source_id=$1 AND m.mailbox_name=$2 AND a.address_id>$3 AND a.consumed_at IS NULL ORDER BY a.address_id LIMIT 32`, id, mailbox, pendingAfter)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var p Pending
		if err = rows.Scan(&p.AddressID, &p.MessageID, &p.Generation, &p.UIDValidity, &p.UID, &p.SelectedAt); err != nil {
			rows.Close()
			return s, err
		}
		s.Pending = append(s.Pending, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return s, err
	}
	if err = tx.Commit(); err != nil {
		return s, err
	}
	return s, nil
}

func (r *Repository) LoadBackfill(ctx context.Context, gate *sourceguard.Lease, s Snapshot, addressID int64) (Snapshot, error) {
	if !r.valid(gate, s.Source.ID) || addressID < 1 {
		return s, ErrInvalid
	}
	b := &Backfill{AddressID: addressID}
	err := r.DB.QueryRowContext(ctx, `SELECT scan_epoch,uid_validity,lower_uid,captured_upper_uid,committed_uid,state FROM space.address_backfills
 WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3 AND address_id=$4 AND state IN ('pending','scanning') ORDER BY scan_epoch DESC LIMIT 1`, s.Source.ID, s.Source.Generation, s.Mailbox, addressID).
		Scan(&b.ScanEpoch, &b.UIDValidity, &b.Lower, &b.Upper, &b.Committed, &b.State)
	if err != nil {
		return s, err
	}
	s.Backfill = b
	return s, nil
}

func readSource(ctx context.Context, tx *sql.Tx, id int64, lock bool) (s Source, err error) {
	q := `SELECT id,revision,source_generation,credential_generation,enabled,kind,address_namespace,imap_username,imap_host,imap_port,
 coalesce((SELECT allow_weak_recipient_evidence FROM space.installation_settings WHERE singleton),false) FROM space.mail_sources WHERE id=$1`
	if lock {
		q += ` FOR UPDATE`
	}
	err = tx.QueryRowContext(ctx, q, id).Scan(&s.ID, &s.Revision, &s.Generation, &s.CredentialGeneration, &s.Enabled, &s.Kind, &s.Namespace, &s.Username, &s.Host, &s.Port, &s.AllowWeak)
	return
}

func readAliases(ctx context.Context, tx *sql.Tx, id int64, lock bool) (out []Alias, err error) {
	q := `SELECT id,revision,auth_generation,normalized_email,lifecycle,enabled,deleted_at IS NOT NULL,uid_next FROM space.private_addresses WHERE source_id=$1 ORDER BY id`
	if lock {
		q += ` FOR UPDATE`
	}
	rows, err := tx.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a Alias
		if err = rows.Scan(&a.ID, &a.Revision, &a.AuthGeneration, &a.Email, &a.Lifecycle, &a.Enabled, &a.Deleted, &a.UIDNext); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func readCursor(ctx context.Context, tx *sql.Tx, s Snapshot) (c Cursor, err error) {
	err = tx.QueryRowContext(ctx, `SELECT uid_validity,committed_uid,observed_uid,revision FROM space.mailbox_cursors WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3`, s.Source.ID, s.Source.Generation, s.Mailbox).Scan(&c.UIDValidity, &c.Committed, &c.Observed, &c.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	c.Exists = err == nil
	return
}

// All canonical intake writers lock the source before its alias set. The full
// set comparison detects additions as well as lifecycle/auth changes. No alias
// metadata or permission value is ever overwritten by this worker.
func checkSnapshot(ctx context.Context, tx *sql.Tx, s Snapshot) error {
	current, err := readSource(ctx, tx, s.Source.ID, true)
	if err != nil {
		return err
	}
	if current != s.Source || !current.Enabled {
		return ErrStale
	}
	var weak bool
	err = tx.QueryRowContext(ctx, `SELECT allow_weak_recipient_evidence FROM space.installation_settings WHERE singleton FOR SHARE`).Scan(&weak)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if weak != s.Source.AllowWeak {
		return ErrStale
	}
	aliases, err := readAliases(ctx, tx, s.Source.ID, true)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(aliases, s.Aliases) {
		return ErrStale
	}
	c, err := readCursor(ctx, tx, s)
	if err != nil {
		return err
	}
	if c != s.Cursor {
		return ErrStale
	}
	if b := s.Backfill; b != nil {
		var actual Backfill
		actual.AddressID = b.AddressID
		err = tx.QueryRowContext(ctx, `SELECT scan_epoch,uid_validity,lower_uid,captured_upper_uid,committed_uid,state FROM space.address_backfills
		 WHERE source_id=$1 AND address_id=$2 AND source_generation=$3 AND mailbox_name=$4 ORDER BY scan_epoch DESC LIMIT 1 FOR UPDATE`, s.Source.ID, b.AddressID, s.Source.Generation, s.Mailbox).Scan(&actual.ScanEpoch, &actual.UIDValidity, &actual.Lower, &actual.Upper, &actual.Committed, &actual.State)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		if err != nil {
			return err
		}
		if actual != *b {
			return ErrStale
		}
		found := false
		for _, a := range aliases {
			if a.ID == b.AddressID && a.Enabled && !a.Deleted && a.Lifecycle == "confirmed" {
				found = true
			}
		}
		if !found {
			return ErrStale
		}
	}
	return nil
}

func (r *Repository) CheckPending(ctx context.Context, gate *sourceguard.Lease, id int64) error {
	key, err := r.PendingBatch(ctx, gate, id)
	if err != nil {
		return err
	}
	if key != "" {
		return &PendingError{BatchKey: key}
	}
	return nil
}

// PendingBatch is the restart entry point for the source's unique prepared
// receipt. Finding it grants no authority to replay or allocate replacement IDs.
func (r *Repository) PendingBatch(ctx context.Context, gate *sourceguard.Lease, id int64) (string, error) {
	if !r.valid(gate, id) {
		return "", ErrInvalid
	}
	var key string
	err := r.DB.QueryRowContext(ctx, `SELECT batch_key FROM space.intake_batches WHERE source_id=$1 AND state='prepared'`, id).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return key, err
}

func (r *Repository) PrepareBatch(ctx context.Context, gate *sourceguard.Lease, p plan) error {
	if !r.valid(gate, p.Snapshot.Source.ID) || p.BatchKey == "" {
		return ErrInvalid
	}
	_, h, err := digest(p)
	if err != nil {
		return err
	}
	doc, err := json.Marshal(record{Intent: p})
	if err != nil {
		return err
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = checkSnapshot(ctx, tx, p.Snapshot); err != nil {
		return err
	}
	var pending bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.intake_batches WHERE source_id=$1 AND state='prepared')`, p.Snapshot.Source.ID).Scan(&pending)
	if err != nil {
		return err
	}
	if pending {
		return ErrUnresolved
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO space.intake_batches(batch_key,source_id,plan,plan_digest,state,created_at) VALUES($1,$2,$3,$4,'prepared',$5)`, p.BatchKey, p.Snapshot.Source.ID, string(doc), h, p.CreatedAt)
	if err != nil {
		return err
	}
	commit := r.commitPreparation
	if commit == nil {
		commit = (*sql.Tx).Commit
	}
	if err = commit(tx); err == nil {
		return nil
	}
	// A confirmed durable identity permits the read to begin. Missing evidence
	// leaves the batch unresolved and never starts a replacement stream.
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	var stored []byte
	var state string
	e := r.DB.QueryRowContext(lookup, `SELECT plan_digest,state FROM space.intake_batches WHERE batch_key=$1`, p.BatchKey).Scan(&stored, &state)
	if e == nil && bytes.Equal(stored, h) && state == "prepared" {
		return nil
	}
	return ErrUnknown
}

func (r *Repository) AbandonBatch(ctx context.Context, gate *sourceguard.Lease, key string) error {
	if gate == nil || !r.valid(gate, gate.SourceID()) {
		return ErrInvalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, gate.SourceID()).Scan(&id); err != nil {
		return err
	}
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT state FROM space.intake_batches WHERE batch_key=$1 AND source_id=$2 FOR UPDATE`, key, id).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnresolved
		}
		return err
	}
	if state == "abandoned" {
		return tx.Commit()
	}
	if state != "prepared" {
		return ErrUnresolved
	}
	_, err = tx.ExecContext(ctx, `UPDATE space.intake_batches SET state='abandoned',abandoned_at=$3 WHERE batch_key=$1 AND source_id=$2 AND state='prepared'`, key, id, time.Now().UnixNano())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) loadExisting(ctx context.Context, s Snapshot, uidv uint32, uids []uint32) (map[uint32]draft, error) {
	out := make(map[uint32]draft)
	if len(uids) == 0 {
		return out, nil
	}
	uidJSON, _ := json.Marshal(uids)
	rows, err := r.DB.QueryContext(ctx, `SELECT m.id,m.remote_uid,m.declared_body_size,m.received_at,m.sent_at,m.raw_header,m.raw_header_complete,m.content_state,m.rfc_message_id,m.subject,m.sender_descriptors,
 coalesce(v.to_descriptors,'[]'),coalesce(v.cc_descriptors,'[]'),coalesce(v.text_body,''),coalesce(v.html_body,''),coalesce(v.body_complete,false),coalesce(v.attachment_descriptors,'[]'),
 coalesce((SELECT jsonb_agg(code ORDER BY ordinal) FROM space.message_codes WHERE message_id=m.id),'[]'),
 coalesce(o.object_key,''),coalesce(o.state,''),coalesce(o.publication_generation,0),coalesce(o.byte_size,0),coalesce(encode(o.sha256,'hex'),'')
 FROM space.source_messages m LEFT JOIN space.message_views v ON v.message_id=m.id AND v.address_id IS NULL
 LEFT JOIN space.content_objects o ON o.object_key=m.object_key
 WHERE m.source_id=$1 AND m.source_generation=$2 AND m.mailbox_name=$3 AND m.uid_validity=$4 AND m.remote_uid IN (SELECT value::bigint FROM jsonb_array_elements_text($5::jsonb))`, s.Source.ID, s.Source.Generation, s.Mailbox, uidv, string(uidJSON))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d draft
		var from, to, cc, attachments, codes []byte
		var sent sql.NullInt64
		if err = rows.Scan(&d.ExistingID, &d.UID, &d.Size, &d.ReceivedAt, &sent, &d.Header, &d.HeaderComplete, &d.State, &d.MessageID, &d.Subject, &from, &to, &cc, &d.Text, &d.HTML, &d.BodyComplete, &attachments, &codes, &d.ObjectKey, &d.ObjectState, &d.ObjectGeneration, &d.ExpectedSize, &d.ExpectedSHA); err != nil {
			return nil, err
		}
		if sent.Valid {
			d.SentAt = &sent.Int64
		}
		for _, pair := range []struct {
			b []byte
			v any
		}{{from, &d.From}, {to, &d.To}, {cc, &d.CC}, {attachments, &d.Attachments}, {codes, &d.Codes}} {
			if err = json.Unmarshal(pair.b, pair.v); err != nil {
				return nil, err
			}
		}
		// A prefix marked malformed/truncated is never accepted as proof. A
		// fresh header parse applies the content package's actual completeness.
		if d.BodyComplete {
			for _, c := range d.Codes {
				if len(c) == 6 {
					c := c
					d.Code = &c
					break
				}
			}
		}
		out[d.UID] = d
	}
	return out, rows.Err()
}

func decodeSHA(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, ErrInvalid
	}
	return b, nil
}

// A failed publication may already own a filesystem generation even when its
// final SQL did not commit. Never reuse that generation with a different owner.
// This lookup is needed only for restoration of existing unavailable objects.
func (r *Repository) nextGenerations(ctx context.Context, sourceID int64, keys []string) (map[string]int64, error) {
	out := make(map[string]int64)
	if len(keys) == 0 {
		return out, nil
	}
	doc, _ := json.Marshal(keys)
	rows, err := r.DB.QueryContext(ctx, `WITH keys AS (SELECT DISTINCT value AS object_key FROM jsonb_array_elements_text($2::jsonb)), reserved AS (
 SELECT x->'identity'->>'object_key' AS object_key,max((x->'identity'->>'generation')::bigint) AS generation
 FROM space.intake_batches b CROSS JOIN LATERAL jsonb_array_elements(coalesce(nullif(b.plan->'intent'->'claims','null'::jsonb),'[]'::jsonb)) x
 JOIN keys k ON k.object_key=x->'identity'->>'object_key' WHERE b.source_id=$1 GROUP BY 1
 ), publications AS (SELECT p.object_key,max(p.publication_generation) AS generation FROM space.content_publications p JOIN keys k ON k.object_key=p.object_key WHERE p.source_id=$1 GROUP BY p.object_key)
 SELECT k.object_key,greatest(coalesce(o.publication_generation,0),coalesce(r.generation,0),coalesce(p.generation,0))
 FROM keys k LEFT JOIN space.content_objects o ON o.source_id=$1 AND o.object_key=k.object_key LEFT JOIN reserved r ON r.object_key=k.object_key LEFT JOIN publications p ON p.object_key=k.object_key`, sourceID, string(doc))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var high int64
		if err = rows.Scan(&key, &high); err != nil {
			return nil, err
		}
		if high == int64(^uint64(0)>>1) {
			return nil, ErrInvalid
		}
		out[key] = high + 1
	}
	return out, rows.Err()
}
