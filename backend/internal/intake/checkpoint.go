package intake

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"icloudspace/internal/blobstore"
	"icloudspace/internal/sourceguard"
)

type publication struct {
	ObjectKey          string `json:"object_key"`
	PreviousGeneration int64  `json:"previous_generation"`
	Generation         int64  `json:"generation"`
	Owner              string `json:"owner"`
	ReceiptKey         string `json:"receipt_key"`
	StagingRef         string `json:"staging_ref"`
	StorageRef         string `json:"storage_ref"`
	Size               int64  `json:"size"`
	SHA                string `json:"sha"`
	RetentionOrderAt   int64  `json:"retention_order_at"`
	PublishedAt        int64  `json:"published_at"`
}

func (r *Repository) CommitBatch(ctx context.Context, gate *sourceguard.Lease, cp checkpoint) (result Result, err error) {
	p := cp.Plan
	result.BatchKey = p.BatchKey
	result.Through = p.Through
	if !r.valid(gate, p.Snapshot.Source.ID) {
		return result, ErrInvalid
	}
	if cp.Messages == nil {
		cp.Messages = []draft{}
	}
	for i := range cp.Messages {
		d := &cp.Messages[i]
		if d.From == nil {
			d.From = []mailbox{}
		}
		if d.To == nil {
			d.To = []mailbox{}
		}
		if d.CC == nil {
			d.CC = []mailbox{}
		}
		if d.Attachments == nil {
			d.Attachments = []attachment{}
		}
		if d.Recipients == nil {
			d.Recipients = []recipient{}
		}
		if d.Codes == nil {
			d.Codes = []string{}
		}
		if d.Links == nil {
			d.Links = []int64{}
		}
	}
	_, planHash, err := digest(p)
	if err != nil {
		return result, err
	}
	_, hash, err := digest(cp)
	if err != nil {
		return result, err
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	commitAttempted := false
	defer func() {
		_ = tx.Rollback()
		if err != nil && !commitAttempted {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			_ = r.AbandonBatch(cleanup, gate, p.BatchKey)
		}
	}()
	if err = checkSnapshot(ctx, tx, p.Snapshot); err != nil {
		return result, err
	}
	appliedAt := time.Now().UnixNano()
	var state string
	var stored []byte
	if err = tx.QueryRowContext(ctx, `SELECT state,plan_digest FROM space.intake_batches WHERE batch_key=$1 AND source_id=$2 FOR UPDATE`, p.BatchKey, p.Snapshot.Source.ID).Scan(&state, &stored); err != nil {
		return result, err
	}
	if state != "prepared" || !bytes.Equal(planHash, stored) {
		return result, ErrUnresolved
	}
	f := facts{Through: p.Through, Messages: []messageFact{}, Entries: []entryFact{}, Publications: []blobstore.Receipt{}, Evidence: []evidenceFact{}}
	for _, d := range cp.Messages {
		if d.TimestampIssue != "" {
			f.TimestampIssues = append(f.TimestampIssues, TimestampIssue{UID: d.UID, Code: d.TimestampIssue})
		}
	}
	if err = writePublications(ctx, tx, cp, &f); err != nil {
		return result, err
	}
	doc, err := json.Marshal(cp.Messages)
	if err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, insertMessagesSQL, p.Snapshot.Source.ID, p.Snapshot.Source.Generation, p.Snapshot.Mailbox, p.UIDValidity, string(doc), appliedAt); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, upgradeMessagesSQL, p.Snapshot.Source.ID, p.Snapshot.Source.Generation, p.Snapshot.Mailbox, p.UIDValidity, string(doc)); err != nil {
		return result, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.remote_uid,m.id,coalesce(m.object_key,'') FROM space.source_messages m
 WHERE m.source_id=$1 AND m.source_generation=$2 AND m.mailbox_name=$3 AND m.uid_validity=$4
 AND m.remote_uid IN (SELECT uid FROM jsonb_to_recordset($5::jsonb) AS x(uid bigint)) ORDER BY m.remote_uid`, p.Snapshot.Source.ID, p.Snapshot.Source.Generation, p.Snapshot.Mailbox, p.UIDValidity, string(doc))
	if err != nil {
		return result, err
	}
	ids := make(map[uint32]messageFact)
	for rows.Next() {
		var m messageFact
		if err = rows.Scan(&m.UID, &m.ID, &m.ObjectKey); err != nil {
			rows.Close()
			return result, err
		}
		f.Messages = append(f.Messages, m)
		ids[m.UID] = m
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(ids) != len(cp.Messages) {
		return result, ErrStale
	}
	for _, d := range cp.Messages {
		m := ids[d.UID]
		if d.ExistingID != 0 && m.ID != d.ExistingID || d.Receipt != nil && m.ObjectKey != d.Receipt.Identity.ObjectKey {
			return result, ErrStale
		}
	}
	args := []any{p.Snapshot.Source.ID, p.Snapshot.Source.Generation, p.Snapshot.Mailbox, p.UIDValidity, string(doc), appliedAt}
	for _, q := range []string{insertViewsSQL, insertRecipientsSQL, insertCodesSQL} {
		if _, err = tx.ExecContext(ctx, q, args...); err != nil {
			return result, err
		}
	}
	// Check the actual missing-link counts before allocating, including the
	// exhausted sentinel uid_next=2^32. No max(local_uid) reconstruction occurs.
	var exhausted bool
	if err = tx.QueryRowContext(ctx, uidExhaustionSQL, args[:5]...).Scan(&exhausted); err != nil {
		return result, err
	}
	if exhausted {
		return result, ErrUIDExhausted
	}
	rows, err = tx.QueryContext(ctx, insertEntriesSQL, args[:5]...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var e entryFact
		if err = rows.Scan(&e.AddressID, &e.MessageID, &e.ID, &e.UID); err != nil {
			rows.Close()
			return result, err
		}
		f.Entries = append(f.Entries, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	invalidations := p.Invalidations
	if _, err = tx.ExecContext(ctx, fillEntryCodesSQL, args[:5]...); err != nil {
		return result, err
	}
	hasEvidence := false
	for _, d := range cp.Messages {
		hasEvidence = hasEvidence || d.Ban != nil
	}
	if hasEvidence {
		if _, err = tx.ExecContext(ctx, insertEvidenceSQL, args...); err != nil {
			return result, err
		}
		rows, err = tx.QueryContext(ctx, `SELECT e.address_id,e.message_id,e.detected_at FROM space.address_evidence e JOIN
 (SELECT DISTINCT (x.ban->>'address_id')::bigint AS address_id FROM jsonb_to_recordset($2::jsonb) AS x(ban jsonb)) b ON b.address_id=e.address_id
 WHERE e.source_id=$1 ORDER BY e.address_id`, p.Snapshot.Source.ID, string(doc))
		if err != nil {
			return result, err
		}
		for rows.Next() {
			var fact evidenceFact
			if err = rows.Scan(&fact.AddressID, &fact.MessageID, &fact.DetectedAt); err != nil {
				rows.Close()
				return result, err
			}
			f.Evidence = append(f.Evidence, fact)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return result, err
		}
	}
	if invalidations == nil {
		invalidations = []Pending{}
	}
	invalid, _ := json.Marshal(invalidations)
	if _, err = tx.ExecContext(ctx, `DELETE FROM space.address_snapshots s USING jsonb_to_recordset($1::jsonb) AS x(address_id bigint,message_id bigint,selected_at bigint)
 WHERE s.source_id=$2 AND s.address_id=x.address_id AND s.message_id=x.message_id AND s.selected_at=x.selected_at`, string(invalid), p.Snapshot.Source.ID); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, selectSnapshotsSQL, args...); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.mailbox_entries e SET snapshot_selected_at=coalesce(e.snapshot_selected_at,s.selected_at) FROM space.address_snapshots s
 WHERE s.source_id=$1 AND s.entry_id=e.id`, p.Snapshot.Source.ID); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, pruneCodesSQL, p.Snapshot.Source.ID, string(doc)); err != nil {
		return result, err
	}
	if err = writeFrontier(ctx, tx, p, appliedAt); err != nil {
		return result, err
	}
	factJSON, err := json.Marshal(f)
	if err != nil {
		return result, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE space.intake_batches SET state='committed',checkpoint_digest=$2,committed_at=$3,plan=jsonb_set(plan,'{facts}',$4::jsonb)
 WHERE batch_key=$1 AND state='prepared'`, p.BatchKey, hash, appliedAt, string(factJSON))
	if err != nil {
		return result, err
	}
	if n, e := res.RowsAffected(); e != nil || n != 1 {
		return result, ErrStale
	}
	commit := r.commitCheckpoint
	if commit == nil {
		commit = (*sql.Tx).Commit
	}
	commitAttempted = true
	if err = commit(tx); err == nil {
		applyCommittedFacts(&result, &f)
		return result, nil
	}
	// Never replay this transaction. A new connection waits for the source
	// transaction lock before reading the receipt and the actual durable rows.
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	resolution, resolved, e := r.resolve(lookup, gate, p.BatchKey, hash)
	if e == nil && resolution == Committed {
		resolved.Recovered = true
		return resolved, nil
	}
	if e == nil && resolution == NotCommitted {
		return result, ErrUnresolved
	}
	return result, ErrUnknown
}

func writePublications(ctx context.Context, tx *sql.Tx, cp checkpoint, f *facts) error {
	var pubs []publication
	for _, d := range cp.Messages {
		if d.Receipt == nil {
			continue
		}
		b := *d.Receipt
		b.Reused = false
		if d.ObjectGeneration > 0 && (b.ByteSize != d.ExpectedSize || b.SHA256 != d.ExpectedSHA) {
			return ErrSourceChanged
		}
		if _, err := decodeSHA(b.SHA256); err != nil {
			return err
		}
		pubs = append(pubs, publication{ObjectKey: b.Identity.ObjectKey, PreviousGeneration: d.ObjectGeneration, Generation: b.Identity.Generation, Owner: b.Identity.OwnerKey, ReceiptKey: b.ReceiptKey, StagingRef: b.StagingRef, StorageRef: b.StorageRef, Size: b.ByteSize, SHA: b.SHA256, RetentionOrderAt: d.ReceivedAt, PublishedAt: d.PublishedAt})
		f.Publications = append(f.Publications, b)
	}
	if len(pubs) == 0 {
		return nil
	}
	doc, _ := json.Marshal(pubs)
	var count int
	err := tx.QueryRowContext(ctx, writeObjectsSQL, string(doc), cp.Plan.Snapshot.Source.ID, cp.Plan.CreatedAt).Scan(&count)
	if err != nil {
		return err
	}
	if count != len(pubs) {
		return ErrStale
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO space.content_publications(receipt_key,source_id,object_key,owner_key,staging_ref,publication_generation,state,created_at,updated_at)
 SELECT x.receipt_key,$2,x.object_key,x.owner,x.staging_ref,x.generation,'committed',$3,x.published_at FROM jsonb_to_recordset($1::jsonb)
 AS x(receipt_key text,object_key text,owner text,staging_ref text,generation bigint,published_at bigint)
 ON CONFLICT (receipt_key) DO NOTHING`, string(doc), cp.Plan.Snapshot.Source.ID, cp.Plan.CreatedAt)
	return err
}

func writeFrontier(ctx context.Context, tx *sql.Tx, p plan, appliedAt int64) error {
	s := p.Snapshot
	if b := s.Backfill; b != nil {
		result, err := tx.ExecContext(ctx, `UPDATE space.address_backfills SET committed_uid=$6,state=CASE WHEN $6=captured_upper_uid THEN 'complete' ELSE 'scanning' END,
 initialized=true,owner_key=$7,updated_at=$8 WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3 AND address_id=$4 AND scan_epoch=$5
 AND uid_validity=$9 AND captured_upper_uid=$10 AND committed_uid=$11 AND state=$12`, s.Source.ID, s.Source.Generation, s.Mailbox, b.AddressID, b.ScanEpoch, p.Through, p.BatchKey, appliedAt, b.UIDValidity, b.Upper, b.Committed, b.State)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrStale
		}
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO space.mailbox_cursors(source_id,mailbox_name,source_generation,uid_validity,committed_uid,observed_uid,revision,updated_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(source_id,source_generation,mailbox_name) DO UPDATE
 SET uid_validity=EXCLUDED.uid_validity,committed_uid=EXCLUDED.committed_uid,observed_uid=EXCLUDED.observed_uid,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at`,
		s.Source.ID, s.Mailbox, s.Source.Generation, p.UIDValidity, p.Through, p.Upper, s.Cursor.Revision+1, appliedAt)
	return err
}

func (r *Repository) ResolveBatch(ctx context.Context, gate *sourceguard.Lease, key string) (Resolution, Result, error) {
	return r.resolve(ctx, gate, key, nil)
}

func (r *Repository) resolve(ctx context.Context, gate *sourceguard.Lease, key string, expected []byte) (Resolution, Result, error) {
	result := Result{BatchKey: key}
	if gate == nil || !r.valid(gate, gate.SourceID()) {
		return Unknown, result, ErrInvalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return Unknown, result, err
	}
	defer tx.Rollback()
	var sourceID int64
	// FOR SHARE conflicts with the checkpoint's FOR UPDATE. A visible prepared
	// row cannot be mistaken for rollback while COMMIT is still finishing.
	if err = tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR SHARE`, gate.SourceID()).Scan(&sourceID); err != nil {
		return Unknown, result, err
	}
	var state string
	var doc, planHash, checkpointHash []byte
	err = tx.QueryRowContext(ctx, `SELECT state,plan,plan_digest,checkpoint_digest FROM space.intake_batches WHERE batch_key=$1 AND source_id=$2`, key, sourceID).Scan(&state, &doc, &planHash, &checkpointHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Unknown, result, nil
	}
	if err != nil {
		return Unknown, result, err
	}
	var rec record
	if err = json.Unmarshal(doc, &rec); err != nil {
		return Unknown, result, err
	}
	_, actualHash, e := digest(rec.Intent)
	if e != nil || !bytes.Equal(actualHash, planHash) {
		return Unknown, result, ErrUnresolved
	}
	if state == "abandoned" || state == "prepared" {
		return NotCommitted, result, nil
	}
	if state != "committed" || rec.Facts == nil || len(checkpointHash) != 32 || expected != nil && !bytes.Equal(expected, checkpointHash) {
		return Unknown, result, ErrUnresolved
	}
	f := rec.Facts
	messageJSON, _ := json.Marshal(f.Messages)
	entryJSON, _ := json.Marshal(f.Entries)
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT
 NOT EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) AS x(uid bigint,id bigint,object_key text) LEFT JOIN space.source_messages m ON m.id=x.id
 WHERE m.id IS NULL OR m.source_id<>$3 OR m.source_generation<>$4 OR m.mailbox_name<>$5 OR m.uid_validity<>$6 OR m.remote_uid<>x.uid OR coalesce(m.object_key,'')<>x.object_key)
 AND NOT EXISTS(SELECT 1 FROM jsonb_to_recordset($2::jsonb) AS x(address_id bigint,message_id bigint,id bigint,uid bigint) LEFT JOIN space.mailbox_entries e ON e.id=x.id
 WHERE e.id IS NULL OR e.source_id<>$3 OR e.address_id<>x.address_id OR e.message_id<>x.message_id OR e.local_uid<>x.uid)`, string(messageJSON), string(entryJSON), sourceID, rec.Intent.Snapshot.Source.Generation, rec.Intent.Snapshot.Mailbox, rec.Intent.UIDValidity).Scan(&valid)
	if err != nil {
		return Unknown, result, err
	}
	if !valid {
		return Unknown, result, ErrUnresolved
	}
	if len(f.Evidence) > 0 {
		evidenceJSON, _ := json.Marshal(f.Evidence)
		err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) AS x(address_id bigint,message_id bigint,detected_at bigint)
 LEFT JOIN space.address_evidence e ON e.source_id=$2 AND e.address_id=x.address_id WHERE e.address_id IS NULL OR e.message_id IS DISTINCT FROM x.message_id OR e.detected_at<>x.detected_at OR e.evidence_kind<>'trusted_ban')`, string(evidenceJSON), sourceID).Scan(&valid)
		if err != nil {
			return Unknown, result, err
		}
		if !valid {
			return Unknown, result, ErrUnresolved
		}
	}
	publicationJSON, _ := json.Marshal(f.Publications)
	err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM jsonb_array_elements($1::jsonb) x
 LEFT JOIN space.content_publications p ON p.receipt_key=x->>'receipt_key'
 LEFT JOIN space.content_objects o ON o.object_key=p.object_key
 WHERE p.receipt_key IS NULL OR p.source_id<>$2 OR p.object_key<>x->'identity'->>'object_key' OR p.owner_key<>x->'identity'->>'owner_key'
 OR p.publication_generation<>(x->'identity'->>'generation')::bigint OR p.staging_ref<>x->>'staging_ref' OR p.state<>'committed'
 OR o.publication_generation<p.publication_generation OR o.byte_size<>(x->>'byte_size')::bigint OR encode(o.sha256,'hex')<>x->>'sha256')`, string(publicationJSON), sourceID).Scan(&valid)
	if err != nil {
		return Unknown, result, err
	}
	if !valid {
		return Unknown, result, ErrUnresolved
	}
	if b := rec.Intent.Snapshot.Backfill; b != nil {
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_backfills WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3 AND address_id=$4 AND scan_epoch=$5 AND uid_validity=$6 AND captured_upper_uid=$7 AND committed_uid>=$8)`, sourceID, rec.Intent.Snapshot.Source.Generation, rec.Intent.Snapshot.Mailbox, b.AddressID, b.ScanEpoch, rec.Intent.UIDValidity, b.Upper, f.Through).Scan(&valid)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.mailbox_cursors WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3 AND ((uid_validity=$4 AND committed_uid>=$5) OR (uid_validity<>$4 AND revision>$6)))`, sourceID, rec.Intent.Snapshot.Source.Generation, rec.Intent.Snapshot.Mailbox, rec.Intent.UIDValidity, f.Through, rec.Intent.Snapshot.Cursor.Revision+1).Scan(&valid)
	}
	if err != nil {
		return Unknown, result, err
	}
	if !valid {
		return Unknown, result, ErrUnresolved
	}
	applyCommittedFacts(&result, f)
	result.Through = f.Through
	result.CapturedUpper = rec.Intent.Upper
	result.Complete = f.Through == rec.Intent.Upper
	if err = tx.Commit(); err != nil {
		return Unknown, result, err
	}
	return Committed, result, nil
}

// Counters come from the same acknowledged receipt as the checkpoint. A
// metadata-only message is never counted as a published body, including when
// the original COMMIT acknowledgement was lost and ResolveBatch recovers it.
func applyCommittedFacts(result *Result, f *facts) {
	result.Messages = len(f.Messages)
	result.Links = len(f.Entries)
	result.Publications = len(f.Publications)
	result.Bytes = 0
	for _, publication := range f.Publications {
		result.Bytes += publication.ByteSize
	}
	result.TimestampIssues = f.TimestampIssues
}

const writeObjectsSQL = `WITH changed AS (
 INSERT INTO space.content_objects AS o(object_key,source_id,manifest_version,byte_size,sha256,storage_ref,state,publication_generation,created_at,published_at,verified_at,retention_order_at)
 SELECT x.object_key,$2,1,x.size,decode(x.sha,'hex'),x.storage_ref,'available',x.generation,$3,x.published_at,x.published_at,x.retention_order_at
 FROM jsonb_to_recordset($1::jsonb) AS x(object_key text,size bigint,sha text,storage_ref text,generation bigint,previous_generation bigint,retention_order_at bigint,published_at bigint)
 ON CONFLICT(object_key) DO UPDATE SET byte_size=EXCLUDED.byte_size,sha256=EXCLUDED.sha256,storage_ref=EXCLUDED.storage_ref,state='available',publication_generation=EXCLUDED.publication_generation,published_at=EXCLUDED.published_at,verified_at=EXCLUDED.verified_at,evicted_at=NULL
 WHERE o.source_id=$2 AND o.publication_generation=(SELECT prior.previous_generation FROM jsonb_to_recordset($1::jsonb) AS prior(object_key text,previous_generation bigint) WHERE prior.object_key=EXCLUDED.object_key)
 AND EXCLUDED.publication_generation>o.publication_generation AND o.state IN ('evicted','missing','corrupt')
 AND o.byte_size=EXCLUDED.byte_size AND o.sha256=EXCLUDED.sha256 RETURNING object_key
) SELECT count(*) FROM changed`

const insertMessagesSQL = `INSERT INTO space.source_messages(source_id,source_generation,mailbox_name,uid_validity,remote_uid,object_key,rfc_message_id,subject,sender_address,sender_name,sender_descriptors,sent_at,received_at,raw_header,raw_header_complete,preview_text,declared_body_size,content_state,created_at)
 SELECT $1,$2,$3,$4,x.uid,nullif(x.object_key,''),x.message_id,x.subject,coalesce(x.from_value->0->>'address',''),coalesce(x.from_value->0->>'name',''),coalesce(x.from_value,'[]'),x.sent_at,x.received_at,decode(x.header,'base64'),x.header_complete,left(x.text,512),x.size,x.state,$6
 FROM (SELECT j.*,j."from" AS from_value FROM jsonb_to_recordset($5::jsonb) AS j(uid bigint,object_key text,message_id text,subject text,"from" jsonb,sent_at bigint,received_at bigint,header text,header_complete boolean,text text,size bigint,state text)) x
 ON CONFLICT(source_id,source_generation,mailbox_name,uid_validity,remote_uid) DO NOTHING`

const upgradeMessagesSQL = `UPDATE space.source_messages m SET object_key=coalesce(m.object_key,nullif(x.object_key,'')),
 subject=CASE WHEN NOT m.raw_header_complete AND x.header_complete THEN x.subject ELSE m.subject END,
 rfc_message_id=CASE WHEN NOT m.raw_header_complete AND x.header_complete THEN x.message_id ELSE m.rfc_message_id END,
 sender_descriptors=CASE WHEN NOT m.raw_header_complete AND x.header_complete THEN x."from" ELSE m.sender_descriptors END,
 sender_address=CASE WHEN NOT m.raw_header_complete AND x.header_complete THEN coalesce(x."from"->0->>'address','') ELSE m.sender_address END,
 sender_name=CASE WHEN NOT m.raw_header_complete AND x.header_complete THEN coalesce(x."from"->0->>'name','') ELSE m.sender_name END,
 preview_text=CASE WHEN x.object_key<>'' THEN left(x.text,512) ELSE m.preview_text END,
 declared_body_size=CASE WHEN m.object_key IS NULL AND x.object_key<>'' THEN x.size ELSE m.declared_body_size END,
 raw_header=CASE WHEN NOT m.raw_header_complete AND x.header_complete THEN decode(x.header,'base64') ELSE m.raw_header END,
 raw_header_complete=m.raw_header_complete OR x.header_complete,
 content_state=CASE WHEN x.object_key<>'' THEN x.state ELSE m.content_state END
 FROM jsonb_to_recordset($5::jsonb) AS x(existing_id bigint,uid bigint,object_key text,header text,header_complete boolean,state text,subject text,message_id text,"from" jsonb,text text,size bigint)
 WHERE m.id=x.existing_id AND m.source_id=$1 AND m.source_generation=$2 AND m.mailbox_name=$3 AND m.uid_validity=$4 AND m.remote_uid=x.uid`

const messageInputSQL = `WITH input AS (SELECT * FROM jsonb_to_recordset($5::jsonb) AS x(uid bigint,links jsonb,code text,seen boolean,received_at bigint)), wanted AS (
 SELECT m.id AS message_id,m.remote_uid,m.received_at,(a.value)::bigint AS address_id,x.code,x.seen
 FROM input x JOIN space.source_messages m ON m.source_id=$1 AND m.source_generation=$2 AND m.mailbox_name=$3 AND m.uid_validity=$4 AND m.remote_uid=x.uid
 CROSS JOIN LATERAL jsonb_array_elements_text(x.links) a
) `

const insertViewsSQL = `INSERT INTO space.message_views(view_key,source_id,message_id,address_id,view_version,rfc_message_id,subject,sender_descriptors,to_descriptors,cc_descriptors,sent_at,received_at,text_body,html_body,attachment_descriptors,body_complete,derived_at)
 SELECT 'message.'||m.id,$1,m.id,NULL,1,x.message_id,x.subject,coalesce(x."from",'[]'),coalesce(x."to",'[]'),coalesce(x.cc,'[]'),x.sent_at,x.received_at,x.text,x.html,coalesce(x.attachments,'[]'),x.body_complete,$6
 FROM jsonb_to_recordset($5::jsonb) AS x(uid bigint,message_id text,subject text,"from" jsonb,"to" jsonb,cc jsonb,sent_at bigint,received_at bigint,text text,html text,attachments jsonb,body_complete boolean)
 JOIN space.source_messages m ON m.source_id=$1 AND m.source_generation=$2 AND m.mailbox_name=$3 AND m.uid_validity=$4 AND m.remote_uid=x.uid
 ON CONFLICT(message_id,address_id) DO UPDATE SET rfc_message_id=EXCLUDED.rfc_message_id,subject=EXCLUDED.subject,sender_descriptors=EXCLUDED.sender_descriptors,to_descriptors=EXCLUDED.to_descriptors,cc_descriptors=EXCLUDED.cc_descriptors,sent_at=EXCLUDED.sent_at,text_body=EXCLUDED.text_body,html_body=EXCLUDED.html_body,attachment_descriptors=EXCLUDED.attachment_descriptors,body_complete=true,derived_at=EXCLUDED.derived_at
 WHERE EXCLUDED.body_complete AND NOT space.message_views.body_complete`

const insertRecipientsSQL = `INSERT INTO space.message_recipients(message_id,role,ordinal,email,display_name,evidence)
 SELECT m.id,y.role,y.ordinal,y.email,y.name,y.evidence FROM jsonb_to_recordset($5::jsonb) AS x(uid bigint,recipients jsonb)
 JOIN space.source_messages m ON m.source_id=$1 AND m.source_generation=$2 AND m.mailbox_name=$3 AND m.uid_validity=$4 AND m.remote_uid=x.uid
 CROSS JOIN LATERAL jsonb_to_recordset(x.recipients) AS y(role text,ordinal integer,email text,name text,evidence text)
 WHERE $6::bigint IS NOT NULL ON CONFLICT DO NOTHING`

const insertCodesSQL = `INSERT INTO space.message_codes(message_id,ordinal,code)
 SELECT m.id,(c.ordinality-1)::integer,c.value #>> '{}' FROM jsonb_to_recordset($5::jsonb) AS x(uid bigint,codes jsonb)
 JOIN space.source_messages m ON m.source_id=$1 AND m.source_generation=$2 AND m.mailbox_name=$3 AND m.uid_validity=$4 AND m.remote_uid=x.uid
 CROSS JOIN LATERAL jsonb_array_elements(x.codes) WITH ORDINALITY c WHERE $6::bigint IS NOT NULL ON CONFLICT DO NOTHING`

const uidExhaustionSQL = messageInputSQL + `SELECT EXISTS(SELECT 1 FROM (SELECT w.address_id,count(*) AS n FROM wanted w LEFT JOIN space.mailbox_entries e ON e.address_id=w.address_id AND e.message_id=w.message_id WHERE e.id IS NULL GROUP BY w.address_id) missing JOIN space.private_addresses a ON a.id=missing.address_id WHERE a.uid_next+missing.n>4294967296)`

const insertEntriesSQL = messageInputSQL + `, missing AS (
 SELECT w.*,a.uid_next,c.claimed_at,row_number() OVER(PARTITION BY w.address_id ORDER BY w.remote_uid,w.message_id) AS ordinal
 FROM wanted w JOIN space.private_addresses a ON a.source_id=$1 AND a.id=w.address_id
 LEFT JOIN space.mailbox_entries e ON e.address_id=w.address_id AND e.message_id=w.message_id
 LEFT JOIN space.consume_claims c ON c.address_id=w.address_id AND c.source_generation=$2 AND c.mailbox_name=$3 AND c.uid_validity=$4 AND c.remote_uid=w.remote_uid
 WHERE e.id IS NULL
), inserted AS (
 INSERT INTO space.mailbox_entries(source_id,address_id,message_id,local_uid,visible_at,consumed_at,retained_code)
 SELECT $1,address_id,message_id,uid_next+ordinal-1,received_at,claimed_at,code FROM missing ORDER BY address_id,ordinal RETURNING address_id,message_id,id,local_uid
), advanced AS (
 UPDATE space.private_addresses a SET uid_next=a.uid_next+n.amount,
 latest_received_at=greatest(a.latest_received_at,n.received_at)
 FROM (SELECT i.address_id,count(*) amount,max(m.received_at) received_at
 FROM inserted i JOIN space.source_messages m ON m.source_id=$1 AND m.id=i.message_id GROUP BY i.address_id) n
 WHERE a.id=n.address_id RETURNING a.id
)
 SELECT address_id,message_id,id,local_uid FROM inserted UNION ALL SELECT e.address_id,e.message_id,e.id,e.local_uid FROM space.mailbox_entries e JOIN wanted w ON w.address_id=e.address_id AND w.message_id=e.message_id ORDER BY 1,4`

const fillEntryCodesSQL = messageInputSQL + `UPDATE space.mailbox_entries e SET retained_code=w.code FROM wanted w
 WHERE e.source_id=$1 AND e.address_id=w.address_id AND e.message_id=w.message_id AND e.retained_code IS NULL AND w.code IS NOT NULL`

const insertEvidenceSQL = `INSERT INTO space.address_evidence(address_id,source_id,message_id,evidence_kind,detected_at,detail)
 SELECT (x.ban->>'address_id')::bigint,$1,m.id,'trusted_ban',(x.ban->>'detected_at')::bigint,x.ban->>'detail'
 FROM jsonb_to_recordset($5::jsonb) AS x(uid bigint,ban jsonb)
 JOIN space.source_messages m ON m.source_id=$1 AND m.source_generation=$2 AND m.mailbox_name=$3 AND m.uid_validity=$4 AND m.remote_uid=x.uid
 JOIN space.mailbox_entries e ON e.source_id=$1 AND e.address_id=(x.ban->>'address_id')::bigint AND e.message_id=m.id
 WHERE $6::bigint IS NOT NULL
 ORDER BY (x.ban->>'address_id')::bigint,m.received_at,m.remote_uid,m.id
 ON CONFLICT(address_id) DO NOTHING`

const selectSnapshotsSQL = messageInputSQL + `, candidates AS (
 SELECT DISTINCT ON(w.address_id) w.address_id,w.message_id,e.id AS entry_id,v.view_key,w.received_at,w.remote_uid
 FROM wanted w JOIN space.mailbox_entries e ON e.address_id=w.address_id AND e.message_id=w.message_id
 JOIN space.message_views v ON v.message_id=w.message_id AND v.address_id IS NULL
 WHERE NOT w.seen AND e.consumed_at IS NULL ORDER BY w.address_id,w.remote_uid DESC,w.message_id DESC
)
 INSERT INTO space.address_snapshots AS s(address_id,source_id,message_id,entry_id,view_key,selected_at)
 SELECT address_id,$1,message_id,entry_id,view_key,$6 FROM candidates
 ON CONFLICT(address_id) DO UPDATE SET message_id=EXCLUDED.message_id,entry_id=EXCLUDED.entry_id,view_key=EXCLUDED.view_key,view_scope_address_id=0,selected_at=EXCLUDED.selected_at,consumed_at=NULL
 WHERE s.message_id<>EXCLUDED.message_id AND (SELECT new.source_generation>old.source_generation OR (new.source_generation=old.source_generation AND (new.uid_validity<>old.uid_validity OR (new.remote_uid,new.id)>(old.remote_uid,old.id))) FROM space.source_messages new,space.source_messages old WHERE new.id=EXCLUDED.message_id AND old.id=s.message_id)`

const pruneCodesSQL = `WITH addresses AS (SELECT DISTINCT value::bigint id FROM jsonb_to_recordset($2::jsonb) AS x(links jsonb) CROSS JOIN LATERAL jsonb_array_elements_text(x.links)), ranked AS (
 SELECT e.id,row_number() OVER(PARTITION BY e.address_id ORDER BY e.visible_at DESC,e.local_uid DESC,e.id DESC) ordinal FROM space.mailbox_entries e JOIN addresses a ON a.id=e.address_id WHERE e.source_id=$1 AND e.retained_code IS NOT NULL
) UPDATE space.mailbox_entries e SET retained_code=NULL FROM ranked r WHERE e.id=r.id AND r.ordinal>100`
