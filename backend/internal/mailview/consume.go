package mailview

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"icloudspace/internal/addressauth"
	"icloudspace/internal/content"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

func requestDigest(id addressauth.Identity, r ClaimRequest) [32]byte {
	encoded, _ := json.Marshal(struct {
		Version             int
		SourceID, AddressID int64
		Request             ClaimRequest
	}{1, id.SourceID, id.AddressID, r})
	return sha256.Sum256(encoded)
}
func validRef(r SnapshotRef) bool {
	return r.AuthGeneration > 0 && r.MessageID > 0 && r.EntryID >= 0 && ((r.EntryID == 0) == (r.LocalUID == 0)) && r.LocalUIDValidity > 0 && r.LocalUIDValidity <= math.MaxUint32 && len(r.ViewKey) <= 256 && utf8.ValidString(r.ViewKey) && !strings.ContainsAny(r.ViewKey, "\x00\r\n") && r.ViewScopeAddressID >= 0 && r.Remote.SourceGeneration > 0 && r.Remote.Mailbox != "" && len(r.Remote.Mailbox) <= 1024 && utf8.ValidString(r.Remote.Mailbox) && !strings.ContainsAny(r.Remote.Mailbox, "\x00\r\n") && r.Remote.UIDValidity > 0 && r.Remote.UID > 0
}
func (s *Service) lockScope(ctx context.Context, tx *sql.Tx, id addressauth.Identity, lease *addressauth.Lease) error {
	var sid int64
	if tx.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE id=$1 FOR UPDATE`, id.SourceID).Scan(&sid) != nil {
		return storage(ctx)
	}
	if tx.QueryRowContext(ctx, `SELECT id FROM space.private_addresses WHERE source_id=$1 AND id=$2 FOR UPDATE`, id.SourceID, id.AddressID).Scan(&sid) != nil {
		return storage(ctx)
	}
	if e := lease.RevalidateTx(ctx, tx); e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrDenied
	}
	return nil
}
func (s *Service) existingClaim(ctx context.Context, tx *sql.Tx, id addressauth.Identity, r ClaimRequest) (ClaimResult, error) {
	var out ClaimResult
	var digest []byte
	e := tx.QueryRowContext(ctx, `SELECT claim_key,request_digest,source_generation,mailbox_name,uid_validity,remote_uid,claimed_at FROM space.consume_claims WHERE claim_key=$1 AND source_id=$2 AND address_id=$3 FOR SHARE`, r.Key, id.SourceID, id.AddressID).Scan(&out.Key, &digest, &out.Remote.SourceGeneration, &out.Remote.Mailbox, &out.Remote.UIDValidity, &out.Remote.UID, &out.ClaimedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, storage(ctx)
	}
	expected := requestDigest(id, r)
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, expected[:]) != 1 {
		return ClaimResult{}, ErrStale
	}
	out.Committed = true
	return out, nil
}

// Consume is an explicit local transaction. It never acquires a network source
// guard or contacts an upstream server. One exact snapshot and remote identity
// produce one durable claim plus one coalesced Seen job in the same commit.
func (s *Service) Consume(ctx context.Context, lease *addressauth.Lease, r ClaimRequest) (ClaimResult, error) {
	id, e := s.allow(lease, addressauth.MailConsume, addressauth.RecentConsume)
	if e != nil {
		return ClaimResult{}, e
	}
	if !validKey(r.Key) || !validRef(r.Snapshot) {
		return ClaimResult{}, ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ClaimResult{}, storage(ctx)
	}
	defer tx.Rollback()
	if e = s.writable(ctx, tx); e != nil {
		return ClaimResult{}, e
	}
	if e = s.lockScope(ctx, tx, id, lease); e != nil {
		return ClaimResult{}, e
	}
	if existing, e := s.existingClaim(ctx, tx, id, r); e == nil {
		if tx.Commit() != nil {
			return ClaimResult{}, storage(ctx)
		}
		return existing, nil
	} else if !errors.Is(e, ErrNotFound) {
		return ClaimResult{}, e
	}
	if r.Snapshot.AuthGeneration != id.Generation || r.Snapshot.LocalUIDValidity != id.UIDValidity || r.Snapshot.Remote.SourceGeneration != id.SourceGeneration {
		return ClaimResult{}, ErrStale
	}
	var address int64
	if e = tx.QueryRowContext(ctx, `SELECT address_id FROM space.address_snapshots WHERE source_id=$1 AND address_id=$2 FOR UPDATE`, id.SourceID, id.AddressID).Scan(&address); errors.Is(e, sql.ErrNoRows) {
		return ClaimResult{}, ErrNotFound
	} else if e != nil {
		return ClaimResult{}, storage(ctx)
	}
	current, e := s.latest(ctx, tx, id)
	if e != nil {
		return ClaimResult{}, e
	}
	if current.Ref != r.Snapshot {
		return ClaimResult{}, ErrStale
	}
	if current.Consumed {
		return ClaimResult{}, ErrConsumed
	}
	lower := int64(math.MinInt64)
	now := s.options.Clock()
	if now >= math.MinInt64+int64(time.Hour) {
		lower = now - int64(time.Hour)
	}
	if current.Message.Metadata.ReceivedAt < lower || current.Message.Metadata.ReceivedAt > now {
		return ClaimResult{}, ErrStale
	}
	var remoteUIDV uint32
	if e = tx.QueryRowContext(ctx, `SELECT uid_validity FROM space.mailbox_cursors WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3 FOR SHARE`, id.SourceID, id.SourceGeneration, r.Snapshot.Remote.Mailbox).Scan(&remoteUIDV); errors.Is(e, sql.ErrNoRows) {
		return ClaimResult{}, ErrStale
	} else if e != nil {
		return ClaimResult{}, storage(ctx)
	}
	if remoteUIDV != r.Snapshot.Remote.UIDValidity {
		return ClaimResult{}, ErrStale
	}
	digest := requestDigest(id, r)
	var entry any
	if r.Snapshot.EntryID != 0 {
		entry = r.Snapshot.EntryID
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO space.consume_claims(claim_key,request_digest,source_id,address_id,entry_id,source_generation,mailbox_name,uid_validity,remote_uid,claimed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.Key, digest[:], id.SourceID, id.AddressID, entry, r.Snapshot.Remote.SourceGeneration, r.Snapshot.Remote.Mailbox, r.Snapshot.Remote.UIDValidity, r.Snapshot.Remote.UID, now)
	if e != nil {
		var state interface{ SQLState() string }
		if errors.As(e, &state) && state.SQLState() == "23505" {
			return ClaimResult{}, ErrStale
		}
		return ClaimResult{}, storage(ctx)
	}
	changed, e := tx.ExecContext(ctx, `UPDATE space.address_snapshots SET consumed_at=$3 WHERE source_id=$1 AND address_id=$2 AND message_id=$4 AND selected_at=$5 AND coalesce(view_key,'')=$6 AND view_scope_address_id=$7 AND consumed_at IS NULL`, id.SourceID, id.AddressID, now, r.Snapshot.MessageID, r.Snapshot.SelectedAt, r.Snapshot.ViewKey, r.Snapshot.ViewScopeAddressID)
	if e != nil {
		return ClaimResult{}, storage(ctx)
	}
	count, e := changed.RowsAffected()
	if e != nil || count != 1 {
		return ClaimResult{}, ErrStale
	}
	if entry != nil {
		if _, e = tx.ExecContext(ctx, `UPDATE space.mailbox_entries SET consumed_at=coalesce(consumed_at,$3) WHERE source_id=$1 AND address_id=$2 AND id=$4 AND message_id=$5`, id.SourceID, id.AddressID, now, entry, r.Snapshot.MessageID); e != nil {
			return ClaimResult{}, storage(ctx)
		}
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO space.seen_jobs(source_id,source_generation,mailbox_name,uid_validity,remote_uid,state,attempts,last_error_code,created_at,next_attempt_at) VALUES($1,$2,$3,$4,$5,'pending',0,'',$6,$6) ON CONFLICT(source_id,source_generation,mailbox_name,uid_validity,remote_uid) DO NOTHING`, id.SourceID, r.Snapshot.Remote.SourceGeneration, r.Snapshot.Remote.Mailbox, r.Snapshot.Remote.UIDValidity, r.Snapshot.Remote.UID, now)
	if e != nil {
		return ClaimResult{}, storage(ctx)
	}
	snippet := trimSnippet(current.Message)
	if snippet == "" && current.Message.HTML != "" {
		snippet, e = content.TextFromHTML(current.Message.HTML, s.options.Limits.BodyBytes)
		if e != nil {
			return ClaimResult{}, ErrBudget
		}
	}
	if s.commit(tx) != nil {
		return ClaimResult{Key: r.Key, Remote: r.Snapshot.Remote}, ErrUnknown
	}
	return ClaimResult{Key: r.Key, Committed: true, Remote: r.Snapshot.Remote, ClaimedAt: now, Snippet: snippet}, nil
}

// QueryClaim settles status only, never fabricates the original response body
// from a later snapshot. Its source row lock waits for an in-flight claim's
// commit/rollback before observing the durable native request digest.
func (s *Service) QueryClaim(ctx context.Context, lease *addressauth.Lease, r ClaimRequest) (ClaimResult, error) {
	id, e := s.allow(lease, addressauth.MailConsume, addressauth.RecentConsume)
	if e != nil {
		return ClaimResult{}, e
	}
	if !validKey(r.Key) || !validRef(r.Snapshot) {
		return ClaimResult{}, ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ClaimResult{}, storage(ctx)
	}
	defer tx.Rollback()
	if e = s.lockScope(ctx, tx, id, lease); e != nil {
		return ClaimResult{}, e
	}
	result, e := s.existingClaim(ctx, tx, id, r)
	if e != nil {
		return ClaimResult{}, e
	}
	if tx.Commit() != nil {
		return ClaimResult{}, storage(ctx)
	}
	return result, nil
}
