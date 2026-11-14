package mailview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"icloudspace/internal/addressauth"
	"icloudspace/internal/content"
	"math"
	"strings"
	"time"
)

const descriptorBudget = 1 << 20

// Body and descriptor byte lengths are checked inside SQL before transferring
// text to this process; malformed oversized rows cannot bypass parser budgets.
const messageHead = `m.id,m.source_generation,m.mailbox_name,m.uid_validity,m.remote_uid,m.rfc_message_id,m.subject,
 CASE WHEN octet_length(m.sender_descriptors::text)<=$4 THEN m.sender_descriptors END,
 m.sent_at,m.received_at,m.content_state,coalesce(o.state,CASE WHEN m.content_state='over_budget' THEN 'over_budget' ELSE 'metadata_only' END),m.declared_body_size,m.declared_body_truncated,m.preview_text,
 v.view_key,v.rfc_message_id,v.subject,
 CASE WHEN octet_length(v.sender_descriptors::text)<=$4 THEN v.sender_descriptors END,
 CASE WHEN octet_length(v.to_descriptors::text)<=$4 THEN v.to_descriptors END,
 CASE WHEN octet_length(v.cc_descriptors::text)<=$4 THEN v.cc_descriptors END,v.sent_at,v.received_at,`
const messageColumns = messageHead + `
 CASE WHEN octet_length(v.text_body)<=$3 THEN v.text_body END,CASE WHEN octet_length(v.html_body)<=$3 THEN v.html_body END,
 CASE WHEN octet_length(v.attachment_descriptors::text)<=$4 THEN v.attachment_descriptors END,v.body_complete,
 e.id,e.local_uid,e.visible_at,(e.consumed_at IS NOT NULL)`
const metadataColumns = messageHead + `CASE WHEN $3::bigint>0 THEN NULL::text END,NULL::text,CASE WHEN $4::bigint>0 THEN '[]'::jsonb END,false,e.id,e.local_uid,e.visible_at,(e.consumed_at IS NOT NULL)`
const entryFrom = ` FROM space.mailbox_entries e JOIN space.source_messages m ON m.source_id=e.source_id AND m.id=e.message_id
 JOIN space.mail_sources current_source ON current_source.id=m.source_id AND current_source.source_generation=m.source_generation
 LEFT JOIN space.content_objects o ON o.source_id=m.source_id AND o.object_key=m.object_key
 LEFT JOIN space.message_views v ON v.source_id=m.source_id AND v.message_id=m.id AND v.scope_address_id=0 `

type rowScanner interface{ Scan(...any) error }
type scanFunc func(...any) error

func (f scanFunc) Scan(v ...any) error { return f(v...) }

func (s *Service) scanMessage(row rowScanner, snapshot bool) (Message, error) {
	return s.scanMessageView(row, snapshot, true)
}
func (s *Service) scanMessageView(row rowScanner, snapshot, sanitize bool) (Message, error) {
	var out Message
	var sourceFrom, from, to, cc, attachments []byte
	var sent, viewSent, viewReceived, entry, uid, visible sql.NullInt64
	var viewKey, rfc, subject, text, html sql.NullString
	var complete sql.NullBool
	m := &out.Metadata
	e := row.Scan(&m.MessageID, &m.Remote.SourceGeneration, &m.Remote.Mailbox, &m.Remote.UIDValidity, &m.Remote.UID, &m.RFCMessageID, &m.Subject, &sourceFrom, &sent, &m.ReceivedAt, &m.ContentState, &m.RawState, &m.DeclaredBodySize, &m.DeclaredBodyTruncated, &m.Preview, &viewKey, &rfc, &subject, &from, &to, &cc, &viewSent, &viewReceived, &text, &html, &attachments, &complete, &entry, &uid, &visible, &m.Seen)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, ErrStorage
	}
	if len(sourceFrom) > descriptorBudget || json.Unmarshal(sourceFrom, &m.From) != nil {
		return out, ErrMetadata
	}
	if sent.Valid {
		x := sent.Int64
		m.SentAt = &x
	}
	if entry.Valid {
		m.EntryID = entry.Int64
		m.UID = uint32(uid.Int64)
		m.VisibleAt = visible.Int64
	}
	out.Attachments = []Attachment{}
	m.To = []Mailbox{}
	m.CC = []Mailbox{}
	if viewKey.Valid {
		if from == nil || len(from) > descriptorBudget || len(to) > descriptorBudget || len(cc) > descriptorBudget || json.Unmarshal(to, &m.To) != nil || json.Unmarshal(cc, &m.CC) != nil || attachments == nil || json.Unmarshal(attachments, &out.Attachments) != nil {
			return out, ErrMetadata
		}
		out.ViewKey = viewKey.String
		out.Text = text.String
		out.HTML = html.String
		out.BodyComplete = complete.Valid && complete.Bool && text.Valid && html.Valid
		if snapshot {
			if json.Unmarshal(from, &m.From) != nil {
				return out, ErrMetadata
			}
			m.RFCMessageID = rfc.String
			m.Subject = subject.String
			m.ReceivedAt = viewReceived.Int64
			m.SentAt = nil
			if viewSent.Valid {
				x := viewSent.Int64
				m.SentAt = &x
			}
		}
	}
	if m.From == nil {
		m.From = []Mailbox{}
	}
	if m.To == nil {
		m.To = []Mailbox{}
	}
	if m.CC == nil {
		m.CC = []Mailbox{}
	}
	// Imported historical views are untrusted HTML, even when body_complete.
	if sanitize && out.HTML != "" {
		safe, e := content.SafeFragment(out.HTML, s.options.Limits.BodyBytes)
		if e != nil {
			return Message{}, ErrBudget
		}
		out.HTML = safe
	}
	return out, nil
}

func (s *Service) Latest(ctx context.Context, lease *addressauth.Lease) (Snapshot, error) {
	return s.readLatest(ctx, lease, true)
}

// PublicLatest returns bounded stored HTML as JSON data for the published
// latest-mail contract. Rendering paths continue through sanitized Latest or
// RawMessage and must never interpolate this data into executable markup.
func (s *Service) PublicLatest(ctx context.Context, lease *addressauth.Lease) (Snapshot, error) {
	return s.readLatest(ctx, lease, false)
}
func (s *Service) readLatest(ctx context.Context, lease *addressauth.Lease, sanitize bool) (Snapshot, error) {
	id, e := s.allow(lease, addressauth.LatestRead, addressauth.MailRead)
	if e != nil {
		return Snapshot{}, e
	}
	if e = s.observe(ctx, id); e != nil {
		return Snapshot{}, e
	}
	return s.latestView(ctx, s.db, id, sanitize)
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Service) latest(ctx context.Context, q queryer, id addressauth.Identity) (Snapshot, error) {
	return s.latestView(ctx, q, id, true)
}
func (s *Service) latestView(ctx context.Context, q queryer, id addressauth.Identity, sanitize bool) (Snapshot, error) {
	var out Snapshot
	var selected, viewScope int64
	var consumed bool
	row := q.QueryRowContext(ctx, `SELECT `+messageColumns+`,a.selected_at,a.view_scope_address_id,(a.consumed_at IS NOT NULL OR EXISTS(SELECT 1 FROM space.consume_claims c WHERE c.source_id=a.source_id AND c.address_id=a.address_id AND c.source_generation=m.source_generation AND c.mailbox_name=m.mailbox_name AND c.uid_validity=m.uid_validity AND c.remote_uid=m.remote_uid)) FROM space.address_snapshots a JOIN space.source_messages m ON m.source_id=a.source_id AND m.id=a.message_id JOIN space.mail_sources current_source ON current_source.id=m.source_id AND current_source.source_generation=m.source_generation LEFT JOIN space.mailbox_entries e ON e.source_id=a.source_id AND e.address_id=a.address_id AND e.id=a.entry_id AND e.message_id=a.message_id LEFT JOIN space.content_objects o ON o.source_id=m.source_id AND o.object_key=m.object_key LEFT JOIN space.message_views v ON v.source_id=a.source_id AND v.message_id=a.message_id AND v.view_key=a.view_key AND v.scope_address_id=a.view_scope_address_id WHERE a.source_id=$1 AND a.address_id=$2 AND m.source_generation=$5`, id.SourceID, id.AddressID, s.options.Limits.BodyBytes, descriptorBudget, id.SourceGeneration)
	var e error
	out.Message, e = s.scanMessageView(scanFunc(func(v ...any) error { return row.Scan(append(v, &selected, &viewScope, &consumed)...) }), true, sanitize)
	if e != nil {
		return out, e
	}
	out.Ref = SnapshotRef{AuthGeneration: id.Generation, MessageID: out.Message.Metadata.MessageID, EntryID: out.Message.Metadata.EntryID, LocalUID: out.Message.Metadata.UID, LocalUIDValidity: id.UIDValidity, ViewKey: out.Message.ViewKey, ViewScopeAddressID: viewScope, SelectedAt: selected, Remote: out.Message.Metadata.Remote}
	out.Consumed = consumed
	return out, nil
}
func (s *Service) Recent(ctx context.Context, lease *addressauth.Lease) (Snapshot, error) {
	id, e := s.allow(lease, addressauth.MailRead, addressauth.LatestRead, addressauth.MailConsume, addressauth.RecentConsume)
	if e != nil {
		return Snapshot{}, e
	}
	if e = s.observe(ctx, id); e != nil {
		return Snapshot{}, e
	}
	snapshot, e := s.latest(ctx, s.db, id)
	if e != nil {
		return snapshot, e
	}
	lower := int64(math.MinInt64)
	now := s.options.Clock()
	if now >= math.MinInt64+int64(time.Hour) {
		lower = now - int64(time.Hour)
	}
	if snapshot.Consumed || snapshot.Message.Metadata.ReceivedAt < lower || snapshot.Message.Metadata.ReceivedAt > now || snapshot.Ref.Remote.SourceGeneration != id.SourceGeneration {
		return Snapshot{}, ErrNotFound
	}
	return snapshot, nil
}
func validCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func (s *Service) Codes(ctx context.Context, lease *addressauth.Lease, limit int) ([]Code, error) {
	return s.codes(ctx, lease, limit, false)
}

// PublicCodes uses the published received-time/message-ID ordering rather
// than the independently allocated mailbox UID and visibility time.
func (s *Service) PublicCodes(ctx context.Context, lease *addressauth.Lease, limit int) ([]Code, error) {
	return s.codes(ctx, lease, limit, true)
}
func (s *Service) codes(ctx context.Context, lease *addressauth.Lease, limit int, published bool) ([]Code, error) {
	id, e := s.allow(lease, addressauth.MailRead)
	if e != nil {
		return nil, e
	}
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	if e = s.observe(ctx, id); e != nil {
		return nil, e
	}
	projection, order := "e.visible_at", "e.visible_at DESC,e.local_uid DESC,e.id DESC"
	if published {
		projection, order = "m.received_at", "m.received_at DESC,m.id DESC"
	}
	rows, e := s.db.QueryContext(ctx, `SELECT e.retained_code,e.id,e.local_uid,`+projection+` FROM space.mailbox_entries e JOIN space.source_messages m ON m.source_id=e.source_id AND m.id=e.message_id JOIN space.mail_sources current_source ON current_source.id=m.source_id AND current_source.source_generation=m.source_generation WHERE e.source_id=$1 AND e.address_id=$2 AND m.source_generation=$4 AND e.retained_code ~ '^[0-9]{6}$' ORDER BY `+order+` LIMIT $3`, id.SourceID, id.AddressID, limit, id.SourceGeneration)
	if e != nil {
		return nil, storage(ctx)
	}
	defer rows.Close()
	out := []Code{}
	for rows.Next() {
		var c Code
		if rows.Scan(&c.Code, &c.EntryID, &c.UID, &c.ReceivedAt) != nil {
			return nil, ErrStorage
		}
		if !validCode(c.Code) {
			return nil, ErrMetadata
		}
		out = append(out, c)
	}
	if rows.Err() != nil {
		return nil, storage(ctx)
	}
	return out, nil
}
func (s *Service) List(ctx context.Context, lease *addressauth.Lease, page Page) (MessagePage, error) {
	id, e := s.allow(lease, addressauth.MailRead)
	if e != nil {
		return MessagePage{}, e
	}
	if e = s.observe(ctx, id); e != nil {
		return MessagePage{}, e
	}
	return s.list(ctx, id, page)
}

// Message returns an existing local UID's bounded stored view. It does not
// consume, select a new latest snapshot, fetch a remote body or mark Seen.
func (s *Service) Message(ctx context.Context, lease *addressauth.Lease, uid uint32) (Message, error) {
	id, err := s.allow(lease, addressauth.MailRead)
	if err != nil {
		return Message{}, err
	}
	if uid == 0 {
		return Message{}, ErrInvalid
	}
	return s.scanMessage(s.db.QueryRowContext(ctx, `SELECT `+messageColumns+entryFrom+`WHERE e.source_id=$1 AND e.address_id=$2 AND e.local_uid=$5 AND m.source_generation=$6`, id.SourceID, id.AddressID, s.options.Limits.BodyBytes, descriptorBudget, uid, id.SourceGeneration), false)
}
func (s *Service) list(ctx context.Context, id addressauth.Identity, page Page) (MessagePage, error) {
	return s.listOrdered(ctx, id, page, false)
}
func (s *Service) listOrdered(ctx context.Context, id addressauth.Identity, page Page, published bool) (MessagePage, error) {
	if page.Limit == 0 {
		page.Limit = 20
	}
	if page.Limit < 1 || page.Limit > 1000 || page.BeforeID < 0 || (page.BeforeTime == nil) != (page.BeforeID == 0) {
		return MessagePage{}, ErrInvalid
	}
	timeColumn, idColumn := "e.visible_at", "e.id"
	if published {
		timeColumn, idColumn = "m.received_at", "m.id"
	}
	rows, e := s.db.QueryContext(ctx, `SELECT `+metadataColumns+entryFrom+`WHERE e.source_id=$1 AND e.address_id=$2 AND m.source_generation=$8 AND ($5::bigint IS NULL OR (`+timeColumn+`,`+idColumn+`)<($5,$6)) ORDER BY `+timeColumn+` DESC,`+idColumn+` DESC LIMIT $7`, id.SourceID, id.AddressID, s.options.Limits.BodyBytes, descriptorBudget, page.BeforeTime, page.BeforeID, page.Limit+1, id.SourceGeneration)
	if e != nil {
		return MessagePage{}, storage(ctx)
	}
	defer rows.Close()
	out := MessagePage{Items: []Metadata{}}
	for rows.Next() {
		m, e := s.scanMessage(rows, false)
		if e != nil {
			return MessagePage{}, e
		}
		if len(out.Items) == page.Limit {
			out.More = true
			break
		}
		out.Items = append(out.Items, m.Metadata)
	}
	if rows.Err() != nil {
		return MessagePage{}, storage(ctx)
	}
	if out.More {
		last := out.Items[len(out.Items)-1]
		x := last.VisibleAt
		if published {
			x = last.ReceivedAt
		}
		out.NextTime = &x
		out.NextID = last.EntryID
		if published {
			out.NextID = last.MessageID
		}
	}
	return out, nil
}
func (s *Service) Status(ctx context.Context, lease *addressauth.Lease) (Status, error) {
	id, e := s.allow(lease, addressauth.IMAPLogin)
	if e != nil {
		return Status{}, e
	}
	var out Status
	e = s.db.QueryRowContext(ctx, `SELECT a.uid_validity,a.uid_next,count(e.id),coalesce(max(e.local_uid),0),count(e.id) FILTER(WHERE e.consumed_at IS NULL) FROM space.private_addresses a JOIN space.mail_sources current_source ON current_source.id=a.source_id AND current_source.source_generation=$3 LEFT JOIN (space.mailbox_entries e JOIN space.source_messages m ON m.source_id=e.source_id AND m.id=e.message_id AND m.source_generation=$3) ON e.source_id=a.source_id AND e.address_id=a.id WHERE a.source_id=$1 AND a.id=$2 GROUP BY a.id`, id.SourceID, id.AddressID, id.SourceGeneration).Scan(&out.UIDValidity, &out.UIDNext, &out.Messages, &out.HighestUID, &out.Unseen)
	if e != nil {
		return Status{}, storage(ctx)
	}
	if out.UIDValidity != id.UIDValidity {
		return Status{}, ErrStale
	}
	return out, nil
}

const uidSelectionSQL = `SELECT e.local_uid FROM space.mailbox_entries e JOIN space.source_messages m ON m.source_id=e.source_id AND m.id=e.message_id JOIN space.mail_sources current_source ON current_source.id=m.source_id AND current_source.source_generation=m.source_generation WHERE e.source_id=$1 AND e.address_id=$2 AND m.source_generation=$3`

// UIDSnapshot streams the selected mailbox's UID-only statement into the UID
// list that IMAP already retains for sequence mapping. Paging that same list
// adds a database round trip per thousand UIDs without bounding its final size.
func (s *Service) UIDSnapshot(ctx context.Context, lease *addressauth.Lease) ([]uint32, error) {
	id, e := s.allow(lease, addressauth.IMAPLogin)
	if e != nil {
		return nil, e
	}
	rows, e := s.db.QueryContext(ctx, uidSelectionSQL+` ORDER BY e.local_uid`, id.SourceID, id.AddressID, id.SourceGeneration)
	if e != nil {
		return nil, storage(ctx)
	}
	defer rows.Close()
	return scanUIDs(ctx, rows)
}

func (s *Service) UIDs(ctx context.Context, lease *addressauth.Lease, after uint32, limit int) ([]uint32, error) {
	id, e := s.allow(lease, addressauth.IMAPLogin)
	if e != nil {
		return nil, e
	}
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, uidSelectionSQL+` AND e.local_uid>$4 ORDER BY e.local_uid LIMIT $5`, id.SourceID, id.AddressID, id.SourceGeneration, after, limit)
	if e != nil {
		return nil, storage(ctx)
	}
	defer rows.Close()
	return scanUIDs(ctx, rows)
}

func scanUIDs(ctx context.Context, rows *sql.Rows) ([]uint32, error) {
	out := []uint32{}
	for rows.Next() {
		var uid uint32
		if rows.Scan(&uid) != nil {
			return nil, ErrStorage
		}
		out = append(out, uid)
	}
	if rows.Err() != nil {
		return nil, storage(ctx)
	}
	return out, nil
}
func (s *Service) Metadata(ctx context.Context, lease *addressauth.Lease, uids []uint32) ([]Metadata, error) {
	id, e := s.allow(lease, addressauth.IMAPLogin)
	if e != nil {
		return nil, e
	}
	if len(uids) > 1000 {
		return nil, ErrInvalid
	}
	out := []Metadata{}
	if len(uids) == 0 {
		return out, nil
	}
	for _, uid := range uids {
		if uid == 0 {
			return nil, ErrInvalid
		}
	}
	rows, e := s.db.QueryContext(ctx, `SELECT `+metadataColumns+entryFrom+`WHERE e.source_id=$1 AND e.address_id=$2 AND m.source_generation=$6 AND e.local_uid=ANY($5::bigint[]) ORDER BY e.local_uid`, id.SourceID, id.AddressID, s.options.Limits.BodyBytes, descriptorBudget, uids, id.SourceGeneration)
	if e != nil {
		return nil, storage(ctx)
	}
	defer rows.Close()
	for rows.Next() {
		m, e := s.scanMessage(rows, false)
		if e != nil {
			return nil, e
		}
		out = append(out, m.Metadata)
	}
	if rows.Err() != nil {
		return nil, storage(ctx)
	}
	return out, nil
}

func trimSnippet(m Message) string {
	if strings.TrimSpace(m.Text) != "" {
		return strings.TrimSpace(m.Text)
	}
	return strings.TrimSpace(m.Metadata.Preview)
}
