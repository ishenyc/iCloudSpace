package accessimap

import (
	"bufio"
	"io"
	"mime"
	netmail "net/mail"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	gomessage "github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
	"icloudspace/internal/mailview"
)

type searchMessage struct {
	meta                mailview.Metadata
	seq, count, highest uint32
	size                int64
	header              textproto.Header
	body, text          string
	sent                time.Time
}

func invalidSearch(c *imap.SearchCriteria) bool {
	if c.ModSeq != nil {
		return true
	}
	for i := range c.Not {
		if invalidSearch(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if invalidSearch(&c.Or[i][0]) || invalidSearch(&c.Or[i][1]) {
			return true
		}
	}
	return false
}
func searchNeedsRaw(c *imap.SearchCriteria) (header, body bool) {
	header = len(c.Header) > 0 || !c.SentSince.IsZero() || !c.SentBefore.IsZero()
	body = len(c.Body)+len(c.Text) > 0
	if len(c.Text) > 0 {
		header = true
	}
	for i := range c.Not {
		h, b := searchNeedsRaw(&c.Not[i])
		header = header || h
		body = body || b
	}
	for i := range c.Or {
		for j := 0; j < 2; j++ {
			h, b := searchNeedsRaw(&c.Or[i][j])
			header = header || h
			body = body || b
		}
	}
	return
}
func searchNeedsSize(c *imap.SearchCriteria) bool {
	if c.Larger > 0 || c.Smaller > 0 {
		return true
	}
	for i := range c.Not {
		if searchNeedsSize(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if searchNeedsSize(&c.Or[i][0]) || searchNeedsSize(&c.Or[i][1]) {
			return true
		}
	}
	return false
}
func day(t time.Time) time.Time { y, m, d := t.Date(); return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }
func dateMatch(value, since, before time.Time) bool {
	if value.IsZero() {
		return since.IsZero() && before.IsZero()
	}
	v := day(value)
	return (since.IsZero() || !v.Before(day(since))) && (before.IsZero() || v.Before(day(before)))
}
func contains(value, part string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(part))
}
func (m *searchMessage) match(c *imap.SearchCriteria) bool {
	for _, set := range c.SeqNum {
		if !selected(set, m.seq, m.meta.UID, m.count, m.highest) {
			return false
		}
	}
	for _, set := range c.UID {
		if !selected(set, m.seq, m.meta.UID, m.count, m.highest) {
			return false
		}
	}
	if !dateMatch(time.Unix(0, m.meta.ReceivedAt), c.Since, c.Before) || !dateMatch(m.sent, c.SentSince, c.SentBefore) {
		return false
	}
	for _, f := range c.Flag {
		if f != imap.FlagSeen || !m.meta.Seen {
			return false
		}
	}
	for _, f := range c.NotFlag {
		if f == imap.FlagSeen && m.meta.Seen {
			return false
		}
	}
	if c.Larger > 0 && m.size <= c.Larger || c.Smaller > 0 && m.size >= c.Smaller {
		return false
	}
	decoder := new(mime.WordDecoder)
	for _, h := range c.Header {
		matched := false
		for fields := m.header.FieldsByKey(h.Key); fields.Next(); {
			value := fields.Value()
			if decoded, e := decoder.DecodeHeader(value); e == nil {
				value = decoded
			}
			if contains(value, h.Value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, text := range c.Body {
		if !contains(m.body, text) {
			return false
		}
	}
	for _, text := range c.Text {
		if !contains(m.text, text) {
			return false
		}
	}
	for i := range c.Not {
		if m.match(&c.Not[i]) {
			return false
		}
	}
	for i := range c.Or {
		if !m.match(&c.Or[i][0]) && !m.match(&c.Or[i][1]) {
			return false
		}
	}
	return true
}
func (s *session) Search(kind imapserver.NumKind, c *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	lease, e := s.command(false)
	if e != nil {
		return nil, e
	}
	if invalidSearch(c) || options.ReturnSave {
		return nil, unsupported()
	}
	needHeader, needBody := searchNeedsRaw(c)
	needSize := searchNeedsSize(c)
	var seqSet imap.SeqSet
	var uidSet imap.UIDSet
	data := new(imap.SearchData)
	count, highest := uint32(len(s.uids)), uint32(0)
	if count > 0 {
		highest = s.uids[count-1]
	}
	for start := 0; start < len(s.uids); start += 1000 {
		end := min(start+1000, len(s.uids))
		rows, e := s.service.views.Metadata(s.ctx, lease, s.uids[start:end])
		if e != nil {
			return nil, cancelled(s.ctx)
		}
		byUID := make(map[uint32]mailview.Metadata, len(rows))
		for _, m := range rows {
			byUID[m.UID] = m
		}
		for i := start; i < end; i++ {
			meta, exists := byUID[s.uids[i]]
			if !exists {
				continue
			}
			m := searchMessage{meta: meta, seq: uint32(i + 1), count: count, highest: highest}
			if needHeader || needBody || needSize {
				raw, e := s.service.views.IMAPRaw(s.ctx, lease, meta.UID)
				if e != nil {
					return nil, cancelled(s.ctx)
				}
				m.size = raw.ByteSize
				if needHeader || needBody {
					br := bufio.NewReader(rawReader(raw))
					m.header, e = textproto.ReadHeader(br)
					if e == nil {
						m.sent, _ = netmail.ParseDate(m.header.Get("Date"))
					}
					if e == nil && needBody {
						reader, readErr := mail.CreateReader(rawReader(raw))
						if gomessage.IsUnknownCharset(readErr) {
							readErr = nil
						}
						if readErr == nil {
							var body strings.Builder
							for {
								part, partErr := reader.NextPart()
								if gomessage.IsUnknownCharset(partErr) {
									partErr = nil
								}
								if partErr == io.EOF {
									break
								}
								if partErr != nil {
									readErr = partErr
									break
								}
								if _, readErr = io.Copy(&body, part.Body); readErr != nil {
									break
								}
								body.WriteByte('\n')
							}
							reader.Close()
							m.body = body.String()
							if readErr != nil {
								e = readErr
							}
						}
						if readErr != nil {
							e = readErr
						}
					}
					var text strings.Builder
					for fields := m.header.Fields(); fields.Next(); {
						value := fields.Value()
						if decoded, de := new(mime.WordDecoder).DecodeHeader(value); de == nil {
							value = decoded
						}
						text.WriteString(fields.Key() + ": " + value + "\n")
					}
					text.WriteString(m.body)
					m.text = text.String()
				}
				raw.Close()
				if e != nil {
					return nil, cancelled(s.ctx)
				}
			}
			if !m.match(c) {
				continue
			}
			n := m.seq
			if kind == imapserver.NumKindUID {
				n = meta.UID
				uidSet.AddNum(imap.UID(n))
			} else {
				seqSet.AddNum(n)
			}
			data.Count++
			if data.Min == 0 || n < data.Min {
				data.Min = n
			}
			if n > data.Max {
				data.Max = n
			}
		}
	}
	if kind == imapserver.NumKindUID {
		data.All = uidSet
	} else {
		data.All = seqSet
	}
	return data, nil
}
