package accessimap

import (
	"bufio"
	"bytes"
	"io"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"
	"icloudspace/internal/mailview"
)

func inRange(value, start, stop, maximum uint32) bool {
	if start == 0 {
		start = maximum
	}
	if stop == 0 {
		stop = maximum
	}
	if start > stop {
		start, stop = stop, start
	}
	return value >= start && value <= stop
}
func selected(set imap.NumSet, seq, uid, count, highest uint32) bool {
	switch set := set.(type) {
	case imap.SeqSet:
		for _, r := range set {
			if inRange(seq, r.Start, r.Stop, count) {
				return true
			}
		}
	case imap.UIDSet:
		for _, r := range set {
			if inRange(uid, uint32(r.Start), uint32(r.Stop), highest) {
				return true
			}
		}
	}
	return false
}
func (s *session) Fetch(w *imapserver.FetchWriter, set imap.NumSet, options *imap.FetchOptions) error {
	lease, e := s.command(false)
	if e != nil {
		return e
	}
	if options.ModSeq || options.ChangedSince != 0 || imap.IsSearchRes(set) {
		return unsupported()
	}
	count, highest := uint32(len(s.uids)), uint32(0)
	if count > 0 {
		highest = s.uids[count-1]
	}
	for index, uid := range s.uids {
		seq := uint32(index + 1)
		if !selected(set, seq, uid, count, highest) {
			continue
		}
		rows, e := s.service.views.Metadata(s.ctx, lease, []uint32{uid})
		if e != nil {
			return cancelled(s.ctx)
		}
		if len(rows) == 0 {
			continue
		} // expunges are delivered at the permitted poll boundary
		meta := rows[0]
		needsBody := options.RFC822Size || options.Envelope || options.BodyStructure != nil || len(options.BodySection)+len(options.BinarySection)+len(options.BinarySectionSize) > 0
		var raw *mailview.Raw
		if needsBody {
			raw, e = s.service.views.IMAPRaw(s.ctx, lease, uid)
			if e != nil {
				return cancelled(s.ctx)
			}
		}
		e = writeMessage(w, seq, uid, meta, raw, options)
		if raw != nil {
			raw.Close()
		}
		if e != nil {
			return e
		}
	}
	return nil
}
func rawReader(raw *mailview.Raw) *io.SectionReader {
	return io.NewSectionReader(raw.Reader, 0, raw.ByteSize)
}
func bounds(size int64, partial *imap.SectionPartial) (int64, int64) {
	if partial == nil {
		return 0, size
	}
	offset := max(int64(0), min(size, partial.Offset))
	return offset, min(size-offset, max(int64(0), partial.Size))
}
func writeLiteral(dst io.WriteCloser, src io.Reader) error {
	_, e := io.Copy(dst, src)
	closeErr := dst.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func writeMessage(w *imapserver.FetchWriter, seq, uid uint32, meta mailview.Metadata, raw *mailview.Raw, options *imap.FetchOptions) error {
	response := w.CreateMessage(seq)
	if options.UID {
		response.WriteUID(imap.UID(uid))
	}
	if options.Flags {
		flags := []imap.Flag{}
		if meta.Seen {
			flags = append(flags, imap.FlagSeen)
		}
		response.WriteFlags(flags)
	}
	if options.InternalDate {
		response.WriteInternalDate(time.Unix(0, meta.ReceivedAt))
	}
	if options.RFC822Size {
		response.WriteRFC822Size(raw.ByteSize)
	}
	if options.Envelope {
		header, e := textproto.ReadHeader(bufio.NewReader(rawReader(raw)))
		if e != nil {
			response.Close()
			return e
		}
		response.WriteEnvelope(imapserver.ExtractEnvelope(header))
	}
	if options.BodyStructure != nil {
		response.WriteBodyStructure(imapserver.ExtractBodyStructure(rawReader(raw)))
	}
	for _, item := range options.BodySection {
		if len(item.Part) == 0 && item.Specifier == imap.PartSpecifierNone && len(item.HeaderFields)+len(item.HeaderFieldsNot) == 0 {
			offset, size := bounds(raw.ByteSize, item.Partial)
			if e := writeLiteral(response.WriteBodySection(item, size), io.NewSectionReader(raw.Reader, offset, size)); e != nil {
				response.Close()
				return e
			}
			continue
		}
		copyItem := *item
		copyItem.Partial = nil
		data := imapserver.ExtractBodySection(rawReader(raw), &copyItem)
		offset, size := bounds(int64(len(data)), item.Partial)
		if e := writeLiteral(response.WriteBodySection(item, size), bytes.NewReader(data[offset:offset+size])); e != nil {
			response.Close()
			return e
		}
	}
	for _, item := range options.BinarySection {
		copyItem := *item
		copyItem.Partial = nil
		data := imapserver.ExtractBinarySection(rawReader(raw), &copyItem)
		offset, size := bounds(int64(len(data)), item.Partial)
		if e := writeLiteral(response.WriteBinarySection(item, size), bytes.NewReader(data[offset:offset+size])); e != nil {
			response.Close()
			return e
		}
	}
	for _, item := range options.BinarySectionSize {
		data := imapserver.ExtractBinarySection(rawReader(raw), &imap.FetchItemBinarySection{Part: item.Part})
		response.WriteBinarySectionSize(item, uint32(len(data)))
	}
	return response.Close()
}
