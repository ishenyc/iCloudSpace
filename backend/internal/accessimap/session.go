package accessimap

import (
	"context"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-sasl"
	"icloudspace/internal/addressauth"
	"icloudspace/internal/mailview"
	"math"
	"strings"
	"time"
)

type session struct {
	service                 *Service
	wire                    *secureWire
	ctx                     context.Context
	handle                  addressauth.Handle
	authenticated, selected bool
	uids                    []uint32
	uidNext                 uint64
	uidValidity             int64
}

func readOnly() error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: "READ-ONLY", Text: "Mailbox is read-only"}
}
func noMailbox() error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "Only INBOX exists"}
}
func exhausted() error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: "LIMIT", Text: "Mailbox UID space is exhausted"}
}
func (s *session) Close() error {
	defer s.service.sessionDone(s.wire)
	s.wire.release(nil)
	s.wire.cancel()
	s.handle = addressauth.Handle{}
	return nil
}
func (s *session) Login(user, password string) error {
	return s.login(user, password, addressauth.IMAPPassword)
}
func (s *session) login(user, raw string, kind addressauth.Kind) error {
	if s.authenticated {
		return imapserver.ErrAuthFailed
	}
	if e := s.wire.SetReadDeadline(time.Time{}); e != nil {
		return e
	}
	lease, e := s.service.authority.Authenticate(s.ctx, addressauth.Credential{Kind: kind, Raw: raw}, addressauth.IMAPLogin, addressauth.Selector{Email: user})
	if e != nil {
		return imapserver.ErrAuthFailed
	}
	s.handle = lease.Handle()
	s.authenticated = true
	s.wire.attach(lease, false)
	return nil
}
func (s *session) AuthenticateMechanisms() []string { return []string{"XOAUTH2"} }
func (s *session) Authenticate(mechanism string) (sasl.Server, error) {
	if mechanism != "XOAUTH2" || s.authenticated {
		return nil, imapserver.ErrAuthFailed
	}
	return newXOAUTH2Server(func(user, token string) error { return s.login(user, token, addressauth.Access) }), nil
}
func (s *session) command(selecting bool) (*addressauth.Lease, error) {
	// The SDK has parsed a complete command. Its 30-second input deadline
	// must not cancel a slow repository operation through the EOF pump.
	// The SDK restores input deadlines after the tagged response; IDLE uses
	// commandLease directly so its separate DONE deadline remains intact.
	if e := s.wire.SetReadDeadline(time.Time{}); e != nil {
		return nil, e
	}
	return s.commandLease(selecting)
}
func (s *session) commandLease(selecting bool) (*addressauth.Lease, error) {
	if !s.authenticated {
		return nil, imapserver.ErrAuthFailed
	}
	if active := s.wire.active(); active != nil && active.ValidFor(s.service.authority) {
		if selecting {
			s.wire.attach(active, true)
		}
		return active, nil
	}
	lease, e := s.service.authority.Renew(s.ctx, s.handle, addressauth.IMAPLogin)
	if e != nil {
		return nil, imapserver.ErrAuthFailed
	}
	s.wire.attach(lease, selecting)
	return lease, nil
}
func (s *session) loadUIDs(lease *addressauth.Lease) ([]uint32, error) {
	uids, e := s.service.views.UIDSnapshot(s.ctx, lease)
	if e != nil {
		return nil, cancelled(s.ctx)
	}
	return uids, nil
}
func (s *session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	lease, e := s.command(true)
	if e != nil {
		return nil, e
	}
	if !strings.EqualFold(mailbox, "INBOX") {
		return nil, noMailbox()
	}
	if options != nil && options.CondStore {
		return nil, unsupported()
	}
	before, e := s.service.views.PollMetadata(s.ctx, lease)
	if e != nil {
		return nil, cancelled(s.ctx)
	}
	uids, e := s.loadUIDs(lease)
	if e != nil {
		return nil, e
	}
	// Read the monotonic high-water after obtaining the UID snapshot. An intake
	// commit between the two reads must never advertise UIDNEXT below a UID we
	// already selected. Later appends are reported by Poll.
	status, e := s.service.views.PollMetadata(s.ctx, lease)
	if e != nil {
		return nil, cancelled(s.ctx)
	}
	if status.UIDNext > math.MaxUint32 {
		return nil, exhausted()
	}
	s.uids = uids
	s.selected = true
	// The returned high water is current, while the cache records only what
	// preceded the UID walk. If intake committed during that walk, the next
	// Poll must reconcile it even when SELECT advertised the newer UIDNEXT.
	s.uidNext = before.UIDNext
	s.uidValidity = status.UIDValidity
	return &imap.SelectData{Flags: []imap.Flag{imap.FlagSeen}, PermanentFlags: []imap.Flag{}, NumMessages: uint32(len(uids)), UIDValidity: uint32(status.UIDValidity), UIDNext: imap.UID(status.UIDNext)}, nil
}
func (s *session) Unselect() error {
	if _, e := s.command(false); e != nil {
		return e
	}
	s.selected = false
	s.uids = nil
	return nil
}
func (s *session) Namespace() (*imap.NamespaceData, error) {
	if _, e := s.command(false); e != nil {
		return nil, e
	}
	return &imap.NamespaceData{Personal: []imap.NamespaceDescriptor{{Prefix: "", Delim: '/'}}}, nil
}
func (s *session) List(w *imapserver.ListWriter, reference string, patterns []string, options *imap.ListOptions) error {
	if _, e := s.command(false); e != nil {
		return e
	}
	for _, pattern := range patterns {
		if pattern == "" {
			return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: '/', Mailbox: ""})
		}
		if imapserver.MatchList("INBOX", '/', reference, pattern) {
			return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoInferiors}, Delim: '/', Mailbox: "INBOX"})
		}
	}
	return nil
}
func (s *session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	lease, e := s.command(false)
	if e != nil {
		return nil, e
	}
	if !strings.EqualFold(mailbox, "INBOX") {
		return nil, noMailbox()
	}
	if options.HighestModSeq {
		return nil, unsupported()
	}
	status, e := s.service.views.Status(s.ctx, lease)
	if e != nil {
		return nil, cancelled(s.ctx)
	}
	if options.UIDNext && status.UIDNext > math.MaxUint32 {
		return nil, exhausted()
	}
	messages, unseen, zero := uint32(status.Messages), uint32(status.Unseen), uint32(0)
	data := &imap.StatusData{Mailbox: "INBOX", NumMessages: &messages, NumUnseen: &unseen, NumRecent: &zero, NumDeleted: &zero, UIDValidity: uint32(status.UIDValidity), AppendLimit: &zero}
	if status.UIDNext <= math.MaxUint32 {
		data.UIDNext = imap.UID(status.UIDNext)
	}
	if options.Size {
		uids, e := s.loadUIDs(lease)
		if e != nil {
			return nil, e
		}
		var size int64
		for _, uid := range uids {
			body, e := s.service.views.IMAPRaw(s.ctx, lease, uid)
			if e != nil {
				return nil, cancelled(s.ctx)
			}
			size += body.ByteSize
			body.Close()
		}
		data.Size = &size
	}
	return data, nil
}
func (s *session) poll(w *imapserver.UpdateWriter, allowExpunge bool, lease *addressauth.Lease, freshAdmission bool) error {
	if !s.selected {
		return nil
	}
	var status mailview.PollMetadata
	if freshAdmission {
		next, ok := lease.InitialUIDNext(s.service.authority)
		if !ok || next < 1 || next > 4294967296 {
			return imapserver.ErrAuthFailed
		}
		status = mailview.PollMetadata{UIDValidity: lease.Identity().UIDValidity, UIDNext: next}
	} else {
		var e error
		status, e = s.service.views.PollMetadata(s.ctx, lease)
		if e != nil {
			return cancelled(s.ctx)
		}
	}
	if status.UIDValidity != s.uidValidity {
		return imapserver.ErrAuthFailed
	}
	if status.UIDNext == s.uidNext {
		return nil
	}
	if status.UIDNext < s.uidNext {
		return imapserver.ErrAuthFailed
	}
	current, e := s.loadUIDs(lease)
	if e != nil {
		return e
	}
	previousCount := len(s.uids)
	if allowExpunge {
		present := make(map[uint32]bool, len(current))
		for _, uid := range current {
			present[uid] = true
		}
		for i := len(s.uids) - 1; i >= 0; i-- {
			if !present[s.uids[i]] {
				if e = w.WriteExpunge(uint32(i + 1)); e != nil {
					return e
				}
			}
		}
		s.uids = current
	} else {
		known := map[uint32]bool{}
		for _, uid := range s.uids {
			known[uid] = true
		}
		for _, uid := range current {
			if !known[uid] {
				s.uids = append(s.uids, uid)
			}
		}
	}
	s.uidNext = status.UIDNext
	if previousCount == len(s.uids) {
		return nil
	}
	return w.WriteNumMessages(uint32(len(s.uids)))
}
func (s *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if !s.authenticated {
		return nil
	}
	active := s.wire.active()
	freshAdmission := active == nil || !active.ValidFor(s.service.authority)
	lease, e := s.command(false)
	if e != nil {
		return e
	}
	return s.poll(w, allowExpunge, lease, freshAdmission)
}
func (s *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	ticker := time.NewTicker(s.service.poll)
	defer ticker.Stop()
	for {
		active := s.wire.active()
		freshAdmission := active == nil || !active.ValidFor(s.service.authority)
		lease, e := s.commandLease(false)
		if e != nil {
			// The pinned SDK waits for DONE before observing Idle's returned
			// error. Close the wire so revoked/invalid sessions stop now and
			// the SDK's blocked read and session lifecycle can both finish.
			_ = s.wire.Close()
			return e
		}
		e = s.poll(w, true, lease, freshAdmission)
		s.wire.release(lease)
		if e != nil {
			_ = s.wire.Close()
			return e
		}
		select {
		case <-stop:
			return nil
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-ticker.C:
		}
	}
}
func (s *session) reject() error {
	// APPEND reaches this read-only rejection before its literal is drained.
	// Keep the SDK's input deadline while it discards those remaining bytes.
	if _, e := s.commandLease(false); e != nil {
		return e
	}
	return readOnly()
}
func (s *session) Create(string, *imap.CreateOptions) error         { return s.reject() }
func (s *session) Delete(string) error                              { return s.reject() }
func (s *session) Rename(string, string, *imap.RenameOptions) error { return s.reject() }
func (s *session) Subscribe(string) error                           { return s.reject() }
func (s *session) Unsubscribe(string) error                         { return s.reject() }
func (s *session) Append(string, imap.LiteralReader, *imap.AppendOptions) (*imap.AppendData, error) {
	return nil, s.reject()
}
func (s *session) Expunge(*imapserver.ExpungeWriter, *imap.UIDSet) error { return s.reject() }
func (s *session) Store(*imapserver.FetchWriter, imap.NumSet, *imap.StoreFlags, *imap.StoreOptions) error {
	return s.reject()
}
func (s *session) Copy(imap.NumSet, string) (*imap.CopyData, error)       { return nil, s.reject() }
func (s *session) Move(*imapserver.MoveWriter, imap.NumSet, string) error { return s.reject() }
func unsupported() error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: "CANNOT", Text: "Extension is not supported"}
}

var _ imapserver.Session = (*session)(nil)
