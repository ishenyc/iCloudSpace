package applemail

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
	"strings"

	"icloudspace/internal/content"
	"icloudspace/internal/mailout"
	"icloudspace/internal/provider/apple"
	upstream "icloudspace/internal/provider/imap"
)

// These reads borrow the send's source gate and the application's existing
// IMAP pool. They never ingest, change flags, acquire another source, or write.
func (o *operation) readMailbox(ctx context.Context, route mailout.Route, folder string, read func(*upstream.Lease) error) error {
	writer := o.provider.config.Drafts
	if writer == nil || writer.config.ReadPool == nil {
		return mailout.ErrReference
	}
	client, err := o.client()
	if err != nil {
		return err
	}
	mailbox, err := o.mailbox(client, route)
	if err != nil {
		return err
	}
	endpoint, err := writer.config.Credentials(ctx, mailbox)
	if err != nil {
		return err
	}
	local := strings.SplitN(mailbox.Address, "@", 2)[0]
	if endpoint.Host != "imap.mail.me.com" || endpoint.Port != 993 || !same(endpoint.Username, mailbox.Address) && !same(endpoint.Username, local) || !safe(endpoint.Password, 4096) {
		return mailout.ErrIneligible
	}
	permit, err := writer.config.AcquireSlot(ctx, o.scope.Gate)
	if err != nil {
		return err
	}
	if permit == nil {
		return mailout.ErrInvalid
	}
	defer permit.Close()
	bounded, cancel := context.WithTimeout(ctx, writer.config.Timeout)
	defer cancel()
	lease, err := writer.config.ReadPool.Acquire(bounded, upstream.Endpoint{Host: endpoint.Host, Port: endpoint.Port, Username: endpoint.Username, Password: endpoint.Password}, upstream.Scope{SourceID: o.scope.Source.ID, SourceGeneration: o.scope.Source.Generation, CredentialGeneration: o.scope.Source.CredentialGeneration}, folder)
	if err != nil {
		return err
	}
	defer lease.Release()
	return read(lease)
}
func (o *operation) nativeMailbox() bool {
	return o.scope.Source.Kind == "apple_direct" && o.provider.config.Drafts != nil && o.provider.config.Drafts.config.ReadPool != nil
}

// Read the exact, already-verified draft without Seen changes. SMTP uses the
// stored MIME and original Message-ID rather than fabricating another seed.
func (o *operation) nativeSeedRaw(ctx context.Context, route mailout.Route, candidate mailout.Candidate) ([]byte, error) {
	var raw []byte
	err := o.readMailbox(ctx, route, "Drafts", func(lease *upstream.Lease) error {
		if lease.Snapshot().UIDValidity != candidate.UIDValidity || candidate.UID == 0 {
			return mailout.ErrReference
		}
		return lease.StreamRawBatchWithLimit(ctx, candidate.UIDValidity, []uint32{candidate.UID}, 64<<10, func(_ uint32, reader io.Reader) error {
			var err error
			raw, err = io.ReadAll(io.LimitReader(reader, (64<<10)+1))
			if len(raw) > 64<<10 {
				return mailout.ErrReference
			}
			return err
		})
	})
	if err != nil {
		clear(raw)
		return nil, err
	}
	return raw, nil
}

func (o *operation) nativeCandidate(ctx context.Context, route mailout.Route, e mailout.Evidence) (candidate mailout.Candidate, found bool, err error) {
	err = o.readMailbox(ctx, route, "Drafts", func(lease *upstream.Lease) error {
		epoch := lease.Snapshot().UIDValidity
		if e.CandidateUIDValidity != 0 && epoch != e.CandidateUIDValidity {
			return mailout.ErrReference
		}
		var ids []uint32
		if e.CandidateID != "" {
			guid, ok := canonicalGUID(e.CandidateID)
			folder, uid, valid := apple.MailGUID(guid)
			if !ok || !valid || !same(folder, "Drafts") {
				return mailout.ErrReference
			}
			ids = []uint32{uid}
		} else {
			var searchErr error
			ids, searchErr = lease.SearchHeader(ctx, epoch, "Subject", e.Nonce, 4)
			if searchErr != nil {
				return searchErr
			}
		}
		for _, uid := range ids {
			var parsed *content.Message
			readErr := lease.StreamRawBatchWithLimit(ctx, epoch, []uint32{uid}, 64<<10, func(_ uint32, r io.Reader) error {
				var parseErr error
				parsed, parseErr = content.Parse(r, content.Limits{MessageBytes: 64 << 10, HeaderBytes: 16 << 10, BodyBytes: 32 << 10, AttachmentBytes: 1, Parts: 2, Depth: 2, Addresses: 8, Attachments: 1})
				return parseErr
			})
			if readErr != nil {
				return readErr
			}
			if parsed == nil || !parsed.Complete || !parsed.HeaderComplete || !parsed.BodyComplete || len(parsed.Attachments) != 0 {
				continue
			}
			message, parseErr := mail.ReadMessage(bytes.NewReader(parsed.RawHeader))
			if parseErr != nil {
				continue
			}
			h := textproto.MIMEHeader(message.Header)
			if !nonceMatch(h, e.Nonce) || !exactAddress(h, "From", route.ProviderFrom) || !exactAddress(h, "To", route.Alias) || !exactAddress(h, "Reply-To", route.Recipient) || len(h.Values("Cc")) != 0 || len(h.Values("Bcc")) != 0 {
				continue
			}
			rejected := false
			for k := range h {
				if strings.HasPrefix(strings.ToLower(k), "resent-") {
					rejected = true
				}
			}
			if rejected {
				continue
			}
			if e.Draft != nil && (!draftMarker(h, e.Nonce) || strings.TrimSpace(parsed.Text) != strings.TrimSpace(e.Draft.Text)) {
				continue
			}
			id := messageID(h)
			if id == "" || e.CandidateMessageID != "" && e.CandidateMessageID != id {
				continue
			}
			if found {
				return mailout.ErrReference
			}
			candidate = mailout.Candidate{ID: fmt.Sprintf("message:Drafts/%d", uid), UID: uid, UIDValidity: epoch, MessageID: id, Nonce: e.Nonce}
			if e.CandidateID != "" {
				candidate.ID = e.CandidateID
			}
			found = true
		}
		return lease.ValidateSelection(ctx, epoch)
	})
	// SMTP submits this verified IMAP MIME directly. Only the legacy WebMail
	// draft sender needs a second proof that its WebMail draft GUID is visible.
	if err == nil && found && !o.usesSMTP() {
		client, clientErr := o.client()
		if clientErr != nil {
			return candidate, false, clientErr
		}
		guid, ok := canonicalGUID(candidate.ID)
		if !ok {
			return candidate, false, mailout.ErrReference
		}
		message, readErr := client.MailGet(ctx, guid)
		if readErr != nil {
			return candidate, false, o.checkpoint(ctx, readErr)
		}
		header, headerErr := headers(message)
		if headerErr != nil || !nonceMatch(header, e.Nonce) || messageID(header) != candidate.MessageID || !exactAddress(header, "From", route.ProviderFrom) || !exactAddress(header, "To", route.Alias) || !exactAddress(header, "Reply-To", route.Recipient) {
			return candidate, false, mailout.ErrReference
		}
		epoch, epochErr := client.MailUIDValidity(ctx, "Drafts")
		if epochErr != nil {
			return candidate, false, o.checkpoint(ctx, epochErr)
		}
		if epoch != candidate.UIDValidity {
			return candidate, false, mailout.ErrReference
		}
	}
	return
}

type seedMailboxHint struct {
	folder string
	mailout.RemoteHint
}

func (o *operation) nativeSeeds(ctx context.Context, route mailout.Route, e mailout.Evidence) ([]seedMailboxHint, error) {
	for _, folder := range []string{"INBOX", "Junk"} {
		hints, err := o.nativeSeedFolder(ctx, route, e, folder)
		if err != nil || len(hints) != 0 {
			return hints, err
		}
	}
	return nil, nil
}

func (o *operation) nativeSeedFolder(ctx context.Context, route mailout.Route, e mailout.Evidence, folder string) (hints []seedMailboxHint, err error) {
	err = o.readMailbox(ctx, route, folder, func(lease *upstream.Lease) error {
		epoch := lease.Snapshot().UIDValidity
		ids, err := lease.SearchHeader(ctx, epoch, "Subject", e.Nonce, 4)
		if err != nil || len(ids) == 0 {
			return err
		}
		rows, err := lease.Headers(ctx, epoch, ids)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if !row.Complete || row.Truncated {
				continue
			}
			message, err := mail.ReadMessage(bytes.NewReader(row.RawHeader))
			if err != nil {
				continue
			}
			header := textproto.MIMEHeader(message.Header)
			if !nonceMatch(header, e.Nonce) || !hmeAlias(header, route, route.ProviderFrom) || messageID(header) == "" || !relayForRecipient(one(header, "Reply-To"), route.Recipient) {
				continue
			}
			hints = append(hints, seedMailboxHint{folder: folder, RemoteHint: mailout.RemoteHint{UIDValidity: epoch, UID: row.UID}})
		}
		if len(hints) > 1 {
			return mailout.ErrReference
		}
		return lease.ValidateSelection(ctx, epoch)
	})
	return
}
