package applemail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	protocol "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"icloudspace/internal/mailout"
	"icloudspace/internal/provider/apple"
	upstream "icloudspace/internal/provider/imap"
	"icloudspace/internal/sourceguard"
)

// AppleMailbox is the authenticated WebMail principal, never the forwarded
// receiving namespace. Credentials must resolve this exact Apple mailbox.
type AppleMailbox struct {
	SourceID, PrincipalRevision int64
	AppleID, DSID, Address      string
}
type DraftEndpoint struct {
	Host               string
	Port               uint16
	Username, Password string
}

func (DraftEndpoint) String() string   { return "applemail: private draft endpoint" }
func (DraftEndpoint) GoString() string { return "applemail: private draft endpoint" }

type DraftConfig struct {
	ReadPool    *upstream.Pool
	Credentials func(context.Context, AppleMailbox) (DraftEndpoint, error)
	AcquireSlot func(context.Context, *sourceguard.Lease) (io.Closer, error)
	TLSConfig   *tls.Config
	DialContext func(context.Context, string, string) (net.Conn, error)
	Timeout     time.Duration
}
type DraftWriter struct{ config DraftConfig }

func NewDraftWriter(config DraftConfig) (*DraftWriter, error) {
	if config.Credentials == nil || config.AcquireSlot == nil || config.TLSConfig != nil && config.TLSConfig.InsecureSkipVerify {
		return nil, mailout.ErrInvalid
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < time.Millisecond || config.Timeout > time.Minute {
		return nil, mailout.ErrInvalid
	}
	if config.DialContext == nil {
		config.DialContext = (&net.Dialer{Timeout: config.Timeout}).DialContext
	}
	if config.TLSConfig != nil {
		config.TLSConfig = config.TLSConfig.Clone()
	}
	return &DraftWriter{config: config}, nil
}

type DraftError struct {
	Stage   string
	Unknown bool
	cause   error
}

func (e *DraftError) Error() string                         { return "applemail: draft " + e.Stage + " failed" }
func (e *DraftError) Unwrap() error                         { return e.cause }
func (e *DraftError) SafeDiagnostic() (string, int, string) { return e.Stage, 0, "" }
func draftError(stage string, err error, unknown bool) *DraftError {
	e := &DraftError{Stage: stage, Unknown: unknown}
	if errors.Is(err, context.Canceled) {
		e.cause = context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		e.cause = context.DeadlineExceeded
	}
	return e
}
func (o *operation) mailbox(client *apple.Client, route mailout.Route) (AppleMailbox, error) {
	p := client.Snapshot().Principal
	mailAddress, err := ownerAddress(p)
	if err != nil || p.DSID == "" || o.scope.Source.Kind != "apple_direct" || !same(route.ProviderFrom, mailAddress) {
		return AppleMailbox{}, mailout.ErrIneligible
	}
	return AppleMailbox{SourceID: o.scope.Source.ID, PrincipalRevision: o.scope.Source.PrincipalRevision, AppleID: p.AppleID, DSID: p.DSID, Address: mailAddress}, nil
}
func ownerAddress(p apple.Principal) (string, error) {
	value, err := address(p.PrimaryEmail)
	if err != nil || !appleAddress(value) {
		value, err = address(p.AppleID)
	}
	if err != nil || !appleAddress(value) {
		return "", mailout.ErrIneligible
	}
	return value, nil
}
func appleAddress(raw string) bool {
	_, domain, ok := strings.Cut(raw, "@")
	return ok && (domain == "icloud.com" || domain == "me.com" || domain == "mac.com")
}
func draftMIME(mailbox AppleMailbox, route mailout.Route, plan mailout.BootstrapPlan, at time.Time) ([]byte, error) {
	if !safe(plan.Nonce, 256) || !safe(plan.OwnerKey, 256) || !safe(plan.ContextKey, 1024) || !same(plan.Draft.From, mailbox.Address) || !same(plan.Draft.To, route.Alias) || !same(plan.Draft.ReplyTo, route.Recipient) || plan.Draft.Subject != plan.Nonce || len(plan.Draft.Text) > 32<<10 || plan.Draft.Text == "" {
		return nil, mailout.ErrInvalid
	}
	for _, c := range plan.Nonce {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return nil, mailout.ErrInvalid
		}
	}
	from, err := address(mailbox.Address)
	if err != nil {
		return nil, err
	}
	to, err := address(route.Alias)
	if err != nil {
		return nil, err
	}
	reply, err := address(route.Recipient)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, value := range []byte(plan.Draft.Text) {
		if value >= 128 {
			return nil, mailout.ErrInvalid
		}
	}
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nReply-To: %s\r\nMessage-ID: <%s@icloud.com>\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n", from, to, reply, plan.Nonce, plan.Nonce, at.UTC().Format(time.RFC1123Z))
	b.WriteString(strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(plan.Draft.Text, "\r\n", "\n"), "\n", "\r\n"), "\r\n") + "\r\n")
	return b.Bytes(), nil
}
func (w *DraftWriter) append(ctx context.Context, gate *sourceguard.Lease, mailbox AppleMailbox, raw []byte) (mailout.AppendReceipt, error) {
	return w.appendTo(ctx, gate, mailbox, raw, "Drafts", []protocol.Flag{protocol.FlagDraft})
}

// Sent copies are attempted once only after definite SMTP acceptance. Their
// acknowledgement is separate from delivery and must never trigger a resend.
func (w *DraftWriter) appendSent(ctx context.Context, gate *sourceguard.Lease, mailbox AppleMailbox, raw []byte) (mailout.AppendReceipt, error) {
	return w.appendTo(ctx, gate, mailbox, raw, "", []protocol.Flag{protocol.FlagSeen})
}

func (w *DraftWriter) appendTo(ctx context.Context, gate *sourceguard.Lease, mailbox AppleMailbox, raw []byte, folder string, flags []protocol.Flag) (mailout.AppendReceipt, error) {
	notSent := mailout.AppendReceipt{Outcome: mailout.NotSent, Matched: true}
	endpoint, err := w.config.Credentials(ctx, mailbox)
	if err != nil {
		return notSent, draftError("credentials", err, false)
	}
	local := strings.SplitN(mailbox.Address, "@", 2)[0]
	if endpoint.Host != "imap.mail.me.com" || endpoint.Port != 993 || !same(endpoint.Username, mailbox.Address) && !same(endpoint.Username, local) || !safe(endpoint.Password, 4096) {
		return notSent, mailout.ErrIneligible
	}
	permit, err := w.config.AcquireSlot(ctx, gate)
	if err != nil {
		return notSent, err
	}
	if permit == nil {
		return notSent, mailout.ErrInvalid
	}
	defer permit.Close()
	ctx, cancel := context.WithTimeout(ctx, w.config.Timeout)
	defer cancel()
	conn, err := w.config.DialContext(ctx, "tcp", net.JoinHostPort(endpoint.Host, "993"))
	if err != nil {
		return notSent, draftError("connect", err, false)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if w.config.TLSConfig != nil {
		tlsConfig = w.config.TLSConfig.Clone()
	}
	tlsConfig.ServerName = endpoint.Host
	tlsConfig.InsecureSkipVerify = false
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	secure := tls.Client(conn, tlsConfig)
	if err = secure.HandshakeContext(ctx); err != nil {
		return notSent, draftError("tls", err, false)
	}
	client := imapclient.New(secure, nil)
	defer client.Close()
	if err = client.WaitGreeting(); err != nil {
		return notSent, draftError("greeting", err, false)
	}
	if err = client.Login(endpoint.Username, endpoint.Password).Wait(); err != nil {
		return notSent, draftError("login", err, false)
	}
	if folder == "" {
		// Apple exposes the real IMAP sent folder as a SPECIAL-USE attribute
		// (e.g. "Sent Messages"); the WebMail UI name "Sent" is not its path.
		rows, listErr := client.List("", "*", nil).Collect()
		if listErr != nil {
			return notSent, draftError("sent_folder", listErr, false)
		}
		folder, err = sentMailbox(rows)
		if err != nil {
			return notSent, draftError("sent_folder", err, false)
		}
	}
	command := client.Append(folder, int64(len(raw)), &protocol.AppendOptions{Flags: flags})
	_, writeErr := command.Write(raw)
	closeErr := command.Close()
	if writeErr != nil || closeErr != nil {
		var rejected *protocol.Error
		if errors.As(writeErr, &rejected) || errors.As(closeErr, &rejected) {
			return mailout.AppendReceipt{Outcome: mailout.Rejected, Matched: true}, draftError("append", rejected, false)
		}
		return mailout.AppendReceipt{Outcome: mailout.Unknown, Matched: true}, draftError("append", joined(writeErr, closeErr), true)
	}
	data, err := command.Wait()
	if err != nil {
		var rejected *protocol.Error
		if errors.As(err, &rejected) {
			return mailout.AppendReceipt{Outcome: mailout.Rejected, Matched: true}, draftError("append", err, false)
		}
		return mailout.AppendReceipt{Outcome: mailout.Unknown, Matched: true}, draftError("append", err, true)
	}
	result := mailout.AppendReceipt{Outcome: mailout.Accepted, Matched: true}
	if data != nil && data.UID != 0 {
		result.Candidate.ID = fmt.Sprintf("message:%s/%d", folder, data.UID)
		result.Candidate.UID = uint32(data.UID)
		result.Candidate.UIDValidity = data.UIDValidity
	}
	return result, nil
}

func sentMailbox(rows []*protocol.ListData) (string, error) {
	folder := ""
	for _, row := range rows {
		sent, selectable := false, true
		for _, attr := range row.Attrs {
			sent = sent || strings.EqualFold(string(attr), string(protocol.MailboxAttrSent))
			selectable = selectable && !strings.EqualFold(string(attr), string(protocol.MailboxAttrNoSelect))
		}
		if sent {
			if folder != "" || !selectable || !safe(row.Mailbox, 1024) {
				return "", mailout.ErrReference
			}
			folder = row.Mailbox
		}
	}
	if folder == "" {
		return "", mailout.ErrReference
	}
	return folder, nil
}
