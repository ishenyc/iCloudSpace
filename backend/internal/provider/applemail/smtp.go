package applemail

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"icloudspace/internal/mailout"
	"icloudspace/internal/sourceguard"
)

const smtpHost = "smtp.mail.me.com"

// SMTPConfig shares the canonical Apple credential resolver and source slots.
// The route is explicit and may differ from WebMail/IMAP on Docker Desktop.
type SMTPConfig struct {
	Drafts      *DraftWriter
	DialContext func(context.Context, string, string) (net.Conn, error)
	TLSConfig   *tls.Config
	Timeout     time.Duration
}

type SMTPTransport struct{ config SMTPConfig }

func NewSMTPTransport(config SMTPConfig) (*SMTPTransport, error) {
	if config.Drafts == nil || config.Drafts.config.Credentials == nil || config.Drafts.config.AcquireSlot == nil || config.TLSConfig != nil && config.TLSConfig.InsecureSkipVerify {
		return nil, mailout.ErrInvalid
	}
	if config.Timeout == 0 {
		config.Timeout = 2 * time.Minute
	}
	if config.Timeout < time.Millisecond || config.Timeout > 5*time.Minute {
		return nil, mailout.ErrInvalid
	}
	if config.DialContext == nil {
		config.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	if config.TLSConfig != nil {
		config.TLSConfig = config.TLSConfig.Clone()
	}
	return &SMTPTransport{config: config}, nil
}

type SMTPError struct {
	Stage string
	Code  int
}

func (e *SMTPError) Error() string { return "applemail: SMTP " + e.Stage + " failed" }
func (e *SMTPError) SafeDiagnostic() (string, int, string) {
	code := ""
	if e.Code != 0 {
		code = "smtp_" + strconv.Itoa(e.Code)
	}
	return "smtp_" + e.Stage, 0, code
}

func smtpFailure(stage string, err error) *SMTPError {
	failure := &SMTPError{Stage: stage}
	var response *textproto.Error
	if errors.As(err, &response) && response.Code >= 400 && response.Code <= 599 {
		failure.Code = response.Code
	}
	return failure
}

// send makes exactly one SMTP attempt. Only a positive final DATA response is
// accepted. Loss after DATA starts is unknown; QUIT never downgrades acceptance.
// The mailout owner has already committed its seed/final intent before entry.
func (s *SMTPTransport) send(ctx context.Context, gate *sourceguard.Lease, mailbox AppleMailbox, to string, raw []byte, rpcID, messageID string) (mailout.RPCReceipt, error) {
	receipt := mailout.RPCReceipt{RPCID: rpcID, Outcome: mailout.NotSent, Matched: true}
	if !safe(rpcID, 256) || !safe(messageID, 2048) || len(raw) == 0 || len(raw) > 16<<20 {
		return receipt, mailout.ErrInvalid
	}
	recipient, err := address(to)
	if err != nil {
		return receipt, err
	}
	endpoint, err := s.config.Drafts.config.Credentials(ctx, mailbox)
	if err != nil {
		return receipt, smtpFailure("credentials", err)
	}
	local := strings.SplitN(mailbox.Address, "@", 2)[0]
	if endpoint.Host != "imap.mail.me.com" || endpoint.Port != 993 || !same(endpoint.Username, mailbox.Address) && !same(endpoint.Username, local) || !safe(endpoint.Password, 4096) {
		return receipt, mailout.ErrIneligible
	}
	permit, err := s.config.Drafts.config.AcquireSlot(ctx, gate)
	if err != nil || permit == nil {
		return receipt, smtpFailure("slot", err)
	}
	defer permit.Close()
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	conn, err := s.config.DialContext(ctx, "tcp", net.JoinHostPort(smtpHost, "587"))
	if err != nil {
		return receipt, smtpFailure("connect", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return receipt, smtpFailure("greeting", err)
	}
	defer client.Close()
	if err = client.Hello("localhost"); err != nil {
		return receipt, smtpFailure("ehlo", err)
	}
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return receipt, smtpFailure("starttls_required", nil)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.config.TLSConfig != nil {
		tlsConfig = s.config.TLSConfig.Clone()
	}
	tlsConfig.ServerName = smtpHost
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS12)
	if err = client.StartTLS(tlsConfig); err != nil {
		return receipt, smtpFailure("tls", err)
	}
	if err = client.Auth(smtp.PlainAuth("", mailbox.Address, endpoint.Password, smtpHost)); err != nil {
		return receipt, smtpFailure("auth", err)
	}
	endpoint.Password = ""
	if err = client.Mail(mailbox.Address); err != nil {
		return receipt, smtpFailure("mail_from", err)
	}
	if err = client.Rcpt(recipient); err != nil {
		failure := smtpFailure("recipient", err)
		if failure.Code != 0 {
			receipt.Outcome = mailout.Rejected
		}
		return receipt, failure
	}
	writer, err := client.Data()
	if err != nil {
		return receipt, smtpFailure("data", err)
	}
	receipt.Outcome = mailout.Unknown
	if _, err = writer.Write(raw); err != nil {
		// Do not close the dot writer: doing so would submit a partial message.
		return receipt, smtpFailure("body", err)
	}
	if err = writer.Close(); err != nil {
		failure := smtpFailure("data_response", err)
		if failure.Code != 0 {
			receipt.Outcome = mailout.Rejected
		}
		return receipt, failure
	}
	receipt.Outcome = mailout.Accepted
	receipt.ObservedMessageID = messageID
	return receipt, nil
}

func (o *operation) usesSMTP() bool {
	return o.scope.Source.Kind == "apple_direct" && o.provider.config.SMTP != nil
}
