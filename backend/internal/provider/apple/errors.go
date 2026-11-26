package apple

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type ErrorKind string

const (
	Invalid                ErrorKind = "invalid"
	Canceled               ErrorKind = "canceled"
	DNS                    ErrorKind = "dns"
	Connect                ErrorKind = "connect"
	TLS                    ErrorKind = "tls"
	Timeout                ErrorKind = "timeout"
	Transport              ErrorKind = "transport"
	Redirect               ErrorKind = "redirect"
	ResponseBudget         ErrorKind = "response_budget"
	MalformedResponse      ErrorKind = "malformed_response"
	AuthenticationRequired ErrorKind = "authentication_required"
	RateLimited            ErrorKind = "rate_limited"
	AppleRejected          ErrorKind = "apple_rejected"
	SecondFactorRequired   ErrorKind = "second_factor_required"
	ChallengeUnavailable   ErrorKind = "challenge_method_unavailable"
)

// Error retains safe diagnostics only: no upstream response text, URL, cookies,
// account names or underlying net/url.Error chain. Unknown means a mutating
// request could have reached Apple; callers must query rather than replay it.
type Error struct {
	Kind            ErrorKind
	Operation       string
	Status          int
	Code            string
	Unknown         bool
	RetryAfter      time.Duration
	TimedOut        bool
	Attempts        int
	TransportPhase  string
	TransportReason string
	cause           error
}

func (e *Error) Error() string {
	text := "apple: " + e.Operation + ": " + string(e.Kind)
	if e.Status != 0 {
		text += " status=" + strconv.Itoa(e.Status)
	}
	if e.Code != "" {
		text += " code=" + e.Code
	}
	if e.Unknown {
		text += " outcome=unknown"
	}
	if e.TimedOut {
		text += " timed_out=true"
	}
	return text
}

func (e *Error) Unwrap() error { return e.cause }

func (e *Error) SafeDiagnostic() (string, int, string) {
	return string(e.Kind), e.Status, safeCode(e.Code)
}

func (e *Error) SafeTransportDiagnostic() (string, int, string, string) {
	return safeCode(e.Operation), e.Attempts, e.TransportPhase, e.TransportReason
}

// DefinitiveRejection is the provider-neutral HME lifecycle contract. A
// transport error or an ambiguous mutation can never satisfy it.
func (e *Error) DefinitiveRejection() bool {
	return e != nil && !e.Unknown && (e.Kind == AppleRejected || e.Kind == RateLimited)
}
func (e *Error) FailureCode() string {
	if e == nil {
		return ""
	}
	if code := safeCode(e.Code); code != "" {
		return code
	}
	return string(e.Kind)
}

type sendTrace struct{ sent atomic.Bool }

func (s *sendTrace) context(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteHeaders: func() { s.sent.Store(true) }, WroteRequest: func(httptrace.WroteRequestInfo) { s.sent.Store(true) }})
}

func networkError(operation string, err error, mutation, sent bool) *Error {
	e := &Error{Kind: Transport, Operation: operation, Unknown: mutation && sent, Attempts: 1, TransportPhase: "request", TransportReason: "transport_failed"}
	var timed net.Error
	e.TimedOut = errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timed) && timed.Timeout())
	switch {
	case errors.Is(err, context.Canceled):
		e.Kind = Canceled
		e.cause = context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		e.Kind = Timeout
		e.cause = context.DeadlineExceeded
	default:
		var dns *net.DNSError
		var op *net.OpError
		var certificate *tls.CertificateVerificationError
		var unknown x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var invalid x509.CertificateInvalidError
		var record tls.RecordHeaderError
		switch {
		case errors.As(err, &dns):
			e.Kind = DNS
			if dns.IsTemporary || dns.IsTimeout {
				e.TransportReason = "dns_temporary"
			} else {
				e.TransportReason = "dns_failed"
			}
		case errors.As(err, &certificate), errors.As(err, &unknown), errors.As(err, &hostname), errors.As(err, &invalid), errors.As(err, &record):
			e.Kind = TLS
		case errors.As(err, &timed) && timed.Timeout():
			e.Kind = Timeout
		case errors.As(err, &op) && op.Op == "dial":
			e.Kind = Connect
		}
	}
	// Only fixed categories survive this boundary, never raw URLs, addresses,
	// certificate text, response bodies or the underlying error string.
	switch {
	case e.Kind == Canceled:
		e.TransportReason = "canceled"
	case e.Kind == Timeout:
		e.TransportReason = "timeout"
	case e.Kind == TLS:
		e.TransportReason = "tls_failed"
	case errors.Is(err, io.ErrUnexpectedEOF):
		e.TransportReason = "unexpected_eof"
	case errors.Is(err, io.EOF):
		e.TransportReason = "eof"
	case errors.Is(err, syscall.ECONNRESET):
		e.TransportReason = "connection_reset"
	case errors.Is(err, syscall.EPIPE):
		e.TransportReason = "broken_pipe"
	case errors.Is(err, net.ErrClosed):
		e.TransportReason = "connection_closed"
	case e.Kind == Connect:
		e.TransportReason = "connect_failed"
	}
	return e
}

func safeCode(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return ""
	}
	for _, c := range value {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return ""
		}
	}
	return value
}

func retryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	for _, layout := range []string{time.RFC1123, time.RFC850, time.ANSIC} {
		if at, err := time.Parse(layout, value); err == nil && at.After(now) {
			return at.Sub(now)
		}
	}
	return 0
}

func invalid(operation string) error { return &Error{Kind: Invalid, Operation: operation} }

func errorCode(value jsonCode) string { return safeCode(string(value)) }

// jsonCode accepts only JSON string/integer business codes; it never returns
// arbitrary errorMessage/reason data in a public diagnostic.
type jsonCode string

func (c *jsonCode) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	if len(data) > 66 {
		return fmt.Errorf("invalid business code")
	}
	if len(data) > 0 && data[0] == '"' {
		value, err := strconv.Unquote(string(data))
		if err != nil {
			return fmt.Errorf("invalid business code")
		}
		*c = jsonCode(safeCode(value))
		return nil
	}
	if _, err := strconv.ParseInt(string(data), 10, 64); err != nil {
		return fmt.Errorf("invalid business code")
	}
	*c = jsonCode(data)
	return nil
}
