// Package smtpegress provides an authenticated, single-destination CONNECT
// tunnel for Docker Desktop. SMTP TLS remains between the application and Apple.
package smtpegress

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

const Target = "smtp.mail.me.com:587"

var ErrConfiguration = errors.New("smtp egress: invalid configuration")

type Config struct {
	TokenFile string
	Interface string
	DNS       string
}

type Handler struct {
	token [32]byte
	dial  func(context.Context, string, string) (net.Conn, error)
	slots chan struct{}
}

func New(config Config) (*Handler, error) {
	info, err := os.Stat(config.TokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 256 {
		return nil, ErrConfiguration
	}
	raw, err := os.ReadFile(config.TokenFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer clear(raw)
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 || len(token) > 128 || strings.ContainsAny(token, " \t\r\n:") {
		return nil, ErrConfiguration
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if config.Interface != "" {
		control, err := interfaceControl(config.Interface)
		if err != nil {
			return nil, ErrConfiguration
		}
		dialer.Control = control
		// Resolve through the same physical interface; the system resolver may
		// otherwise hand Docker's tunnel a fake-IP address from a TUN provider.
		endpoint, err := netip.ParseAddrPort(config.DNS)
		if err != nil || !endpoint.Addr().Is4() || endpoint.Port() != 53 {
			return nil, ErrConfiguration
		}
		dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second, Control: control}
			if strings.HasPrefix(network, "tcp") {
				return d.DialContext(ctx, "tcp4", endpoint.String())
			}
			return d.DialContext(ctx, "udp4", endpoint.String())
		}}
	}
	return &Handler{token: sha256.Sum256([]byte(token)), dial: dialer.DialContext, slots: make(chan struct{}, 16)}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// BasicAuth parses Authorization, so copy only this explicitly selected
	// proxy header; nothing from this request is forwarded to Apple.
	auth := &http.Request{Header: make(http.Header)}
	auth.Header.Set("Authorization", r.Header.Get("Proxy-Authorization"))
	user, password, ok := auth.BasicAuth()
	sum := sha256.Sum256([]byte(password))
	if !ok || user != "smtp" || subtle.ConstantTimeCompare(sum[:], h.token[:]) != 1 {
		w.Header().Set("Proxy-Authenticate", `Basic realm="iCloudSpace SMTP"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method != http.MethodConnect || r.Host != Target || r.URL.Host != Target || r.URL.Path != "" || r.URL.RawQuery != "" || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "destination not allowed", http.StatusForbidden)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "egress busy", http.StatusServiceUnavailable)
		return
	}
	remote, err := h.dial(r.Context(), "tcp4", Target)
	if err != nil {
		http.Error(w, "SMTP connection unavailable", http.StatusBadGateway)
		return
	}
	defer remote.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "tunnel unavailable", http.StatusInternalServerError)
		return
	}
	local, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer local.Close()
	deadline := time.Now().Add(5 * time.Minute)
	local.SetDeadline(deadline)
	remote.SetDeadline(deadline)
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		return
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		io.Copy(remote, buffered)
		remote.Close()
	}()
	io.Copy(local, remote)
	local.Close()
	remote.Close()
	<-finished
}
