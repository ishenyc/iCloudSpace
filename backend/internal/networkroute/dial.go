// Package networkroute supplies one explicit route for IMAP read/write owners.
// It never reads proxy environment variables or falls back to another route.
package networkroute

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

var ErrConfiguration = errors.New("networkroute: invalid explicit network route")

type Error struct {
	Stage  string
	Status int
	cause  error
}

func (e *Error) Error() string { return "networkroute: " + e.Stage + " failed" }
func (e *Error) Unwrap() error { return e.cause }

type Options struct {
	Timeout  time.Duration
	ProxyTLS *tls.Config
}
type Dialer struct {
	route   *url.URL
	direct  *net.Dialer
	timeout time.Duration
	tls     *tls.Config
}

func New(route *url.URL, options Options) (*Dialer, error) {
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.Timeout < time.Millisecond || options.Timeout > time.Minute || options.ProxyTLS != nil && options.ProxyTLS.InsecureSkipVerify {
		return nil, ErrConfiguration
	}
	d := &Dialer{direct: &net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}, timeout: options.Timeout, tls: &tls.Config{MinVersion: tls.VersionTLS12}}
	if options.ProxyTLS != nil {
		d.tls = options.ProxyTLS.Clone()
		if d.tls.MinVersion < tls.VersionTLS12 {
			d.tls.MinVersion = tls.VersionTLS12
		}
	}
	if route != nil {
		if route.Hostname() == "" || route.Path != "" || route.RawQuery != "" || route.Fragment != "" || route.Scheme != "http" && route.Scheme != "https" && route.Scheme != "socks5" && route.Scheme != "socks5h" {
			return nil, ErrConfiguration
		}
		copy := *route
		d.route = &copy
	}
	return d, nil
}
func (d *Dialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if d == nil || network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrConfiguration
	}
	host, port, err := net.SplitHostPort(target)
	number, e := strconv.ParseUint(port, 10, 16)
	if err != nil || e != nil || host == "" || number == 0 || len(target) > 1024 || strings.ContainsAny(target, "\r\n\x00") {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	if d.route == nil {
		return d.direct.DialContext(ctx, network, target)
	}
	if d.route.Scheme == "socks5" || d.route.Scheme == "socks5h" {
		route := *d.route
		route.Scheme = "socks5"
		p, err := proxy.FromURL(&route, d.direct)
		if err != nil {
			return nil, ErrConfiguration
		}
		contextual, ok := p.(proxy.ContextDialer)
		if !ok {
			return nil, ErrConfiguration
		}
		return contextual.DialContext(ctx, network, target)
	}
	proxyPort := d.route.Port()
	if proxyPort == "" {
		proxyPort = "80"
		if d.route.Scheme == "https" {
			proxyPort = "443"
		}
	}
	conn, err := d.direct.DialContext(ctx, network, net.JoinHostPort(d.route.Hostname(), proxyPort))
	if err != nil {
		return nil, &Error{Stage: "proxy_connect", cause: err}
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	if deadline, exists := ctx.Deadline(); exists {
		conn.SetDeadline(deadline)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func(raw net.Conn) {
		defer close(done)
		select {
		case <-ctx.Done():
			raw.Close()
		case <-stop:
		}
	}(conn)
	watching := true
	stopWatcher := func() {
		if watching {
			close(stop)
			<-done
			watching = false
		}
	}
	defer stopWatcher()
	if d.route.Scheme == "https" {
		config := d.tls.Clone()
		config.ServerName = d.route.Hostname()
		secured := tls.Client(conn, config)
		if err := secured.HandshakeContext(ctx); err != nil {
			return nil, &Error{Stage: "proxy_tls", cause: err}
		}
		conn = secured
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if user := d.route.User; user != nil {
		password, _ := user.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user.Username()+":"+password)))
	}
	if err := request.Write(conn); err != nil {
		return nil, &Error{Stage: "proxy_request", cause: err}
	}
	header := &headerReader{Reader: conn, remaining: 64 << 10}
	reader := bufio.NewReader(header)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, &Error{Stage: "proxy_response", cause: contextCause(ctx, err)}
	}
	if response.StatusCode != http.StatusOK {
		return nil, &Error{Stage: "proxy_refused", Status: response.StatusCode}
	}
	// Join the dial-only watcher before handing the connection to its owner.
	// A cancelled handshake may close it, but cannot race a successful handoff.
	stopWatcher()
	if err := ctx.Err(); err != nil {
		return nil, &Error{Stage: "proxy_response", cause: err}
	}
	header.tunnel = true
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, &Error{Stage: "proxy_deadline"}
	}
	ok = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}
func contextCause(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return context.DeadlineExceeded
	}
	return nil
}

type headerReader struct {
	io.Reader
	remaining int
	tunnel    bool
}

func (r *headerReader) Read(p []byte) (int, error) {
	if !r.tunnel {
		if r.remaining == 0 {
			return 0, errors.New("networkroute: proxy header budget")
		}
		p = p[:min(len(p), r.remaining)]
	}
	n, err := r.Reader.Read(p)
	if !r.tunnel {
		r.remaining -= n
	}
	return n, err
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
