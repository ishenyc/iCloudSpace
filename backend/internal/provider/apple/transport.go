package apple

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	defaultResponseBytes = 2 << 20
	maxRequestBytes      = 1 << 20
)

// Options never borrows an ambient http.Client, proxy environment or cookie
// jar. TLS verification is mandatory; RootCAs can add a controlled test CA.
type Options struct {
	ProxyURL      *url.URL
	Timeout       time.Duration
	RootCAs       *x509.CertPool
	ResponseBytes int64
}

// Client serializes complete exchanges for one Apple principal. This preserves
// response-header/cookie rotation order, including rejected authentication
// responses. It owns no password and never saves its own state to disk.
type Client struct {
	gate          chan struct{}
	document      SessionDocument
	http          *http.Client
	jar           *cookiejar.Jar
	cookies       map[string]Cookie
	responseBytes int64
}

func New(document SessionDocument, options Options) (*Client, error) {
	if validateSession(document) != nil {
		return nil, ErrSession
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	if options.ResponseBytes == 0 {
		options.ResponseBytes = defaultResponseBytes
	}
	if options.Timeout < time.Millisecond || options.Timeout > 5*time.Minute || options.ResponseBytes < 1024 || options.ResponseBytes > 16<<20 {
		return nil, invalid("configuration")
	}
	var proxy func(*http.Request) (*url.URL, error)
	if options.ProxyURL != nil {
		p := *options.ProxyURL
		if (p.Scheme != "http" && p.Scheme != "https" && p.Scheme != "socks5" && p.Scheme != "socks5h") || p.Hostname() == "" || p.Path != "" || p.RawQuery != "" || p.Fragment != "" {
			return nil, invalid("proxy")
		}
		proxy = http.ProxyURL(&p)
	}
	var roots *x509.CertPool
	if options.RootCAs != nil {
		roots = options.RootCAs.Clone()
	}
	transport := &http.Transport{
		Proxy:               proxy,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: options.Timeout,
		MaxResponseHeaderBytes: 64 << 10, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2, IdleConnTimeout: 60 * time.Second,
		// HTTP/1.1 gives this boundary a simple no-replay rule: mutations have
		// non-rewindable bodies and no idempotency header. No HTTP/2 internal
		// REFUSED_STREAM replay or application-level mutation retry is used here.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, invalid("cookies")
	}
	c := &Client{gate: make(chan struct{}, 1), document: cloneSession(document), jar: jar, cookies: make(map[string]Cookie), responseBytes: options.ResponseBytes,
		http: &http.Client{Transport: transport, Timeout: options.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	c.gate <- struct{}{}
	for _, stored := range document.Cookies {
		h := restoreCookie(stored)
		if stored.ExpiresAt != "" && !h.Expires.After(time.Now()) {
			continue
		}
		origin := &url.URL{Scheme: "https", Host: stored.Domain, Path: stored.Path}
		jar.SetCookies(origin, []*http.Cookie{h})
		c.cookies[cookieKey(stored)] = stored
	}
	return c, nil
}

// NewSession creates only local identifiers; it performs no network activity.
func NewSession(principal Principal) (SessionDocument, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return SessionDocument{}, invalid("browser_identifier")
	}
	client := hex.EncodeToString(id[:])
	document := SessionDocument{Version: SessionVersion, Principal: principal, Browser: Browser{ClientID: client, FrameID: "auth-" + client}, Cookies: []Cookie{}}
	if validateSession(document) != nil {
		return SessionDocument{}, ErrSession
	}
	return document, nil
}

func (c *Client) Snapshot() SessionDocument {
	<-c.gate
	defer func() { c.gate <- struct{}{} }()
	c.document.Cookies = c.cookieSnapshot(time.Now())
	return cloneSession(c.document)
}

func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

func (c *Client) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return networkError("wait", ctx.Err(), false, false)
	case <-c.gate:
	}
	if err := ctx.Err(); err != nil {
		c.gate <- struct{}{}
		return networkError("wait", err, false, false)
	}
	return nil
}

func (c *Client) unlock() { c.gate <- struct{}{} }

type exchangeResult struct {
	status int
	header http.Header
	body   []byte
}

// Callers hold gate across the exchange and its bounded read-only retries, so
// no late response can overwrite a newer authentication capsule.
func (c *Client) exchangeLocked(ctx context.Context, operation, method, endpoint string, body []byte, auth, mutation bool) (exchangeResult, error) {
	if retryableMailRead(operation, auth, mutation) {
		return c.readExchangeLocked(ctx, operation, method, endpoint, body)
	}
	return c.exchangeModeLocked(ctx, operation, method, endpoint, body, auth, mutation, false)
}

func (c *Client) exchangeShellLocked(ctx context.Context, operation, endpoint string) (exchangeResult, error) {
	return c.exchangeModeLocked(ctx, operation, http.MethodGet, endpoint, nil, true, false, true)
}

func (c *Client) exchangeModeLocked(ctx context.Context, operation, method, endpoint string, body []byte, auth, mutation, shell bool) (exchangeResult, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !allowedRequest(u, c.document.Principal.Region) || len(body) > maxRequestBytes ||
		(auth && u.Host != "idmsa.apple.com") || (method != http.MethodGet && method != http.MethodPost && method != http.MethodPut) {
		return exchangeResult{}, invalid(operation)
	}
	if shell && (!auth || mutation || method != http.MethodGet || u.Host != "idmsa.apple.com" || u.Path != "/appleauth/auth/authorize/signin") {
		return exchangeResult{}, invalid(operation)
	}
	trustRequest := mutation && method == http.MethodGet && u.Host == "idmsa.apple.com" && u.Path == "/appleauth/auth/2sv/trust"
	deviceCodeRequest := mutation && auth && method == http.MethodPut && len(body) == 0 && u.Host == "idmsa.apple.com" && u.Path == "/appleauth/auth/verify/trusteddevice/securitycode"
	if mutation && !trustRequest && !deviceCodeRequest && (method == http.MethodGet || len(body) == 0) {
		return exchangeResult{}, invalid(operation)
	}
	trace := &sendTrace{}
	request, err := http.NewRequestWithContext(trace.context(ctx), method, endpoint, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return exchangeResult{}, invalid(operation)
	}
	request.ContentLength = int64(len(body))
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	if shell {
		request.Header.Set("Accept", "text/html")
	}
	request.Header.Set("Content-Type", "application/json")
	if u.Path == "/wm/message" || operation == "mail_route" {
		request.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	}
	request.Header.Set("Origin", homeOrigin(c.document.Principal.Region))
	request.Header.Set("Referer", homeOrigin(c.document.Principal.Region)+"/")
	request.Header.Set("User-Agent", "iCloudSpace/1 provider")
	if strings.HasPrefix(operation, "mail_") {
		request.Header.Set("User-Agent", serviceUserAgent)
	}
	if auth {
		c.authHeaders(request.Header)
	}
	for _, cookie := range c.jar.Cookies(u) {
		request.AddCookie(cookie)
	}
	client := c.http
	if trustRequest || deviceCodeRequest {
		// Apple's trust operation is an observed GET with a side effect. A
		// fresh HTTP/1.1 transport prevents Go's reused-connection GET retry.
		// No arbitrary injected transport can opt into this mutation.
		base, ok := c.http.Transport.(*http.Transport)
		if !ok {
			return exchangeResult{}, invalid(operation)
		}
		fresh := base.Clone()
		fresh.DisableKeepAlives = true
		defer fresh.CloseIdleConnections()
		oneAttempt := *c.http
		oneAttempt.Transport = fresh
		client = &oneAttempt
	}
	response, err := client.Do(request)
	if err != nil {
		return exchangeResult{}, networkError(operation, err, mutation, trace.sent.Load())
	}
	defer response.Body.Close()
	if auth {
		c.rotate(response.Header)
	}
	if err := c.receiveCookies(u, response.Cookies(), time.Now()); err != nil {
		return exchangeResult{}, &Error{Kind: ResponseBudget, Operation: operation, Status: response.StatusCode, Unknown: mutation}
	}
	result := exchangeResult{status: response.StatusCode, header: response.Header.Clone()}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return result, &Error{Kind: Redirect, Operation: operation, Status: response.StatusCode, Unknown: mutation}
	}
	limited := io.LimitReader(response.Body, c.responseBytes+1)
	result.body, err = io.ReadAll(limited)
	if err != nil {
		failure := networkError(operation, err, mutation, true)
		failure.TransportPhase = "response_body"
		failure.Status = response.StatusCode
		return result, failure
	}
	if int64(len(result.body)) > c.responseBytes {
		return result, &Error{Kind: ResponseBudget, Operation: operation, Status: response.StatusCode, Unknown: mutation}
	}
	if len(bytes.TrimSpace(result.body)) > 0 {
		media, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if shell {
			if parseErr != nil || media != "text/html" {
				return result, &Error{Kind: MalformedResponse, Operation: operation, Status: response.StatusCode}
			}
			return result, nil
		}
		if parseErr != nil || (media != "application/json" && media != "text/json" && media != "application/json-rpc") || !json.Valid(result.body) {
			if response.StatusCode >= 400 {
				result.body = nil
				return result, nil
			}
			return result, &Error{Kind: MalformedResponse, Operation: operation, Status: response.StatusCode, Unknown: mutation}
		}
	}
	return result, nil
}

func (c *Client) rotate(header http.Header) {
	a := &c.document.Authentication
	for name, destination := range map[string]*string{"X-Apple-ID-Session-Id": &a.SessionID, "X-Apple-Session-Token": &a.SessionToken, "X-Apple-TwoSV-Trust-Token": &a.TrustToken, "scnt": &a.SCNT, "X-Apple-Auth-Attributes": &a.AuthAttributes, "X-Apple-ID-Account-Country": &c.document.Browser.CountryCode} {
		limit := 32768
		if name == "X-Apple-ID-Account-Country" {
			limit = 16
		}
		if value := header.Get(name); value != "" && field(value, limit, false) {
			*destination = value
		}
	}
}

func (c *Client) authHeaders(header http.Header) {
	a, b := c.document.Authentication, c.document.Browser
	header.Set("X-Apple-OAuth-Client-Id", widgetKey)
	header.Set("X-Apple-Widget-Key", widgetKey)
	header.Set("X-Apple-OAuth-Client-Type", "firstPartyAuth")
	header.Set("X-Apple-OAuth-Redirect-URI", homeOrigin(c.document.Principal.Region))
	header.Set("X-Apple-OAuth-Response-Mode", "web_message")
	header.Set("X-Apple-OAuth-Response-Type", "code")
	header.Set("X-Apple-OAuth-State", b.FrameID)
	header.Set("X-Apple-Frame-Id", b.FrameID)
	if a.SessionID != "" {
		header.Set("X-Apple-ID-Session-Id", a.SessionID)
	}
	if a.SCNT != "" {
		header.Set("scnt", a.SCNT)
	}
	if a.AuthAttributes != "" {
		header.Set("X-Apple-Auth-Attributes", a.AuthAttributes)
	}
}

func restoreCookie(stored Cookie) *http.Cookie {
	c := &http.Cookie{Name: stored.Name, Value: stored.Value, Path: stored.Path, Secure: stored.Secure, HttpOnly: stored.HTTPOnly, SameSite: http.SameSite(stored.SameSite)}
	if !stored.HostOnly {
		c.Domain = stored.Domain
	}
	if stored.ExpiresAt != "" {
		c.Expires, _ = time.Parse(time.RFC3339Nano, stored.ExpiresAt)
	}
	return c
}

func (c *Client) replaceCookies(cookies []Cookie) {
	c.jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	c.cookies = make(map[string]Cookie, len(cookies))
	for _, stored := range cookies {
		c.jar.SetCookies(&url.URL{Scheme: "https", Host: stored.Domain, Path: stored.Path}, []*http.Cookie{restoreCookie(stored)})
		c.cookies[cookieKey(stored)] = stored
	}
}

func (c *Client) receiveCookies(origin *url.URL, cookies []*http.Cookie, now time.Time) error {
	// Reserve room for the authentication headers and document structure. This
	// also bounds accumulation across many individually valid responses.
	const cookieBytesBudget = 768 << 10
	collectionBytes := 0
	for _, stored := range c.cookies {
		encoded, _ := json.Marshal(stored)
		collectionBytes += len(encoded)
	}
	for _, incoming := range cookies {
		stored := Cookie{Name: incoming.Name, Value: incoming.Value, Domain: origin.Hostname(), Path: incoming.Path, HostOnly: incoming.Domain == "", Secure: incoming.Secure, HTTPOnly: incoming.HttpOnly, SameSite: int(incoming.SameSite)}
		if incoming.Domain != "" {
			stored.Domain = strings.TrimPrefix(strings.ToLower(incoming.Domain), ".")
		}
		if origin.Hostname() != stored.Domain && !strings.HasSuffix(origin.Hostname(), "."+stored.Domain) {
			continue
		}
		if stored.Path == "" || stored.Path[0] != '/' {
			stored.Path = "/"
			if index := strings.LastIndex(origin.Path, "/"); index > 0 {
				stored.Path = origin.Path[:index]
			}
		}
		if incoming.MaxAge > 0 {
			if int64(incoming.MaxAge) > 253402300799-now.Unix() {
				continue
			}
			stored.ExpiresAt = time.Unix(now.Unix()+int64(incoming.MaxAge), int64(now.Nanosecond())).UTC().Format(time.RFC3339Nano)
		} else if !incoming.Expires.IsZero() {
			stored.ExpiresAt = incoming.Expires.UTC().Format(time.RFC3339Nano)
		}
		if !validCookie(stored, c.document.Principal.Region) {
			continue
		}
		key := cookieKey(stored)
		oldBytes := 0
		if old, ok := c.cookies[key]; ok {
			encoded, _ := json.Marshal(old)
			oldBytes = len(encoded)
		}
		if incoming.MaxAge < 0 || (stored.ExpiresAt != "" && !restoreCookie(stored).Expires.After(now)) {
			delete(c.cookies, key)
			collectionBytes -= oldBytes
		} else {
			encoded, _ := json.Marshal(stored)
			if collectionBytes-oldBytes+len(encoded) > cookieBytesBudget {
				return ErrSession
			}
			if len(c.cookies) >= maxCookies {
				if _, ok := c.cookies[key]; !ok {
					return ErrSession
				}
			}
			c.cookies[key] = stored
			collectionBytes = collectionBytes - oldBytes + len(encoded)
		}
		c.jar.SetCookies(origin, []*http.Cookie{incoming})
	}
	return nil
}

func (c *Client) cookieSnapshot(now time.Time) []Cookie {
	result := make([]Cookie, 0, len(c.cookies))
	for key, cookie := range c.cookies {
		if cookie.ExpiresAt != "" && !restoreCookie(cookie).Expires.After(now) {
			delete(c.cookies, key)
			continue
		}
		result = append(result, cookie)
	}
	return result
}
