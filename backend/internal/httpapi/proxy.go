package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type requestSource struct {
	address netip.Addr
	scheme  string
	host    string
}

func (a *ManagementAuth) trusted(address netip.Addr) bool {
	for _, prefix := range a.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (a *ManagementAuth) requestSource(r *http.Request) requestSource {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	address, _ := netip.ParseAddr(host)
	address = address.Unmap()
	result := requestSource{address: address, scheme: "http", host: r.Host}
	if r.TLS != nil {
		result.scheme = "https"
	}
	if !a.trusted(address) {
		return result
	}
	if forwarded, ok := oneHeader(r, "X-Forwarded-Proto"); ok && (forwarded == "http" || forwarded == "https") {
		result.scheme = forwarded
	}
	if forwarded, ok := oneHeader(r, "X-Forwarded-Host"); ok && validAuthority(forwarded) {
		result.host = forwarded
	}
	// Start at the real peer and walk from the nearest hop. A client-provided
	// leftmost value never overrides the first untrusted hop in that chain.
	forwarded, ok := oneHeader(r, "X-Forwarded-For")
	if len(r.Header.Values("X-Forwarded-For")) == 0 {
		if value, present := oneHeader(r, "X-Real-IP"); present {
			if realIP, err := netip.ParseAddr(value); err == nil {
				result.address = realIP.Unmap()
			}
		}
		return result
	}
	if ok && len(forwarded) <= 4096 {
		chain := strings.Split(forwarded, ",")
		for i := len(chain) - 1; i >= 0 && a.trusted(result.address); i-- {
			next, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
			if err != nil {
				result.address = address
				break
			}
			result.address = next.Unmap()
		}
	}
	return result
}

func oneHeader(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func validAuthority(value string) bool {
	u, err := url.Parse("https://" + value)
	if err != nil || u.Host != value || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(value, " ,\\\t\r\n") {
		return false
	}
	if port := u.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		return err == nil && number != 0
	}
	return true
}

func (a *ManagementAuth) clientAddress(r *http.Request) string {
	peer := a.requestSource(r)
	if peer.address.IsValid() {
		return peer.address.String()
	}
	return "unknown"
}

func (a *ManagementAuth) cookieSecure(r *http.Request) bool {
	return a.secure || a.requestSource(r).scheme == "https"
}
