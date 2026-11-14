package apple

import (
	"net/url"
	"regexp"
	"strings"
)

// Service selects the exact discovered Apple capability being normalized.
type Service string

const (
	PremiumMail Service = "premium_mail"
	MailGateway Service = "mail_gateway"
	Mail        Service = "mail"
)

// CanonicalOrigin accepts only an equivalent HTTPS origin. A root slash and
// explicit default port may be removed; a non-root path, credentials, query,
// fragment or mismatched regional/service host is rejected rather than lost.
func CanonicalOrigin(raw string, region Region, service Service) (string, error) {
	if raw == "" {
		return "", nil
	}
	if region != Global && region != China {
		return "", ErrSession
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Port() != "" && u.Port() != "443") {
		return "", ErrSession
	}
	host := strings.ToLower(u.Hostname())
	if u.Host != u.Hostname() && u.Host != u.Hostname()+":443" {
		return "", ErrSession
	}
	var role serviceRole
	switch service {
	case PremiumMail:
		role = premiumService
	case MailGateway:
		role = gatewayService
	case Mail:
		role = mailService
	default:
		return "", ErrSession
	}
	origin := "https://" + host
	if !validServiceOrigin(origin, region, role) {
		return "", ErrSession
	}
	return origin, nil
}

type serviceRole uint8

const (
	premiumService serviceRole = iota
	gatewayService
	mailService
)

var clusterHost = regexp.MustCompile(`^p[0-9]{1,3}-(premiummailsettings|maildomainws|mailws|mail|mccgateway)\.icloud\.(com|com\.cn)$`)

func serviceSuffix(region Region) string {
	if region == China {
		return "icloud.com.cn"
	}
	return "icloud.com"
}

func homeOrigin(region Region) string  { return "https://www." + serviceSuffix(region) }
func setupOrigin(region Region) string { return "https://setup." + serviceSuffix(region) }

func strictHTTPS(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Host == "" || u.Host != u.Hostname() ||
		u.Host != strings.ToLower(u.Host) || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" {
		return nil, false
	}
	return u, true
}

func validServiceOrigin(raw string, region Region, role serviceRole) bool {
	u, ok := strictHTTPS(raw)
	if !ok || u.Path != "" {
		return false
	}
	match := clusterHost.FindStringSubmatch(u.Hostname())
	if match == nil || !strings.HasSuffix(u.Hostname(), "."+serviceSuffix(region)) {
		return false
	}
	switch role {
	case premiumService:
		return match[1] == "premiummailsettings" || match[1] == "maildomainws"
	case gatewayService:
		return match[1] == "mailws" || match[1] == "mccgateway"
	case mailService:
		return match[1] == "mailws" || match[1] == "mail"
	}
	return false
}

func cookieDomainAllowed(domain string, region Region) bool {
	if domain == "idmsa.apple.com" || domain == "apple.com" {
		return true
	}
	suffix := serviceSuffix(region)
	if domain == suffix || domain == "www."+suffix || domain == "setup."+suffix {
		return true
	}
	u := "https://" + domain
	return validServiceOrigin(u, region, premiumService) || validServiceOrigin(u, region, gatewayService) || validServiceOrigin(u, region, mailService)
}

// Authentication has a fixed, global origin; discovery may never redirect
// password proofs or verification codes to a service host or a regional alias.
func allowedRequest(u *url.URL, region Region) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Host != u.Hostname() ||
		u.Host != strings.ToLower(u.Host) || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || strings.Contains(u.Path, "//") {
		return false
	}
	if u.Host == "idmsa.apple.com" {
		switch u.Path {
		case "/appleauth/auth", "/appleauth/auth/authorize/signin", "/appleauth/auth/signin/init", "/appleauth/auth/signin/complete", "/appleauth/auth/verify/trusteddevice", "/appleauth/auth/verify/trusteddevice/securitycode", "/appleauth/auth/verify/phone", "/appleauth/auth/verify/phone/securitycode", "/appleauth/auth/verify/security/key", "/appleauth/auth/2sv/trust":
			return true
		}
		return false
	}
	if "https://"+u.Host == setupOrigin(region) {
		return u.Path == "/setup/ws/1/validate" || u.Path == "/setup/ws/1/accountLogin"
	}
	if validServiceOrigin("https://"+u.Host, region, premiumService) {
		switch u.Path {
		case "/v2/hme/list", "/v1/hme/generate", "/v1/hme/reserve", "/v1/hme/updateMetaData", "/v1/hme/updateForwardTo", "/v1/hme/deactivate", "/v1/hme/delete", "/v1/hme/mail/fetchOrRegister":
			return true
		}
	}
	if validServiceOrigin("https://"+u.Host, region, mailService) {
		return u.Path == "/wm/message" || u.Path == "/wm/messagepart"
	}
	if validServiceOrigin("https://"+u.Host, region, gatewayService) {
		return u.Path == "/mailws2/v1/geqs/query" || u.Path == "/mailws2/v1/draft/send"
	}
	return false
}
