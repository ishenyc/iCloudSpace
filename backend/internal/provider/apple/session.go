// Package apple owns Apple web authentication and its per-principal state.
// Its versioned document is a provider capsule, not an administration DTO.
package apple

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"icloudspace/internal/vault"
)

const (
	SessionVersion  = 1
	MaxSessionBytes = 1 << 20
	maxCookies      = 512
)

type Region string

const (
	Global Region = "global"
	China  Region = "china"
)

var ErrSession = errors.New("apple: invalid session document")

// SessionDocument is the only resumable plaintext format accepted by this
// provider. Secrets belong inside the installation vault, never API responses.
// Principal revision is authenticated by the vault binding rather than copied
// from an untrusted document. Unix nanoseconds retain the source's exact value.
type SessionDocument struct {
	Version             int            `json:"version"`
	Principal           Principal      `json:"principal"`
	Browser             Browser        `json:"browser"`
	Authentication      Authentication `json:"authentication"`
	Services            Services       `json:"services"`
	Assurance           Assurance      `json:"assurance"`
	Cookies             []Cookie       `json:"cookies"`
	AuthFlow            *AuthFlow      `json:"auth_flow,omitempty"`
	ValidatedAtUnixNano *int64         `json:"validated_at_unix_nano,omitempty"`
}

type Principal struct {
	AppleID      string `json:"apple_id"`
	Region       Region `json:"region"`
	DSID         string `json:"dsid,omitempty"`
	PrimaryEmail string `json:"primary_email,omitempty"`
}

type Browser struct {
	ClientID    string `json:"client_id"`
	FrameID     string `json:"frame_id"`
	CountryCode string `json:"country_code,omitempty"`
}

type Authentication struct {
	SessionID      string `json:"session_id,omitempty"`
	SessionToken   string `json:"session_token,omitempty"`
	TrustToken     string `json:"trust_token,omitempty"`
	SCNT           string `json:"scnt,omitempty"`
	AuthAttributes string `json:"auth_attributes,omitempty"`
}

// Services contains only validated Apple service origins. No paths or query
// strings are persisted, so later calls cannot turn discovery into an open URL.
type Services struct {
	PremiumMail string `json:"premium_mail,omitempty"`
	MailGateway string `json:"mail_gateway,omitempty"`
	Mail        string `json:"mail,omitempty"`
}

type Assurance struct {
	HSAVersion           int  `json:"hsa_version"`
	HSAChallengeRequired bool `json:"hsa_challenge_required"`
	TrustedBrowser       bool `json:"trusted_browser"`
	HideMyEmailActive    bool `json:"hide_my_email_active"`
	HideMyEmailAvailable bool `json:"hide_my_email_available"`
}

// Cookie's domain omits the historical leading dot. HostOnly differentiates a
// cookie set without Domain from one explicitly scoped to that domain. Empty
// expiry is a session cookie; otherwise ExpiresAt is UTC RFC3339Nano, retaining
// source precision and dates outside the UnixNano range. SameSite uses net/http's numeric constants; zero
// means the server supplied no attribute. Max-Age is resolved at receipt time.
type Cookie struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
	HostOnly  bool   `json:"host_only"`
	Secure    bool   `json:"secure"`
	HTTPOnly  bool   `json:"http_only"`
	SameSite  int    `json:"same_site"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// SessionBinding must be built from trusted database identity, not JSON fields.
// Updating the Apple identity invalidates every old session binding even when
// the IMAP source's credential generation remains unchanged.
func SessionBinding(installation string, sourceID, principalRevision int64) (vault.Binding, error) {
	if installation == "" || sourceID <= 0 || principalRevision <= 0 {
		return vault.Binding{}, ErrSession
	}
	return vault.Binding{InstallationID: installation, SubjectType: "apple_principal", SubjectID: strconv.FormatInt(sourceID, 10), Purpose: "web_session", Revision: uint64(principalRevision)}, nil
}

func EncodeSession(document SessionDocument) ([]byte, error) {
	if err := validateSession(document); err != nil {
		return nil, err
	}
	document = cloneSession(document)
	sort.Slice(document.Cookies, func(i, j int) bool { return cookieKey(document.Cookies[i]) < cookieKey(document.Cookies[j]) })
	if document.Cookies == nil {
		document.Cookies = []Cookie{}
	}
	data, err := json.Marshal(document)
	if err != nil || len(data) > MaxSessionBytes {
		return nil, ErrSession
	}
	return data, nil
}

func DecodeSession(data []byte) (SessionDocument, error) {
	if len(data) == 0 || len(data) > MaxSessionBytes || !utf8.Valid(data) {
		return SessionDocument{}, ErrSession
	}
	// encoding/json accepts duplicate members. A persisted authentication
	// document must have one interpretation across readers, so reject them.
	if err := uniqueJSON(data); err != nil {
		return SessionDocument{}, ErrSession
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document SessionDocument
	if decoder.Decode(&document) != nil || validateSession(document) != nil {
		return SessionDocument{}, ErrSession
	}
	if decoder.Decode(new(any)) != io.EOF {
		return SessionDocument{}, ErrSession
	}
	return document, nil
}

func validateSession(s SessionDocument) error {
	if s.Version != SessionVersion || (s.Principal.Region != Global && s.Principal.Region != China) ||
		!field(s.Principal.AppleID, 320, true) || !field(s.Principal.PrimaryEmail, 320, false) || strings.TrimSpace(s.Principal.AppleID) != s.Principal.AppleID ||
		!field(s.Browser.ClientID, 256, false) || !field(s.Browser.FrameID, 256, false) ||
		!field(s.Browser.CountryCode, 16, false) || len(s.Cookies) > maxCookies || s.Assurance.HSAVersion < 0 || s.Assurance.HSAVersion > 100 {
		return ErrSession
	}
	if !validFlow(s.AuthFlow) {
		return ErrSession
	}
	if s.Principal.DSID != "" {
		if len(s.Principal.DSID) > 32 {
			return ErrSession
		}
		for _, c := range s.Principal.DSID {
			if c < '0' || c > '9' {
				return ErrSession
			}
		}
	}
	for _, value := range []string{s.Authentication.SessionID, s.Authentication.SessionToken, s.Authentication.TrustToken, s.Authentication.SCNT, s.Authentication.AuthAttributes} {
		if !field(value, 32768, false) {
			return ErrSession
		}
	}
	for role, origin := range map[serviceRole]string{premiumService: s.Services.PremiumMail, gatewayService: s.Services.MailGateway, mailService: s.Services.Mail} {
		if origin != "" && !validServiceOrigin(origin, s.Principal.Region, role) {
			return ErrSession
		}
	}
	seen := make(map[string]bool, len(s.Cookies))
	for _, c := range s.Cookies {
		if !validCookie(c, s.Principal.Region) || seen[cookieKey(c)] {
			return ErrSession
		}
		seen[cookieKey(c)] = true
	}
	return nil
}

func field(value string, max int, required bool) bool {
	if len(value) > max || (required && value == "") || !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func validCookie(c Cookie, region Region) bool {
	if !cookieDomainAllowed(c.Domain, region) || !strings.HasPrefix(c.Path, "/") || !field(c.Path, 4096, true) || len(c.Name)+len(c.Value) > 8192 ||
		c.SameSite < 0 || c.SameSite > int(http.SameSiteNoneMode) {
		return false
	}
	if c.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
		if err != nil || t.UTC().Format(time.RFC3339Nano) != c.ExpiresAt {
			return false
		}
	}
	if strings.HasPrefix(c.Name, "__Secure-") && !c.Secure {
		return false
	}
	if strings.HasPrefix(c.Name, "__Host-") && (!c.Secure || !c.HostOnly || c.Path != "/") {
		return false
	}
	return (&http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain}).Valid() == nil
}

func cookieKey(c Cookie) string { return c.Domain + "\x00" + c.Path + "\x00" + c.Name }

func cloneSession(s SessionDocument) SessionDocument {
	s.Cookies = append([]Cookie(nil), s.Cookies...)
	s.AuthFlow = cloneFlow(s.AuthFlow)
	if s.ValidatedAtUnixNano != nil {
		v := *s.ValidatedAtUnixNano
		s.ValidatedAtUnixNano = &v
	}
	return s
}

func uniqueJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return ErrSession
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return ErrSession
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrSession
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrSession
	}
	return nil
}
