// Package installation reads explicit canonical process references. Opening a
// process never initializes a database, generates a key, or starts a listener.
package installation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"icloudspace/internal/vault"
)

var ErrConfiguration = errors.New("installation: invalid explicit process configuration")
var ErrSecretReference = errors.New("installation: private reference could not be read")

type Process struct {
	Version                             int      `json:"version"`
	InstallationID                      string   `json:"installation_id"`
	DatabaseDSNFile                     string   `json:"database_dsn_file"`
	MasterKeyFile                       string   `json:"master_key_file"`
	BlobDirectory                       string   `json:"blob_directory"`
	WebDirectory                        string   `json:"web_directory"`
	PreviousManagementPath              string   `json:"previous_management_path,omitempty"`
	RecoveryManagementPath              string   `json:"recovery_management_path,omitempty"`
	ProxyURLFile                        string   `json:"proxy_url_file,omitempty"`
	SMTPProxyURLFile                    string   `json:"smtp_proxy_url_file,omitempty"`
	ExternalRegistrationKeyFile         string   `json:"external_registration_key_file,omitempty"`
	TrustedProxies                      []string `json:"trusted_proxies,omitempty"`
	SessionTTLSeconds                   int64    `json:"session_ttl_seconds"`
	MaximumSources                      int      `json:"maximum_sources"`
	IMAPDialTimeoutMilliseconds         int64    `json:"imap_dial_timeout_milliseconds,omitempty"`
	IMAPTLSHandshakeTimeoutMilliseconds int64    `json:"imap_tls_handshake_timeout_milliseconds,omitempty"`
	SyncSegmentTimeoutMilliseconds      int64    `json:"sync_segment_timeout_milliseconds,omitempty"`
	SyncRoundActiveTimeoutMilliseconds  int64    `json:"sync_round_active_timeout_milliseconds,omitempty"`
	ShutdownTimeoutMilliseconds         int64    `json:"shutdown_timeout_milliseconds,omitempty"`
	HTTPReadTimeoutMilliseconds         int64    `json:"http_read_timeout_milliseconds,omitempty"`
	IncomingMessageBytes                int64    `json:"incoming_message_bytes,omitempty"`
	BodyBytes                           int64    `json:"body_bytes,omitempty"`
	ForceSecureCookies                  bool     `json:"force_secure_cookies,omitempty"`
}

func (p Process) String() string   { return "installation: explicit private process references" }
func (p Process) GoString() string { return p.String() }

func LoadProcess(path string) (Process, error) {
	var out Process
	if !absolute(path) {
		return out, ErrConfiguration
	}
	raw, err := readFile(path, 64<<10, false)
	if err != nil {
		return out, ErrConfiguration
	}
	if !oneObject(raw) {
		return out, ErrConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF {
		return Process{}, ErrConfiguration
	}
	if out.Version != 1 || !text(out.InstallationID, 256) || !absolute(out.DatabaseDSNFile) || !absolute(out.MasterKeyFile) || !absolute(out.BlobDirectory) || !absolute(out.WebDirectory) || out.ProxyURLFile != "" && !absolute(out.ProxyURLFile) || out.ExternalRegistrationKeyFile != "" && !absolute(out.ExternalRegistrationKeyFile) {
		return Process{}, ErrConfiguration
	}
	if out.SessionTTLSeconds < 1 || out.SessionTTLSeconds > int64((365*24*time.Hour)/time.Second) || out.MaximumSources < 1 {
		return Process{}, ErrConfiguration
	}
	if out.SMTPProxyURLFile != "" && !absolute(out.SMTPProxyURLFile) {
		return Process{}, ErrConfiguration
	}
	if out.PreviousManagementPath != "" && (!managementPath(out.PreviousManagementPath) || out.PreviousManagementPath == "/admin" || strings.HasPrefix(out.PreviousManagementPath, "/admin/")) {
		return Process{}, ErrConfiguration
	}
	if out.RecoveryManagementPath != "" && (!managementPath(out.RecoveryManagementPath) || out.RecoveryManagementPath == "/admin" || strings.HasPrefix(out.RecoveryManagementPath, "/admin/")) {
		return Process{}, ErrConfiguration
	}
	if out.PreviousManagementPath != "" && out.RecoveryManagementPath != "" && out.PreviousManagementPath != out.RecoveryManagementPath {
		return Process{}, ErrConfiguration
	}
	for _, prefix := range out.TrustedProxies {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return Process{}, ErrConfiguration
		}
	}
	if _, err := out.Budgets(); err != nil {
		return Process{}, ErrConfiguration
	}
	return out, nil
}
func absolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}
func text(value string, max int) bool {
	return value != "" && len(value) <= max && !strings.ContainsAny(value, "\x00\r\n") && strings.TrimSpace(value) == value
}

func readFile(path string, limit int64, secret bool) ([]byte, error) {
	if !absolute(path) {
		return nil, ErrSecretReference
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrSecretReference
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0022 != 0 || secret && info.Mode().Perm()&0077 != 0 {
		return nil, ErrSecretReference
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrSecretReference
	}
	return raw, nil
}

// DatabaseDSN is read only from the named private file. It is never included in
// process formatting/errors and is not selected by an ambient environment.
func (p Process) DatabaseDSN() (string, error) {
	raw, err := readFile(p.DatabaseDSNFile, 32<<10, true)
	if err != nil {
		return "", err
	}
	dsn := strings.TrimSpace(string(raw))
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || u.Hostname() == "" || u.User == nil || u.User.Username() == "" || u.Path == "" || u.Path == "/" || u.Fragment != "" || strings.ContainsAny(dsn, "\x00\r\n") {
		return "", ErrSecretReference
	}
	return dsn, nil
}
func (p Process) Vault() (*vault.Vault, error) {
	key, err := readFile(p.MasterKeyFile, 32, true)
	if err != nil || len(key) != 32 {
		return nil, ErrSecretReference
	}
	box, err := vault.New(key)
	clear(key)
	if err != nil {
		return nil, ErrSecretReference
	}
	return box, nil
}
func (p Process) ProxyURL() (*url.URL, error) {
	if p.ProxyURLFile == "" {
		return nil, nil
	}
	raw, err := readFile(p.ProxyURLFile, 16<<10, true)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrSecretReference
	}
	return u, nil
}

// SMTPProxyURL inherits the explicit application proxy unless a dedicated
// SMTP route is configured. It never uses ambient proxy variables or fallback.
func (p Process) SMTPProxyURL() (*url.URL, error) {
	if p.SMTPProxyURLFile == "" {
		return p.ProxyURL()
	}
	return (Process{ProxyURLFile: p.SMTPProxyURLFile}).ProxyURL()
}

// ExternalRegistrationKeyHash is a deployment-level authority, independent of
// mailbox credentials and browser sessions. An omitted reference disables it.
// The original secret is read once at startup; it is never generated here.
func (p Process) ExternalRegistrationKeyHash() ([32]byte, error) {
	if p.ExternalRegistrationKeyFile == "" {
		return [32]byte{}, nil
	}
	raw, err := readFile(p.ExternalRegistrationKeyFile, 4098, true)
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(raw)
	value := bytes.TrimSuffix(raw, []byte("\n"))
	value = bytes.TrimSuffix(value, []byte("\r"))
	if len(value) == 0 {
		return [32]byte{}, nil
	}
	if len(value) > 4096 {
		return [32]byte{}, ErrSecretReference
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return [32]byte{}, ErrSecretReference
		}
	}
	return sha256.Sum256(value), nil
}
func (p Process) ProxyPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range p.TrustedProxies {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, prefix)
		}
	}
	return out
}

// Process fields are flat except for the trusted-proxy string array. Checking
// keys before struct decoding prevents duplicate configuration interpretations.
func oneObject(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
	}
	token, err = d.Token()
	return err == nil && token == json.Delim('}') && d.Decode(new(any)) == io.EOF
}
