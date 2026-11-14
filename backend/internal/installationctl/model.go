// Package installationctl owns explicit offline installation commands. It is
// never called from Serve and does not decode historical data or issue source
// credentials. The composition/packaging root supplies its private references.
package installationctl

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"icloudspace/internal/adminauth"
	"icloudspace/internal/installation"
)

var (
	ErrInput     = errors.New("installationctl: invalid explicit command")
	ErrPrivate   = errors.New("installationctl: private reference rejected")
	ErrBinding   = errors.New("installationctl: installation binding rejected")
	ErrResources = errors.New("installationctl: actual resources rejected")
	ErrState     = errors.New("installationctl: target is not explicitly empty or fully initialized")
	ErrRunning   = errors.New("installationctl: target has an active owner")
	ErrDatabase  = errors.New("installationctl: database unavailable")
	ErrAmbient   = errors.New("installationctl: ambient PostgreSQL configuration rejected")
	ErrPassword  = errors.New("installationctl: exact new password must contain 12 to 72 bytes")
	ErrConflict  = errors.New("installationctl: original operation or revision conflicts")
	ErrNotFound  = errors.New("installationctl: original write change not recorded")
	ErrUnknown   = errors.New("installationctl: commit outcome unknown; query original operation")
)

type Spec struct {
	Version          int      `json:"version"`
	ProcessFile      string   `json:"process_file"`
	ExpectedDatabase string   `json:"expected_database"`
	OperatorLogin    string   `json:"operator_login"`
	PasswordFile     string   `json:"password_file"`
	ManagementPath   string   `json:"management_path"`
	Settings         Settings `json:"settings"`
}
type Settings struct {
	HTTPAddress                string `json:"http_address"`
	IMAPSAddress               string `json:"imaps_address"`
	PublicHost                 string `json:"public_host"`
	TLSCertificate             string `json:"tls_certificate_file"`
	TLSPrivateKey              string `json:"tls_private_key_file"`
	ArchiveCapacityBytes       string `json:"archive_capacity_bytes"`
	SyncConcurrency            int    `json:"sync_concurrency"`
	SyncRestMilliseconds       string `json:"sync_rest_milliseconds"`
	AllowWeakRecipientEvidence bool   `json:"allow_weak_recipient_evidence"`
}

func (Spec) String() string   { return "installationctl: private initialization specification" }
func (Spec) GoString() string { return "installationctl: private initialization specification" }

type Result struct {
	Operation             string `json:"operation"`
	State                 string `json:"state"`
	OperationDigest       string `json:"operation_digest,omitempty"`
	ExpectedRevision      string `json:"expected_revision,omitempty"`
	ResultRevision        string `json:"result_revision,omitempty"`
	ResultEnabled         *bool  `json:"result_enabled,omitempty"`
	CurrentRevision       string `json:"current_revision,omitempty"`
	CurrentWritesEnabled  *bool  `json:"current_writes_enabled,omitempty"`
	OperatorID            string `json:"operator_id,omitempty"`
	SchemaVersion         int    `json:"schema_version,omitempty"`
	SchemaChecksum        string `json:"schema_checksum,omitempty"`
	SchemaCatalogChecksum string `json:"schema_catalog_checksum,omitempty"`
}

func boolRef(v bool) *bool   { return &v }
func decimal(v int64) string { return strconv.FormatInt(v, 10) }
func positive(v string) (int64, error) {
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil || n < 1 || decimal(n) != v {
		return 0, ErrInput
	}
	return n, nil
}
func nonnegative(v string) (int64, error) {
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil || n < 0 || decimal(n) != v {
		return 0, ErrInput
	}
	return n, nil
}
func (s Spec) settings(process installation.Process) (installation.Settings, error) {
	capacity, err := nonnegative(s.Settings.ArchiveCapacityBytes)
	if err != nil {
		return installation.Settings{}, err
	}
	rest, err := nonnegative(s.Settings.SyncRestMilliseconds)
	if err != nil || rest > math.MaxInt64/int64(time.Millisecond) {
		return installation.Settings{}, ErrInput
	}
	settings := installation.Settings{ID: process.InstallationID, ManagementPath: s.ManagementPath, Revision: 1, WritesEnabled: false, HTTPAddress: s.Settings.HTTPAddress, IMAPSAddress: s.Settings.IMAPSAddress, PublicHost: s.Settings.PublicHost, TLSCertificate: s.Settings.TLSCertificate, TLSPrivateKey: s.Settings.TLSPrivateKey, ArchiveCapacityBytes: capacity, SyncConcurrency: s.Settings.SyncConcurrency, SyncRest: time.Duration(rest) * time.Millisecond, AllowWeakRecipientEvidence: s.Settings.AllowWeakRecipientEvidence}
	if installation.ValidateSettings(settings) != nil {
		return installation.Settings{}, ErrResources
	}
	return settings, nil
}
func validLogin(login string) bool {
	return login != "" && len(login) <= adminauth.MaxUsernameBytes && utf8.ValidString(login) && strings.TrimSpace(login) == login && !strings.ContainsAny(login, "\x00\r\n\t")
}
func validOperationKey(key string) bool {
	return key != "" && len(key) <= 256 && utf8.ValidString(key) && !strings.ContainsAny(key, "\x00\r\n")
}
