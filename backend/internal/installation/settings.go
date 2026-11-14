package installation

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"icloudspace/internal/pgschema"
	"icloudspace/internal/vault"
)

var ErrBinding = errors.New("installation: schema, installation or key binding does not match")

type Settings struct {
	ID                         string
	ManagementPath             string
	Revision                   int64
	WritesEnabled              bool
	HTTPAddress                string
	IMAPSAddress               string
	PublicHost                 string
	TLSCertificate             string
	TLSPrivateKey              string
	ArchiveCapacityBytes       int64
	SyncConcurrency            int
	SyncRest                   time.Duration
	AllowWeakRecipientEvidence bool
}

// ReadSettings is the startup gate after an explicit conversion/initialization.
// A missing or mismatched database is never repaired into a fresh installation.
func ReadSettings(ctx context.Context, db *sql.DB, id string, box *vault.Vault) (Settings, error) {
	var out Settings
	if db == nil || box == nil || !text(id, 256) || pgschema.Check(ctx, db) != nil {
		return out, ErrBinding
	}
	var proof []byte
	var rest int64
	err := db.QueryRowContext(ctx, `SELECT i.installation_id,i.management_path,i.configuration_revision,i.writes_enabled,
 s.http_address,s.imaps_address,s.public_host,s.tls_certificate_ref,s.tls_private_key_ref,s.archive_capacity_bytes,s.sync_concurrency,s.sync_rest_milliseconds,s.allow_weak_recipient_evidence,k.proof
 FROM space.installation i JOIN space.installation_settings s USING(singleton) JOIN space.key_binding k USING(singleton)
 WHERE i.singleton AND k.binding_version=1`).Scan(&out.ID, &out.ManagementPath, &out.Revision, &out.WritesEnabled, &out.HTTPAddress, &out.IMAPSAddress, &out.PublicHost, &out.TLSCertificate, &out.TLSPrivateKey, &out.ArchiveCapacityBytes, &out.SyncConcurrency, &rest, &out.AllowWeakRecipientEvidence, &proof)
	want, e := box.Fingerprint(id)
	if err != nil || e != nil || out.ID != id || subtle.ConstantTimeCompare(proof, want[:]) != 1 || rest < 0 || rest > math.MaxInt64/int64(time.Millisecond) {
		return Settings{}, ErrBinding
	}
	out.SyncRest = time.Duration(rest) * time.Millisecond
	if ValidateSettings(out) != nil {
		return Settings{}, ErrBinding
	}
	return out, nil
}

// ValidateSettings checks the same canonical values used by startup, without
// loading files, opening a database or binding a listener.
func ValidateSettings(settings Settings) error {
	if !text(settings.ID, 256) || !text(settings.PublicHost, 253) || settings.Revision < 1 || settings.ArchiveCapacityBytes < 0 || settings.SyncConcurrency < 1 || settings.SyncConcurrency > math.MaxInt32 || settings.SyncRest < 0 || settings.SyncRest%time.Millisecond != 0 || !managementPath(settings.ManagementPath) || !listener(settings.HTTPAddress) || !listener(settings.IMAPSAddress) || !absolute(settings.TLSCertificate) || !absolute(settings.TLSPrivateKey) {
		return ErrConfiguration
	}
	return nil
}
func listener(address string) bool {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	value, err := strconv.ParseUint(port, 10, 16)
	return err == nil && value <= 65535
}
func managementPath(path string) bool {
	if path == "" || path == "/" || path[0] != '/' || strings.HasSuffix(path, "/") || strings.ContainsAny(path, "?#%{}\\\x00\r\n\t ") || strings.Contains(path, "//") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return path != "/api" && !strings.HasPrefix(path, "/api/") && path != "/healthz"
}
