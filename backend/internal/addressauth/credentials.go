// Package addressauth owns address credentials, grants and their canonical
// secret documents. It does not infer permissions from retained secret fields.
package addressauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"icloudspace/internal/vault"
)

var ErrCredentials = errors.New("addressauth: credential document rejected")

const (
	DocumentVersion = 1
	HashScheme      = "sha256-raw"
	HashVersion     = 1
)

type APISecret struct {
	Key string `json:"key"`
}

type IMAPSecret struct {
	Password string `json:"password"`
}

type OAuthSecrets struct {
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

// Bundle is revealed only by an explicit owner action. Metadata and effective
// permissions are separate facts; this document must never grant access alone.
type Bundle struct {
	Version int          `json:"version"`
	API     APISecret    `json:"api"`
	IMAP    IMAPSecret   `json:"imap"`
	OAuth   OAuthSecrets `json:"oauth"`
}

func (Bundle) String() string   { return "addressauth: private credential bundle" }
func (Bundle) GoString() string { return "addressauth: private credential bundle" }

type Pending struct {
	Version int    `json:"version"`
	APIKey  string `json:"api_key"`
}

func (Pending) String() string   { return "addressauth: private pending credential" }
func (Pending) GoString() string { return "addressauth: private pending credential" }

// Owner comes from trusted canonical rows, not an envelope's visible header.
type Owner struct {
	InstallationID string
	AddressID      int64
	Generation     int64
}

func (o Owner) binding(purpose string) (vault.Binding, error) {
	if o.AddressID < 1 || o.Generation < 1 {
		return vault.Binding{}, ErrCredentials
	}
	return vault.Binding{InstallationID: o.InstallationID, SubjectType: "private_address", SubjectID: strconv.FormatInt(o.AddressID, 10), Purpose: purpose, Revision: uint64(o.Generation)}, nil
}

func Generate() (Bundle, error) {
	values := make([]string, 4)
	for index, prefix := range []string{"spk_", "spm_", "spc_", "spr_"} {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return Bundle{}, ErrCredentials
		}
		values[index] = prefix + base64.RawURLEncoding.EncodeToString(random[:])
	}
	return Bundle{Version: DocumentVersion, API: APISecret{Key: values[0]}, IMAP: IMAPSecret{Password: values[1]}, OAuth: OAuthSecrets{ClientID: values[2], RefreshToken: values[3]}}, nil
}

// Hash uses exact opaque bytes. Long-lived imported secrets retain their value
// and existing SHA-256 meaning; no trimming, case folding or new hash domain is
// applied. A grant's purpose and generation still need independent validation.
func Hash(value string) [sha256.Size]byte { return sha256.Sum256([]byte(value)) }

func validSecret(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (b Bundle) Validate() error {
	if b.Version != DocumentVersion || !validSecret(b.API.Key) || !validSecret(b.IMAP.Password) || !validSecret(b.OAuth.ClientID) || !validSecret(b.OAuth.RefreshToken) {
		return ErrCredentials
	}
	return nil
}

func SealBundle(v *vault.Vault, owner Owner, value Bundle) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrCredentials
	}
	return seal(v, owner, "credential_bundle", value)
}

func OpenBundle(v *vault.Vault, owner Owner, envelope []byte) (Bundle, error) {
	var value Bundle
	if open(v, owner, "credential_bundle", envelope, &value) != nil || value.Validate() != nil {
		return Bundle{}, ErrCredentials
	}
	return value, nil
}

func SealPending(v *vault.Vault, owner Owner, value Pending) ([]byte, error) {
	if value.Version != DocumentVersion || !validSecret(value.APIKey) {
		return nil, ErrCredentials
	}
	return seal(v, owner, "pending_api_key", value)
}

func OpenPending(v *vault.Vault, owner Owner, envelope []byte) (Pending, error) {
	var value Pending
	if open(v, owner, "pending_api_key", envelope, &value) != nil || value.Version != DocumentVersion || !validSecret(value.APIKey) {
		return Pending{}, ErrCredentials
	}
	return value, nil
}

func seal(v *vault.Vault, owner Owner, purpose string, value any) ([]byte, error) {
	binding, err := owner.binding(purpose)
	if err != nil || v == nil {
		return nil, ErrCredentials
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, ErrCredentials
	}
	envelope, err := v.Seal(binding, encoded)
	clear(encoded)
	if err != nil {
		return nil, ErrCredentials
	}
	return []byte(envelope), nil
}

func open(v *vault.Vault, owner Owner, purpose string, envelope []byte, target any) error {
	binding, err := owner.binding(purpose)
	if err != nil || v == nil {
		return ErrCredentials
	}
	encoded, err := v.Open(binding, string(envelope))
	if err != nil {
		return ErrCredentials
	}
	defer clear(encoded)
	if value, ok := target.(*Bundle); ok && value != nil {
		if decoded, complete := decodeUnescapedBundle(encoded); complete {
			*value = decoded
			return nil
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrCredentials
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return ErrCredentials
	}
	return nil
}

// decodeUnescapedBundle recognizes only the complete fixed layout emitted for
// ordinary opaque secrets. Any escape, alternate layout or invalid raw string
// goes through the existing strict JSON decoder instead.
func decodeUnescapedBundle(encoded []byte) (Bundle, bool) {
	const prefix = `{"version":1,"api":{"key":"`
	if !bytes.HasPrefix(encoded, []byte(prefix)) {
		return Bundle{}, false
	}
	remaining := encoded[len(prefix):]
	var fields [4][]byte
	for index, suffix := range [...]string{
		`"},"imap":{"password":"`,
		`"},"oauth":{"client_id":"`,
		`","refresh_token":"`,
		`"}}`,
	} {
		end := bytes.IndexByte(remaining, '"')
		if end < 0 {
			return Bundle{}, false
		}
		field := remaining[:end]
		for _, character := range field {
			if character < 0x20 || character == '\\' {
				return Bundle{}, false
			}
		}
		if !utf8.Valid(field) || !bytes.HasPrefix(remaining[end:], []byte(suffix)) {
			return Bundle{}, false
		}
		fields[index] = field
		remaining = remaining[end+len(suffix):]
	}
	if len(remaining) != 0 {
		return Bundle{}, false
	}
	// Copy the fields before open clears its decrypted plaintext buffer.
	return Bundle{Version: 1, API: APISecret{Key: string(fields[0])}, IMAP: IMAPSecret{Password: string(fields[1])}, OAuth: OAuthSecrets{ClientID: string(fields[2]), RefreshToken: string(fields[3])}}, true
}
