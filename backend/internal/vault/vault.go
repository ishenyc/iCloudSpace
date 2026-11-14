// Package vault encrypts credential values in the version 1 canonical envelope.
// It does not load keys, accept historical codecs, or decide credential grants.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf8"
)

// MaxPlaintextBytes accommodates credential/session cookie collections during
// migration. Callers should impose smaller limits for individual credential
// fields. Mail and attachment bodies belong in the content storage protocol.
const MaxPlaintextBytes = 1 << 20

const (
	envelopePrefix    = "sp1."
	envelopeVersion   = byte(1)
	envelopeDomain    = "iCloudSpace/vault/envelope\x00"
	fingerprintDomain = "iCloudSpace/vault/installation-proof/v1\x00"

	// Binding budgets permit UTF-8 identifiers without allowing a credential
	// envelope to carry an unbounded metadata document. Lengths count bytes.
	maxInstallationBytes = 256
	maxSubjectTypeBytes  = 128
	maxSubjectIDBytes    = 256
	maxPurposeBytes      = 128
	maxHeaderBytes       = 1 + 4*2 + maxInstallationBytes + maxSubjectTypeBytes + maxSubjectIDBytes + maxPurposeBytes + 8
	gcmNonceBytes        = 12
	gcmTagBytes          = 16
	maxEnvelopeBytes     = maxHeaderBytes + gcmNonceBytes + MaxPlaintextBytes + gcmTagBytes
	// MaxEncodedEnvelopeBytes is the existing version1 wire budget, including
	// its prefix and unpadded base64. Readers must not impose a smaller limit.
	MaxEncodedEnvelopeBytes = len(envelopePrefix) + (maxEnvelopeBytes*8+5)/6
)

// ErrRejected is the only public failure. It intentionally identifies neither
// which binding field failed nor whether a key, ciphertext or version differed.
var ErrRejected = errors.New("vault: operation rejected")

// Binding identifies the precise record and use of an encrypted value. Values
// are case sensitive and are not normalized. Callers must obtain the expected
// binding from trusted record identity, never from the envelope being opened.
type Binding struct {
	InstallationID string // Required UTF-8, at most 256 bytes.
	SubjectType    string // Required UTF-8, at most 128 bytes.
	SubjectID      string // Required UTF-8, at most 256 bytes.
	Purpose        string // Required UTF-8, at most 128 bytes.
	Revision       uint64 // Starts at 1; changed credential revisions need a new binding.
}

// Vault is immutable after New and supports concurrent calls. It retains key
// material for its lifetime; it makes no promise of explicit memory erasure.
// A zero Vault cannot perform operations. No method changes caller-owned input.
type Vault struct {
	aead           cipher.AEAD
	fingerprintKey [32]byte
}

// New accepts the existing 32-byte installation master key. It never generates
// a replacement key and takes its own copy, so the caller may clear its input.
func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, ErrRejected
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrRejected
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, ErrRejected
	}
	v := &Vault{aead: aead}
	copy(v.fingerprintKey[:], key)
	return v, nil
}

// Seal authenticates the binding and encrypts the value with a fresh cSPRNG
// nonce supplied by the standard library. As with that AES-GCM API, a master key
// must encrypt fewer than 2^32 values over its lifetime, across all Vaults.
func (v *Vault) Seal(binding Binding, plaintext []byte) (string, error) {
	if v == nil || v.aead == nil || len(plaintext) > MaxPlaintextBytes {
		return "", ErrRejected
	}
	header, ok := bindingHeader(binding)
	if !ok {
		return "", ErrRejected
	}
	aad := append([]byte(envelopeDomain), header...)
	// Wire body: version, four uint16-length-prefixed UTF-8 fields in Binding
	// order, uint64 revision, 12-byte nonce, ciphertext, 16-byte GCM tag. All
	// integers are big endian. The complete header, including version, is AAD.
	body := v.aead.Seal(header, nil, plaintext, aad)
	return envelopePrefix + base64.RawURLEncoding.EncodeToString(body), nil
}

// Open accepts only canonical version 1 envelopes for the supplied binding.
// The returned bytes belong to the caller and are never retained by the Vault.
func (v *Vault) Open(binding Binding, encoded string) ([]byte, error) {
	if v == nil || v.aead == nil || len(encoded) > MaxEncodedEnvelopeBytes {
		return nil, ErrRejected
	}
	header, ok := bindingHeader(binding)
	if !ok {
		return nil, ErrRejected
	}
	payload, ok := strings.CutPrefix(encoded, envelopePrefix)
	if !ok {
		return nil, ErrRejected
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != payload {
		return nil, ErrRejected
	}
	if len(body) < len(header)+v.aead.Overhead() ||
		len(body) > len(header)+v.aead.Overhead()+MaxPlaintextBytes ||
		subtle.ConstantTimeCompare(body[:len(header)], header) != 1 {
		return nil, ErrRejected
	}
	aad := append([]byte(envelopeDomain), header...)
	plaintext, err := v.aead.Open(nil, nil, body[len(header):], aad)
	if err != nil {
		return nil, ErrRejected
	}
	return plaintext, nil
}

// Fingerprint produces a keyed proof of the key/installation pair in a separate
// protocol domain. It is not an unkeyed hash of credentials. A migration must
// compare its trusted installation proof before writing any target records.
func (v *Vault) Fingerprint(installation string) ([32]byte, error) {
	if v == nil || v.aead == nil || !validField(installation, maxInstallationBytes) {
		return [32]byte{}, ErrRejected
	}
	mac := hmac.New(sha256.New, v.fingerprintKey[:])
	mac.Write([]byte(fingerprintDomain))
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(installation)))
	mac.Write(size[:])
	mac.Write([]byte(installation))
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func bindingHeader(b Binding) ([]byte, bool) {
	if !validField(b.InstallationID, maxInstallationBytes) ||
		!validField(b.SubjectType, maxSubjectTypeBytes) ||
		!validField(b.SubjectID, maxSubjectIDBytes) ||
		!validField(b.Purpose, maxPurposeBytes) || b.Revision == 0 {
		return nil, false
	}
	header := make([]byte, 1, 1+4*2+len(b.InstallationID)+len(b.SubjectType)+len(b.SubjectID)+len(b.Purpose)+8)
	header[0] = envelopeVersion
	for _, field := range []string{b.InstallationID, b.SubjectType, b.SubjectID, b.Purpose} {
		header = binary.BigEndian.AppendUint16(header, uint16(len(field)))
		header = append(header, field...)
	}
	header = binary.BigEndian.AppendUint64(header, b.Revision)
	return header, true
}

func validField(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit && utf8.ValidString(value)
}
