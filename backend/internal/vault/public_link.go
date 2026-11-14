package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

// PublicLink preserves the published URL credential wire protocol. It signs
// only an address and its current API-key digest; permission remains the
// authority's decision. This is independent of historical envelope readers.
func (v *Vault) PublicLink(version byte, address int64, keyHash []byte) (string, error) {
	if v == nil || v.aead == nil || address < 1 || len(keyHash) != sha256.Size {
		return "", ErrRejected
	}
	keyDomain, tokenDomain, ok := publicLinkDomains(version)
	if !ok {
		return "", ErrRejected
	}
	keyMAC := hmac.New(sha256.New, v.fingerprintKey[:])
	keyMAC.Write([]byte(keyDomain))
	var payload [32]byte
	copy(payload[:3], "dlt")
	payload[3] = version
	binary.BigEndian.PutUint64(payload[4:12], uint64(address))
	mac := hmac.New(sha256.New, keyMAC.Sum(nil))
	mac.Write([]byte(tokenDomain))
	mac.Write(payload[:12])
	mac.Write(keyHash)
	copy(payload[12:], mac.Sum(nil))
	return "icm_" + base64.RawURLEncoding.EncodeToString(payload[:]), nil
}

// PublicLinkIdentity returns untrusted routing information only. A caller must
// verify the MAC against an eligible current grant before granting a lease.
func PublicLinkIdentity(token string) (int64, byte, bool) {
	if len(token) != 47 || !strings.HasPrefix(token, "icm_") {
		return 0, 0, false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(token[4:])
	if err != nil || len(data) != 32 || string(data[:3]) != "dlt" {
		return 0, 0, false
	}
	_, _, valid := publicLinkDomains(data[3])
	id := binary.BigEndian.Uint64(data[4:12])
	if !valid || id == 0 || id > uint64(^uint64(0)>>1) {
		return 0, 0, false
	}
	return int64(id), data[3], true
}

func (v *Vault) VerifyPublicLink(token string, keyHash []byte) bool {
	id, version, ok := PublicLinkIdentity(token)
	if !ok {
		return false
	}
	want, err := v.PublicLink(version, id, keyHash)
	return err == nil && hmac.Equal([]byte(token), []byte(want))
}

func publicLinkDomains(version byte) (string, string, bool) {
	const current = "icloudspace/direct-link/"
	const original = "icloud-api/direct-link/"
	switch version {
	case 11:
		return current + "key/v3", current + "token/v3", true
	case 12:
		return current + "key/v3", current + "token/recent-mail/v3", true
	case 13:
		return current + "key/v3", current + "token/otp/v3", true
	case 1:
		return original + "key/v1", original + "token/v1", true
	case 2:
		return original + "key/v1", original + "token/recent-mail/v2", true
	case 3:
		return original + "key/v1", original + "token/otp/v2", true
	}
	return "", "", false
}
