package accounts

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"

	"icloudspace/internal/vault"
)

// CredentialOwner is a trusted canonical source identity, never metadata
// extracted from a ciphertext. It is shared with the controlled converter so
// format writers cannot accidentally choose another purpose or revision.
type CredentialOwner struct {
	InstallationID string
	SourceID       int64
	Revision       int64
}

func (o CredentialOwner) Binding() (vault.Binding, error) {
	if o.SourceID < 1 || o.Revision < 1 {
		return vault.Binding{}, ErrCredentials
	}
	return vault.Binding{InstallationID: o.InstallationID, SubjectType: "mail_source", SubjectID: strconv.FormatInt(o.SourceID, 10), Purpose: "imap_credentials", Revision: uint64(o.Revision)}, nil
}

func SealCredentials(v *vault.Vault, owner CredentialOwner, value Credentials) ([]byte, error) {
	binding, err := owner.Binding()
	if err != nil || v == nil || validateCredentials(value) != nil {
		return nil, ErrCredentials
	}
	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, ErrCredentials
	}
	defer clear(plaintext)
	encoded, err := v.Seal(binding, plaintext)
	if err != nil {
		return nil, ErrCredentials
	}
	return []byte(encoded), nil
}

func OpenCredentials(v *vault.Vault, owner CredentialOwner, envelope []byte) (Credentials, error) {
	binding, err := owner.Binding()
	if err != nil || v == nil {
		return Credentials{}, ErrCredentials
	}
	plaintext, err := v.Open(binding, string(envelope))
	if err != nil {
		return Credentials{}, ErrCredentials
	}
	defer clear(plaintext)
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var credentials Credentials
	if decoder.Decode(&credentials) != nil || decoder.Decode(new(any)) != io.EOF || validateCredentials(credentials) != nil {
		return Credentials{}, ErrCredentials
	}
	return credentials, nil
}
