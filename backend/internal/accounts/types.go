// Package accounts owns canonical mail-source administration. Metadata queries
// never read encrypted columns; credential access requires Reveal or Export.
package accounts

import (
	"context"
	"errors"
	"fmt"

	"icloudspace/internal/sourceguard"
)

type Kind string

const (
	Custom         Kind = "custom"
	AppleDirect    Kind = "apple_direct"
	AppleForwarded Kind = "apple_forwarded"
	DefaultLimit        = 20
	MaximumLimit        = 1000
)

var (
	ErrInvalid              = errors.New("accounts: invalid input")
	ErrNotFound             = errors.New("accounts: source not found")
	ErrConflict             = errors.New("accounts: revision or identity conflict")
	ErrIdentityLocked       = errors.New("accounts: identity has addresses")
	ErrSourceChangeRequired = errors.New("accounts: source change requires explicit confirmation")
	ErrCredentials          = errors.New("accounts: credentials unavailable")
	ErrDependentState       = errors.New("accounts: source has dependent state; use the explicit deletion workflow")
	ErrInstallation         = errors.New("accounts: installation identity mismatch")
	ErrReadOnly             = errors.New("accounts: installation writes are disabled")
	ErrCommitUnknown        = errors.New("accounts: commit outcome unknown; query before further mutation")
	ErrSourceChangeFence    = errors.New("accounts: source change read barrier unavailable")
)

// SourceChangeFence drains sensitive responses after the source business
// guard and before any SQL row locks. The composition root supplies the shared
// credential Authority; an unfenced service cannot replace a source.
type SourceChangeFence struct {
	Begin   func(context.Context, *sourceguard.Lease) (SourceChangeScope, error)
	Resolve func(context.Context, *sourceguard.Lease) error
}

type SourceChangeScope interface {
	Close() error
	MarkUncertain()
	Resolve(context.Context) error
}

// FieldError identifies an input field without retaining its supplied value.
type FieldError struct{ Field string }

func (e *FieldError) Error() string { return fmt.Sprintf("%s: %s", ErrInvalid, e.Field) }
func (e *FieldError) Unwrap() error { return ErrInvalid }

type Endpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
}

// PrincipalInput is an Apple identity, independent of the IMAP endpoint. DSID
// and authenticated sessions are provider-owned facts and are not patch inputs.
type PrincipalInput struct {
	AppleID string `json:"apple_id"`
	Region  string `json:"region"`
}

type ApplePrincipal struct {
	AppleID  string  `json:"apple_id"`
	Region   string  `json:"region"`
	DSID     *string `json:"dsid,omitempty"`
	Revision int64   `json:"revision"`
}

type Metadata struct {
	ID                   int64           `json:"id"`
	Kind                 Kind            `json:"kind"`
	DisplayName          string          `json:"display_name"`
	AddressNamespace     string          `json:"address_namespace"`
	Endpoint             Endpoint        `json:"endpoint"`
	AddressSuffix        string          `json:"address_suffix"`
	Enabled              bool            `json:"enabled"`
	AddressCount         int64           `json:"address_count"`
	Revision             int64           `json:"revision"`
	SourceGeneration     int64           `json:"source_generation"`
	CredentialGeneration int64           `json:"credential_generation"`
	AutomaticSyncAfter   *int64          `json:"automatic_sync_after,omitempty"`
	LastTerminalSyncAt   *int64          `json:"last_terminal_sync_at,omitempty"`
	LastSyncState        string          `json:"last_sync_state"`
	LastSyncError        string          `json:"last_sync_error"`
	LastSyncedAt         *int64          `json:"last_synced_at"`
	CreatedAt            int64           `json:"created_at"`
	UpdatedAt            int64           `json:"updated_at"`
	Apple                *ApplePrincipal `json:"apple,omitempty"`
}

// Filter is shared by List and Export. Query is a literal, case-insensitive
// substring of display name, namespace, IMAP username, or Apple ID; SQL wildcard
// characters have no special meaning. Empty fields impose no restriction.
type Filter struct {
	Query   string `json:"query"`
	Kind    Kind   `json:"kind"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type Page struct {
	Limit  int   `json:"limit"`
	Offset int64 `json:"offset"`
}

type MetadataPage struct {
	Items  []Metadata `json:"items"`
	Total  int64      `json:"total"`
	Limit  int        `json:"limit"`
	Offset int64      `json:"offset"`
}

// Change names both generations so downstream owners cannot mistake a changed
// endpoint for a continuation of the previous scan. No cursor is reset here.
type Change struct {
	Source                   Metadata `json:"source"`
	SourceChanged            bool     `json:"source_changed"`
	CredentialsChanged       bool     `json:"credentials_changed"`
	PreviousSourceGeneration int64    `json:"previous_source_generation"`
}

// Credentials is the plaintext version 1 source envelope. Apple credentials
// belong to the Apple authentication/session owner, never this document.
type Credentials struct {
	Version      int    `json:"version"`
	IMAPPassword string `json:"imap_password"`
}

type CreateInput struct {
	Kind             Kind            `json:"kind"`
	DisplayName      string          `json:"display_name"`
	AddressNamespace string          `json:"address_namespace"`
	Endpoint         Endpoint        `json:"endpoint"`
	AddressSuffix    string          `json:"address_suffix"`
	Enabled          bool            `json:"enabled"`
	Credentials      Credentials     `json:"credentials"`
	Apple            *PrincipalInput `json:"apple,omitempty"`
}

// Patch uses omission to retain existing fields, including credentials. A
// supplied credentials document must contain a nonempty password. Endpoint is
// replaced as a unit. Switching to custom removes the separate Apple identity.
type Patch struct {
	Kind                *Kind           `json:"kind,omitempty"`
	DisplayName         *string         `json:"display_name,omitempty"`
	AddressNamespace    *string         `json:"address_namespace,omitempty"`
	Endpoint            *Endpoint       `json:"endpoint,omitempty"`
	AddressSuffix       *string         `json:"address_suffix,omitempty"`
	Enabled             *bool           `json:"enabled,omitempty"`
	Credentials         *Credentials    `json:"credentials,omitempty"`
	Apple               *PrincipalInput `json:"apple,omitempty"`
	RequireSourceChange bool            `json:"require_source_change"`
}

type Revealed struct {
	Source      Metadata    `json:"source"`
	Credentials Credentials `json:"credentials"`
}

type DeleteResult struct {
	OperationKey string `json:"operation_key"`
	SourceID     int64  `json:"source_id"`
	Deleted      bool   `json:"deleted"`
}
