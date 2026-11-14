package externalregistration

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"icloudspace/internal/addresses"
)

// RegisterByEmail resolves the source account by email and uses the same
// registration transaction as the typed API. It performs no provider request
// and never retries an uncertain registration.
func (s *Service) RegisterByEmail(ctx context.Context, access Access, address, email, operation string) (*Delivery, error) {
	if !s.authorized(access) {
		return nil, ErrUnauthorized
	}
	address, err := addresses.NormalizeAddress(address)
	if err != nil {
		return nil, ErrInvalid
	}
	email, err = addresses.NormalizeAddress(email)
	if err != nil {
		return nil, ErrInvalid
	}
	var source int64
	err = s.db.QueryRowContext(ctx, `SELECT id FROM space.mail_sources WHERE lower(address_namespace)=$1 AND retired_at IS NULL`, email).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, storage(ctx)
	}
	return s.Register(ctx, access, Request{SourceID: source, Address: address, OperationKey: operation, sourceEmail: email})
}

// compatibilityInput validates the selected source and address identity under
// Register's source guard and SQL row lock. Address and credential ownership
// remains with the registration transaction.
func compatibilityInput(ctx context.Context, tx *sql.Tx, input Request) error {
	if input.sourceEmail == "" {
		return nil
	}
	var email, username string
	if tx.QueryRowContext(ctx, `SELECT lower(address_namespace),imap_username FROM space.mail_sources WHERE id=$1 AND retired_at IS NULL`, input.SourceID).Scan(&email, &username) != nil {
		return storage(ctx)
	}
	if email != input.sourceEmail {
		return ErrNotFound
	}
	var sourceIdentity, existing bool
	if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.mail_sources WHERE lower(address_namespace)=$1 AND retired_at IS NULL),EXISTS(SELECT 1 FROM space.private_addresses WHERE normalized_email=$1)`, input.Address).Scan(&sourceIdentity, &existing) != nil {
		return storage(ctx)
	}
	if sourceIdentity || input.Address == strings.ToLower(strings.TrimSpace(username)) {
		return ErrIdentityConflict
	}
	if existing {
		return ErrAddressExists
	}
	return nil
}

// RecentToken exposes only a purpose-bound direct link for the just-returned
// committed delivery. The deployment capability does not become mailbox auth.
func (s *Service) RecentToken(access Access, delivery *Delivery) (string, error) {
	if !s.authorized(access) {
		return "", ErrUnauthorized
	}
	if delivery == nil || delivery.Bundle == nil || !delivery.Receipt.Available || delivery.Receipt.State != "committed" {
		return "", ErrNotFound
	}
	return s.authority.CompatibilityRecentToken(delivery.Receipt.AddressID, delivery.Bundle.API.Key)
}
