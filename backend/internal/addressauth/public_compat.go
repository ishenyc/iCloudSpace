package addressauth

import (
	"context"
	"errors"

	"icloudspace/internal/vault"
)

// RecentConsume is admitted only through the recent-mail endpoint. It can read
// and consume the current snapshot, never history, raw, OAuth or IMAP.
const RecentConsume Purpose = "compat_recent_consume"

func (a *Authority) CompatibilityOTPToken(addressID int64, key string) (string, error) {
	if a == nil || !validSecret(key) {
		return "", ErrInvalid
	}
	hash := Hash(key)
	return a.box.PublicLink(13, addressID, hash[:])
}
func (a *Authority) CompatibilityRecentToken(addressID int64, key string) (string, error) {
	if a == nil || !validSecret(key) {
		return "", ErrInvalid
	}
	hash := Hash(key)
	return a.box.PublicLink(12, addressID, hash[:])
}
func (a *Authority) CompatibilityLegacyToken(addressID int64, key string) (string, error) {
	if a == nil || !validSecret(key) {
		return "", ErrInvalid
	}
	hash := Hash(key)
	return a.box.PublicLink(11, addressID, hash[:])
}

// AuthenticateRecent restricts latest_read keys to a single current snapshot.
// Consume always compares that exact snapshot under row locks.
func (a *Authority) AuthenticateRecent(ctx context.Context, key string) (*Lease, error) {
	lease, err := a.Authenticate(ctx, Credential{Kind: APIKey, Raw: key}, MailConsume, Selector{})
	if !errors.Is(err, ErrUnauthenticated) {
		return lease, err
	}
	lease, err = a.Authenticate(ctx, Credential{Kind: APIKey, Raw: key}, LatestRead, Selector{})
	if err == nil {
		lease.purpose = RecentConsume
	}
	return lease, err
}

// AuthenticatePublicLink validates the published purpose before resolving a
// live canonical API-key grant. The URL token is never an opaque access grant.
func (a *Authority) AuthenticatePublicLink(ctx context.Context, token string, purpose Purpose) (*Lease, error) {
	id, version, ok := vault.PublicLinkIdentity(token)
	if a == nil || !ok {
		return nil, ErrUnauthenticated
	}
	wanted := purpose
	if purpose == RecentConsume {
		if version != 1 && version != 2 && version != 11 && version != 12 {
			return nil, ErrUnauthenticated
		}
	} else if purpose == MailRead || purpose == RawRead {
		if version != 3 && version != 13 {
			return nil, ErrUnauthenticated
		}
	} else {
		return nil, ErrUnauthenticated
	}
	release, err := a.gate.read(ctx)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	if !a.readReady() {
		return nil, ErrOutcomeUnknown
	}
	rows, err := a.db.QueryContext(ctx, `SELECT DISTINCT authenticator_hash FROM space.address_grants WHERE address_id=$1 AND authenticator_kind='api_key' AND hash_scheme=$2 AND hash_version=$3 AND parent_grant_id IS NULL AND auth_generation=(SELECT auth_generation FROM space.private_addresses WHERE id=$1) AND revoked_at IS NULL AND issued_at<=$4 AND (expires_at IS NULL OR expires_at>$4) AND purpose IN ('latest_read','mail_read','mail_consume','raw_read')`, id, HashScheme, HashVersion, a.clock())
	if err != nil {
		return nil, storageError(ctx)
	}
	var matched [32]byte
	found := false
	for rows.Next() {
		var hash []byte
		if rows.Scan(&hash) != nil {
			rows.Close()
			return nil, ErrStorage
		}
		if len(hash) == 32 && a.box.VerifyPublicLink(token, hash) {
			copy(matched[:], hash)
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, storageError(ctx)
	}
	if !found {
		return nil, ErrUnauthenticated
	}
	if wanted == RecentConsume {
		purpose = MailConsume
		if version == 1 || version == 11 {
			purpose = LatestRead
		}
	}
	state, err := a.resolveStateWith(ctx, a.db, APIKey, matched, purpose, Selector{AddressID: id}, a.clock())
	if err != nil {
		return nil, err
	}
	lease := a.newLease(state, APIKey, matched, purpose, release)
	if wanted == RecentConsume && purpose == LatestRead {
		lease.purpose = RecentConsume
	}
	success = true
	return lease, nil
}
