package mailview

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"icloudspace/internal/addressauth"
)

var ErrSyncUnavailable = errors.New("mailview: current synchronization unavailable")

type PublicSettings struct {
	Timezone                  string
	LatestOnly                bool
	PollInterval, SyncTimeout time.Duration
}

func (s *Service) PublicRawCandidates(ctx context.Context, lease *addressauth.Lease, page Page) (MessagePage, error) {
	id, err := s.allow(lease, addressauth.RawRead)
	if err != nil {
		return MessagePage{}, err
	}
	if err = s.observe(ctx, id); err != nil {
		return MessagePage{}, err
	}
	return s.listOrdered(ctx, id, page, true)
}

func (s *Service) PublicSettings(ctx context.Context) (PublicSettings, error) {
	var out PublicSettings
	var poll, timeout int64
	err := s.db.QueryRowContext(ctx, `SELECT coalesce((SELECT timezone FROM space.public_http_settings WHERE singleton),'Local'),coalesce((SELECT otp_latest_only FROM space.public_http_settings WHERE singleton),false),coalesce((SELECT poll_interval_ns FROM space.public_http_settings WHERE singleton),10000000000),coalesce((SELECT sync_timeout_ns FROM space.public_http_settings WHERE singleton),70000000000)`).Scan(&out.Timezone, &out.LatestOnly, &poll, &timeout)
	if err != nil {
		return out, storage(ctx)
	}
	if _, err = time.LoadLocation(out.Timezone); err != nil {
		return out, ErrMetadata
	}
	out.PollInterval, out.SyncTimeout = time.Duration(poll), time.Duration(timeout)
	return out, nil
}

// PublicFreshness projects the current source round outcome. Address sync
// columns are historical import facts; new rounds are owned by mail_sources.
func (s *Service) PublicFreshness(ctx context.Context, lease *addressauth.Lease, settings PublicSettings) (int64, error) {
	id, err := s.allow(lease, addressauth.LatestRead, addressauth.MailRead, addressauth.MailConsume, addressauth.RecentConsume)
	if err != nil {
		return 0, err
	}
	if err = s.observe(ctx, id); err != nil {
		return 0, err
	}
	var state string
	var synced sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT CASE WHEN s.last_synced_at IS NOT NULL AND (a.last_synced_at IS NULL OR s.last_synced_at>=a.last_synced_at) THEN s.last_sync_state ELSE a.last_sync_state END,CASE WHEN s.last_synced_at IS NOT NULL AND (a.last_synced_at IS NULL OR s.last_synced_at>=a.last_synced_at) THEN s.last_synced_at ELSE a.last_synced_at END FROM space.private_addresses a JOIN space.mail_sources s ON s.id=a.source_id WHERE a.source_id=$1 AND a.id=$2 AND s.source_generation=$3`, id.SourceID, id.AddressID, id.SourceGeneration).Scan(&state, &synced)
	if err != nil {
		return 0, storage(ctx)
	}
	now := s.options.Clock()
	maxAge := 3 * settings.PollInterval
	if other := settings.SyncTimeout + 2*settings.PollInterval; other > maxAge {
		maxAge = other
	}
	if (state != "ok" && state != "succeeded" && state != "mail_succeeded") || !synced.Valid || synced.Int64 > now || now-synced.Int64 > int64(maxAge) {
		return 0, ErrSyncUnavailable
	}
	return synced.Int64, nil
}
