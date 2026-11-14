-- Public mailbox protocol settings use explicit installation defaults.
-- This migration creates settings storage only.
-- No credential or business rows are synthesized.
CREATE TABLE space.public_http_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    timezone text NOT NULL DEFAULT 'Local' CHECK (timezone <> ''),
    otp_latest_only boolean NOT NULL DEFAULT false,
    poll_interval_ns bigint NOT NULL DEFAULT 10000000000 CHECK (poll_interval_ns > 0 AND poll_interval_ns <= 86400000000000),
    sync_timeout_ns bigint NOT NULL DEFAULT 70000000000 CHECK (sync_timeout_ns > 0 AND sync_timeout_ns <= 86400000000000)
);
