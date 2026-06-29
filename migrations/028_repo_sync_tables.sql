-- 028_repo_sync_tables.sql
-- Manager-hosted package repository sync tracking (issue #116)
-- Tables for tracking package sync from GitHub Releases to manager repo.

-- Repo sync log: tracks each sync run (scheduled or manual)
CREATE TABLE IF NOT EXISTS repo_sync_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    triggered_by    TEXT NOT NULL DEFAULT 'scheduler',  -- 'scheduler' | 'manual' | 'ci'
    status          TEXT NOT NULL DEFAULT 'running',   -- 'running' | 'success' | 'failed' | 'partial'
    packages_synced INTEGER NOT NULL DEFAULT 0,
    packages_skipped INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_repo_sync_log_started ON repo_sync_log (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_repo_sync_log_status ON repo_sync_log (status);

-- Repo packages: tracks individual packages in the manager-hosted repo
CREATE TABLE IF NOT EXISTS repo_packages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename        TEXT NOT NULL,
    version         TEXT NOT NULL,
    distro          TEXT NOT NULL,          -- 'apt', 'dnf', 'apk', 'pacman'
    distro_codename TEXT,                   -- 'noble', 'jammy', 'bookworm', 'el9', 'v3.21', etc.
    arch            TEXT NOT NULL DEFAULT 'amd64',
    file_size       BIGINT,
    sha256          TEXT,
    gpg_signed      BOOLEAN NOT NULL DEFAULT FALSE,
    source          TEXT NOT NULL DEFAULT 'github',  -- 'github' | 'manual' | 'ci'
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sync_log_id     UUID REFERENCES repo_sync_log(id) ON DELETE SET NULL,
    UNIQUE (filename, version, distro, arch)
);

CREATE INDEX IF NOT EXISTS idx_repo_packages_distro ON repo_packages (distro, distro_codename);
CREATE INDEX IF NOT EXISTS idx_repo_packages_version ON repo_packages (version DESC);
CREATE INDEX IF NOT EXISTS idx_repo_packages_synced ON repo_packages (synced_at DESC);

-- Add audit actions for repo sync events
INSERT INTO audit_action (action) VALUES
    ('repo_sync_started'),
    ('repo_sync_completed'),
    ('repo_sync_failed'),
    ('repo_package_uploaded'),
    ('repo_package_deleted'),
    ('repo_metadata_refreshed'),
    ('gpg_key_rotated')
ON CONFLICT (action) DO NOTHING;

-- Add GPG key health columns to hosts table (M15)
-- Tracks GPG key status reported by agents during health checks
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS gpg_key_status TEXT;
-- Values: 'valid', 'expired', 'missing', 'revoked', or NULL (older agent)
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS gpg_key_expires_at TIMESTAMPTZ;
