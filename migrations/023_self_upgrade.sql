-- Migration: Add self_upgrade job kind and available_versions cache table
-- Issues: #89, #90

-- Add self_upgrade to job_kind enum
ALTER TYPE job_kind ADD VALUE IF NOT EXISTS 'self_upgrade';

-- Available versions cache table
-- Stores release information fetched from GitHub
CREATE TABLE IF NOT EXISTS available_versions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version             TEXT NOT NULL,
    download_url        TEXT NOT NULL,
    checksum            TEXT,
    file_name           TEXT NOT NULL,
    source              TEXT NOT NULL DEFAULT 'github',
    prerelease          BOOLEAN NOT NULL DEFAULT FALSE,
    published_at        TIMESTAMPTZ,
    fetched_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (version, source)
);

CREATE INDEX IF NOT EXISTS idx_available_versions_version ON available_versions (version);
CREATE INDEX IF NOT EXISTS idx_available_versions_source ON available_versions (source);
CREATE INDEX IF NOT EXISTS idx_available_versions_fetched ON available_versions (fetched_at DESC);
