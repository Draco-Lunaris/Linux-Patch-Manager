-- 030_add_published_at_to_repo_packages.sql
-- Add published_at to repo_packages so version resolution can sort by
-- release date (replacing the published_at column previously on
-- available_versions). Populated by the package sync worker from the
-- GitHub release's published_at field.

ALTER TABLE repo_packages ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_repo_packages_published_at
    ON repo_packages (published_at DESC);
