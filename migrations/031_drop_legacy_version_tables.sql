-- 031_drop_legacy_version_tables.sql
-- Drop the legacy available_versions and os_package_mappings tables.
-- These were used by the pre-repo self-upgrade flow which sourced
-- version metadata directly from the GitHub Releases API. The
-- manager-hosted package repository (repo_packages table) is now the
-- single source of truth for available agent versions, filtered by
-- the host's OS → (distro, codename) mapping computed in Rust.

DROP TABLE IF EXISTS available_versions;
DROP TABLE IF EXISTS os_package_mappings;
