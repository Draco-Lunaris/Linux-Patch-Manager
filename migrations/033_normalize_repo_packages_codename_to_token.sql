-- 033_normalize_repo_packages_codename_to_token.sql
-- Normalize distro_codename from apt codenames (noble, jammy, bookworm,
-- trixie, resolute) to filename tokens (u2404, u2204, debian12, debian13,
-- u2604) so that repo_packages rows match the new map_os_to_distro output.
--
-- Issue #163 / PR #164: the apt suite name is now the filename token itself.
-- Without this migration, the first upgrade attempt after deploying the new
-- manager would fail because map_os_to_distro returns 'u2404' but the DB
-- still has 'noble'. The ON CONFLICT DO UPDATE in the sync worker only fires
-- on the next sync, which may not have run yet.

UPDATE repo_packages
SET distro_codename = CASE distro_codename
    WHEN 'noble'     THEN 'u2404'
    WHEN 'jammy'     THEN 'u2204'
    WHEN 'resolute'  THEN 'u2604'
    WHEN 'bookworm'  THEN 'debian12'
    WHEN 'trixie'    THEN 'debian13'
    ELSE distro_codename
END
WHERE distro = 'apt'
  AND distro_codename IN ('noble', 'jammy', 'resolute', 'bookworm', 'trixie');