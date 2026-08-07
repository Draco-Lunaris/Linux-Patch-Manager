-- 039_package_sync_auto_enabled.sql
-- Description: Add a runtime-toggleable flag to enable/disable the automatic
--              hourly package sync worker without restarting pm-worker.
--              The TOML config [worker.package_sync] enabled flag is still
--              consulted at startup (kill switch), but this DB row is checked
--              on every sync tick so operators can pause/resume auto-sync
--              from the UI without a restart.
--              Default 'true' preserves existing behavior for deployments
--              where the TOML worker.package_sync.enabled = true.

INSERT INTO system_config (key, value, description)
VALUES ('package_sync_auto_enabled', 'true', 'Runtime toggle for the automatic package sync worker. When false, the hourly GitHub Releases pull is skipped (manual syncs still work).')
ON CONFLICT (key) DO NOTHING;