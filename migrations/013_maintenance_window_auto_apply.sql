-- Migration 013: Add auto_apply flag to maintenance windows
-- When true, the maintenance scheduler will automatically create a patch_apply job
-- for the host when the window opens and patches are pending.

ALTER TABLE maintenance_windows
  ADD COLUMN IF NOT EXISTS auto_apply boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN maintenance_windows.auto_apply IS 'When true, automatically create a patch_apply job when this window opens and the host has pending patches.';
