-- Migration 036: Add reboot_delay_seconds to patch_jobs
-- Allows configuring the delay before automatic reboot after patching.
-- Defaults to 0 (immediate reboot) to preserve historical behavior.

ALTER TABLE patch_jobs
    ADD COLUMN IF NOT EXISTS reboot_delay_seconds BIGINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN patch_jobs.reboot_delay_seconds IS
    'Delay in seconds before triggering automatic reboot after patching. 0 = immediate reboot via systemctl reboot. >0 = delayed reboot via shutdown -r +N (minutes). Only used when allow_reboot = true and a reboot is actually required.';