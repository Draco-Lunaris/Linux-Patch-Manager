-- Migration 037: Add auto_reboot and reboot_delay_minutes to maintenance_windows
-- Allows configuring automatic reboot behavior for auto-created patch jobs.
-- Defaults preserve historical behavior: auto_reboot=true, reboot_delay_minutes=0 (immediate).

ALTER TABLE maintenance_windows
    ADD COLUMN IF NOT EXISTS auto_reboot BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS reboot_delay_minutes INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN maintenance_windows.auto_reboot IS
    'When true and auto_apply = true, auto-created patch jobs will have allow_reboot = true. When false, auto-created jobs will have allow_reboot = false regardless of patch requirements.';

COMMENT ON COLUMN maintenance_windows.reboot_delay_minutes IS
    'Delay in minutes before triggering automatic reboot after patching for auto-created jobs. 0 = immediate reboot via systemctl reboot. >0 = delayed reboot via shutdown -r +N. Only used when auto_apply = true and auto_reboot = true.';