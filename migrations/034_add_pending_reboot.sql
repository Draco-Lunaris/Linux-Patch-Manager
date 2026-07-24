-- 034_add_pending_reboot.sql
-- Add pending_reboot column to hosts table, populated from agent system info.
-- The health poller fetches /system/info which includes pending_reboot, but
-- previously discarded it.  This column persists that field so the dashboard
-- "Hosts Requiring Reboot" stat reflects actual reboot state.

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS pending_reboot BOOLEAN NOT NULL DEFAULT false;