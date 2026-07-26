-- 035_add_allow_reboot_to_patch_jobs.sql
-- Persist the allow_reboot flag on patch_jobs so the job executor can honor
-- the operator's choice (or the maintenance window default) when dispatching
-- patch_apply jobs to agents.  Previously the executor hardcoded
-- allow_reboot: true, ignoring the UI checkbox and the maintenance window
-- intent.  Defaulting to TRUE preserves the historical behavior for existing
-- rows and for auto-created maintenance window jobs (which do not set it
-- explicitly), while allowing operators to opt out of automatic reboots on
-- demand.

ALTER TABLE patch_jobs
    ADD COLUMN IF NOT EXISTS allow_reboot BOOLEAN NOT NULL DEFAULT TRUE;

COMMENT ON COLUMN patch_jobs.allow_reboot IS
    'When true, the agent is permitted to reboot the host after patching if a reboot is required (kernel/glibc/etc. update).';