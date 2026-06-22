-- Migration: 027_prevent_duplicate_auto_jobs
-- Description: Prevent duplicate auto-created patch_apply jobs for the same
--              host + maintenance window during a single window cycle.
--
-- This migration provides DB-level enforcement to backstop the code-level
-- dedup check in maintenance_scheduler.rs auto_create_patch_jobs().
--
-- Approach:
-- 1. Add an `auto_host_id` column to patch_jobs (nullable, populated only by
--    the maintenance scheduler for auto-created single-host jobs).
-- 2. Create a partial unique index on (maintenance_window_id, auto_host_id)
--    for active (non-terminal) auto-created patch_apply jobs.
--
-- This prevents two concurrent active auto-jobs for the same window+host
-- (race condition backstop). The code-level cycle-aware check is the primary
-- dedup — it blocks new auto-jobs for the same window+host in the current
-- cycle even after the previous job reaches a terminal state.

-- Add host_id to patch_jobs for auto-created single-host jobs (nullable,
-- populated only by the maintenance scheduler for auto-created jobs).
ALTER TABLE patch_jobs
    ADD COLUMN IF NOT EXISTS auto_host_id UUID REFERENCES hosts(id) ON DELETE SET NULL;

-- Partial unique index: one active auto-created patch_apply job per
-- (maintenance_window_id, auto_host_id) at a time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_autojob_per_window_host
    ON patch_jobs (maintenance_window_id, auto_host_id)
    WHERE kind = 'patch_apply'
      AND created_by_user_id IS NULL
      AND status IN ('queued', 'running', 'pending');
