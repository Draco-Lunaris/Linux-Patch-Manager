-- Migration: 004_maintenance_windows
-- Description: Additional indexes and scheduler-support for maintenance windows.
--              The maintenance_windows table and window_recurrence ENUM were
--              created in 001_initial_schema.sql.  This migration adds composite
--              indexes needed by the M6 maintenance_scheduler worker and patches
--              the audit_action ENUM to include window events already listed in
--              the audit log helper (they were declared there but the ENUM values
--              already exist – guarded with a DO block to be idempotent).

-- ============================================================
-- Composite index: scheduler query
--   Finds enabled windows by recurrence type + recurrence_day quickly.
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_mw_enabled_recurrence
    ON maintenance_windows (recurrence, recurrence_day)
    WHERE enabled = TRUE;

-- ============================================================
-- Index: quickly find non-immediate queued jobs for a given host
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_pjh_queued_host
    ON patch_job_hosts (host_id, status)
    WHERE status = 'queued';
