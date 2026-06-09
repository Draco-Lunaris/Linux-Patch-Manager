-- Migration: 003_jobs_scheduling
-- Description: Retry/scheduling columns for patch_job_hosts, and NOTIFY trigger
--              for immediate patch job dispatch.

-- ============================================================
-- Add retry-scheduling columns to patch_job_hosts
-- ============================================================

-- When the retry engine should next attempt this host; NULL = not scheduled
ALTER TABLE patch_job_hosts
    ADD COLUMN IF NOT EXISTS retry_next_at TIMESTAMPTZ;

-- Last failure reason captured by the worker for display in the UI
ALTER TABLE patch_job_hosts
    ADD COLUMN IF NOT EXISTS last_error TEXT;

-- ============================================================
-- pg_notify trigger: fires when an immediate job is inserted
-- ============================================================

CREATE OR REPLACE FUNCTION notify_job_enqueued()
    RETURNS TRIGGER
    LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.immediate = TRUE THEN
        PERFORM pg_notify('job_enqueued', NEW.id::text);
    END IF;
    RETURN NEW;
END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_job_enqueued'
    ) THEN
        CREATE TRIGGER trg_job_enqueued
            AFTER INSERT ON patch_jobs
            FOR EACH ROW
            EXECUTE FUNCTION notify_job_enqueued();
    END IF;
END $$;

-- ============================================================
-- Index: efficiently find hosts due for retry
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_pjh_retry
    ON patch_job_hosts (retry_next_at)
    WHERE retry_next_at IS NOT NULL;
