-- Migration: 005_audit_hardening
-- Description: Add prev_hash column to audit_log for full hash chaining,
--              add notification config defaults to system_config, add new
--              audit_action enum values, and add audit_integrity_last_verified.

-- ============================================================
-- 1. Add prev_hash column to audit_log
-- ============================================================
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';

-- ============================================================
-- 2. Add notification config defaults to system_config
-- ============================================================
INSERT INTO system_config (key, value, updated_at)
VALUES
    ('notification_email_enabled', 'false', NOW()),
    ('notification_email_from', 'patch-manager@localhost', NOW()),
    ('notification_email_recipients', '[]', NOW()),
    ('audit_integrity_last_verified', '', NOW())
ON CONFLICT (key) DO NOTHING;

-- ============================================================
-- 3. Add new audit_action enum values
-- ============================================================
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'audit_integrity_verified';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'email_notification_sent';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'patch_job_completed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'patch_job_failed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'maintenance_window_reminder';
