-- Migration: 024_upgrade_audit_actions
-- Description: Add audit_action enum values for self-upgrade management.
-- Issues: #89, #90

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'upgrade_triggered';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'batch_upgrade_triggered';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'upgrade_version_refreshed';
