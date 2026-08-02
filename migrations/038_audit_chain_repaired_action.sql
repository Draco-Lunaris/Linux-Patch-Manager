-- Migration: 038_audit_chain_repaired_action
-- Description: Add audit_action enum value for audit chain repair events.
--              Used when an admin repairs the audit hash chain via the
--              /api/v1/settings/audit-integrity/repair endpoint (issue #160).

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'audit_chain_repaired';