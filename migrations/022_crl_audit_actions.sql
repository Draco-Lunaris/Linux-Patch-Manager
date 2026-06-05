-- Migration: 022_crl_audit_actions
-- Description: Add audit_action enum values for CRL health aggregation events.
--              These are system-initiated events logged by the health poller
--              when a host's CRL status transitions or indicates a problem.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'crl_status_changed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'crl_stale_detected';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'crl_invalid';
