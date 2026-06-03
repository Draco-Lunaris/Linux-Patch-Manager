-- Migration: 019_auth_config_audit_actions
-- Description: Add audit_action enum values for Manager-wide auth-config
--              mutations (issue #5). These are gated behind Admin role
--              and audit-logged with the acting user, the keys changed,
--              and (for OIDC) a flag indicating whether client_secret was
--              rotated (the secret value itself is never logged).

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'oidc_config_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'smtp_config_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'ip_whitelist_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'oidc_test_performed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'oidc_discover_performed';
