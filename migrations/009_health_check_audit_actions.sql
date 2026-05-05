-- Add health check audit_action enum values
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'health_check_created';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'health_check_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'health_check_deleted';
