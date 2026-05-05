-- Add certificate_reissued audit_action enum value
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'certificate_reissued';
