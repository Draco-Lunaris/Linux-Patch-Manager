-- Migration: 026_os_package_mapping_audit_actions
-- Description: Add audit_action enum values for OS package mapping CRUD.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'os_package_mapping_created';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'os_package_mapping_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'os_package_mapping_deleted';
