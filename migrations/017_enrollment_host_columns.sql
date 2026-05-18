-- Migration: 017_enrollment_host_columns
-- Add missing columns for enrollment support
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS machine_id TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS ip_address INET;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS key_pem TEXT;
