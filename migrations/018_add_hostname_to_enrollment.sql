-- Migration: 018_add_hostname_to_enrollment
-- Add hostname column to enrollment_requests for proper display name
ALTER TABLE enrollment_requests ADD COLUMN IF NOT EXISTS hostname TEXT;
