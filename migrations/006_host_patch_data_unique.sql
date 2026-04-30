-- Migration 006: Add UNIQUE constraint on host_id in host_patch_data
-- Clean up duplicate rows (keep latest polled_at per host) before adding constraint.

-- Step 1: Delete duplicate rows, keeping only the most recent poll per host
DELETE FROM host_patch_data a
USING host_patch_data b
WHERE a.host_id = b.host_id
  AND a.polled_at < b.polled_at;

-- Step 2: Add UNIQUE constraint on host_id
ALTER TABLE host_patch_data
  ADD CONSTRAINT host_patch_data_host_id_key UNIQUE (host_id);
