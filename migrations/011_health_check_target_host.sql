-- Add target_host_id to health checks, allowing a check on Host A
-- to query a service on Host B's agent (for redundant services).
-- NULL = check own host (backward compatible).
-- FK with ON DELETE SET NULL: if target host deleted, revert to default.

ALTER TABLE host_health_checks
  ADD COLUMN IF NOT EXISTS target_host_id UUID REFERENCES hosts(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_health_checks_target_host ON host_health_checks (target_host_id)
  WHERE target_host_id IS NOT NULL;
