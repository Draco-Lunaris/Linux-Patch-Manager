-- 021_crl_health_status.sql
-- Add CRL health status columns to the hosts table for tracking
-- Certificate Revocation List status reported by agents.

-- CRL status values: 'valid', 'expired', 'missing', 'invalid', or NULL
-- (NULL = older agent that does not report CRL status)
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS crl_status TEXT;

-- Seconds since the agent's CRL was last refreshed (NULL if not reported)
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS crl_age_seconds BIGINT;

-- When the agent's CRL expires / next update is due (NULL if not reported)
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS crl_next_update TIMESTAMPTZ;
