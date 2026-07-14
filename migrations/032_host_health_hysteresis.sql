-- 030_host_health_hysteresis.sql
-- Add consecutive_failures column to track health check failure streaks.
-- Used by the health poller to implement hysteresis: a host is only marked
-- unreachable after N consecutive failures, preventing flapping from
-- transient network blips.

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0;