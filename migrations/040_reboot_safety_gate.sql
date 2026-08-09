-- Migration 040: Reboot safety gate.
--
-- (1) hosts.package_db_clean — persisted from the agent's read-only
--     `dpkg --audit` (exposed on /api/v1/system/info as package_db_clean by
--     the agent). The manager refuses to reboot a host whose package database
--     is not clean (half-configured / unpacked / failed packages — especially
--     a kernel whose postinst never ran), so a host is never rebooted into an
--     unbootable state. Mirrors hosts.pending_reboot (migration 034). Default
--     true (fail-open): older agents that don't report the field are treated
--     as clean.
-- (2) hosts.reboot_paused — an ad-hoc, per-host operator toggle that blocks
--     ALL reboots (explicit Reboot jobs and auto-reboot-after-patching) for
--     the host regardless of maintenance windows / patch jobs. This is the
--     "do not reboot this host while I recover it" switch used during
--     half-configured-package recovery. Default false.
-- (3) audit_action 'reboot_refused' — recorded when the manager refuses to
--     issue a reboot because the host is reboot_paused or its package database
--     is not clean.

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS package_db_clean BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS reboot_paused BOOLEAN NOT NULL DEFAULT false;

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'reboot_refused';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'host_updated';

COMMENT ON COLUMN hosts.package_db_clean IS
    'True when the agent reports no half-configured / unpacked / failed packages (read-only dpkg --audit). The manager refuses to reboot a host where this is false. Default true (fail-open for older agents).';
COMMENT ON COLUMN hosts.reboot_paused IS
    'Operator toggle: when true, the manager refuses to issue any reboot (explicit or auto) for this host. Used to safely recover a half-configured host without the manager rebooting it mid-recovery. Default false.';