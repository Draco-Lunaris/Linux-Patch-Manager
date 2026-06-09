-- Migration: 001_initial_schema
-- Description: Full initial schema for Linux Patch Manager
-- All tables, indexes, and constraints in a single initial migration.

-- ============================================================
-- Extensions
-- ============================================================
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_bytes, crypt
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- fuzzy text search on host names

-- ============================================================
-- Enumerations
-- ============================================================

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE user_role AS ENUM ('admin', 'operator');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'auth_provider') THEN
        CREATE TYPE auth_provider AS ENUM ('local', 'azure_sso');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'host_health_status') THEN
        CREATE TYPE host_health_status AS ENUM ('pending', 'healthy', 'degraded', 'unreachable');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_status') THEN
        CREATE TYPE job_status AS ENUM ('queued', 'pending', 'running', 'succeeded', 'failed', 'cancelled');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_kind') THEN
        CREATE TYPE job_kind AS ENUM ('patch_apply', 'patch_remove', 'reboot', 'rollback');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'window_recurrence') THEN
        CREATE TYPE window_recurrence AS ENUM ('once', 'daily', 'weekly', 'monthly');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'cert_status') THEN
        CREATE TYPE cert_status AS ENUM ('active', 'revoked', 'expired');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'audit_action') THEN
        CREATE TYPE audit_action AS ENUM (
            'user_login', 'user_logout', 'user_login_failed',
            'user_created', 'user_deleted', 'user_updated',
            'host_registered', 'host_removed',
            'group_created', 'group_deleted',
            'group_membership_changed',
            'patch_job_created', 'patch_job_cancelled', 'patch_job_rollback',
            'maintenance_window_created', 'maintenance_window_updated', 'maintenance_window_deleted',
            'certificate_issued', 'certificate_renewed', 'certificate_revoked', 'certificate_downloaded',
            'config_changed',
            'discovery_scan_started'
        );
    END IF;
END $$;

-- ============================================================
-- Groups (defined before users/hosts for FK ordering)
-- ============================================================

CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_groups_name ON groups (name);

-- ============================================================
-- Users
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username            TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL DEFAULT '',
    email               TEXT NOT NULL UNIQUE,
    role                user_role NOT NULL DEFAULT 'operator',
    auth_provider       auth_provider NOT NULL DEFAULT 'local',
    -- Local auth fields (NULL for SSO-only users)
    password_hash       TEXT,
    -- MFA
    totp_secret         TEXT,          -- NULL = TOTP not configured
    webauthn_credential JSONB,         -- NULL = WebAuthn not configured
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    -- Azure SSO
    azure_oid           TEXT UNIQUE,   -- Azure Object ID
    -- Account state
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    force_password_reset BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_azure_oid ON users (azure_oid) WHERE azure_oid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);

-- ============================================================
-- User <-> Group membership
-- ============================================================

CREATE TABLE IF NOT EXISTS user_groups (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id   UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups (group_id);

-- ============================================================
-- Refresh Tokens
-- ============================================================

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Stored as Argon2id hash of the opaque token bytes
    token_hash      TEXT NOT NULL UNIQUE,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- 1-hour sliding inactivity window; updated on each use
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour',
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    user_agent      TEXT,
    ip_address      INET
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens (expires_at) WHERE revoked = FALSE;

-- ============================================================
-- Hosts
-- ============================================================

CREATE TABLE IF NOT EXISTS hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fqdn            TEXT NOT NULL,
    ip_address      INET NOT NULL,
    display_name    TEXT NOT NULL DEFAULT '',
    os_family       TEXT,          -- debian, rhel, alpine, arch
    os_name         TEXT,          -- e.g. "Ubuntu 24.04"
    arch            TEXT,          -- x86_64, aarch64, etc.
    agent_version   TEXT,
    health_status   host_health_status NOT NULL DEFAULT 'pending',
    last_health_at  TIMESTAMPTZ,
    last_patch_at   TIMESTAMPTZ,
    -- Agent port (default 12443)
    agent_port      INTEGER NOT NULL DEFAULT 12443,
    notes           TEXT NOT NULL DEFAULT '',
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT hosts_fqdn_ip_unique UNIQUE (fqdn, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_hosts_health_status ON hosts (health_status);
CREATE INDEX IF NOT EXISTS idx_hosts_fqdn ON hosts USING gin (fqdn gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts (ip_address);

-- ============================================================
-- Host <-> Group membership
-- ============================================================

CREATE TABLE IF NOT EXISTS host_groups (
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (host_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_host_groups_group ON host_groups (group_id);

-- ============================================================
-- Host Health Data (cached results from 5-min polls)
-- ============================================================

CREATE TABLE IF NOT EXISTS host_health_data (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    polled_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status      host_health_status NOT NULL,
    -- Raw JSON response from agent GET /api/v1/health
    payload     JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_host_health_host ON host_health_data (host_id, polled_at DESC);
-- Retained for 30 days (pruned by worker)

-- ============================================================
-- Host Patch Data (cached results from 30-min polls)
-- ============================================================

CREATE TABLE IF NOT EXISTS host_patch_data (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    polled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Raw JSON response from agent GET /api/v1/patches
    available_patches JSONB NOT NULL DEFAULT '[]',
    installed_packages JSONB NOT NULL DEFAULT '[]',
    patch_count     INTEGER NOT NULL DEFAULT 0,
    cve_count       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_host_patch_host ON host_patch_data (host_id, polled_at DESC);
-- Retained for 30 days (pruned by worker)

-- ============================================================
-- Maintenance Windows
-- ============================================================

CREATE TABLE IF NOT EXISTS maintenance_windows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    label           TEXT NOT NULL DEFAULT '',
    recurrence      window_recurrence NOT NULL DEFAULT 'once',
    -- Start time (UTC)
    start_at        TIMESTAMPTZ NOT NULL,
    -- Duration in minutes
    duration_minutes INTEGER NOT NULL DEFAULT 60,
    -- For recurring windows: day-of-week (0=Sun) or day-of-month
    recurrence_day  INTEGER,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mw_host ON maintenance_windows (host_id);
CREATE INDEX IF NOT EXISTS idx_mw_start ON maintenance_windows (start_at) WHERE enabled = TRUE;

-- ============================================================
-- Patch Jobs
-- ============================================================

CREATE TABLE IF NOT EXISTS patch_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                job_kind NOT NULL DEFAULT 'patch_apply',
    status              job_status NOT NULL DEFAULT 'queued',
    created_by_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    -- For rollback jobs: reference to original job
    parent_job_id       UUID REFERENCES patch_jobs(id) ON DELETE SET NULL,
    -- Optional: restrict to a specific maintenance window
    maintenance_window_id UUID REFERENCES maintenance_windows(id) ON DELETE SET NULL,
    -- Immediate apply if TRUE; else queued for next window
    immediate           BOOLEAN NOT NULL DEFAULT FALSE,
    -- Patch selection (list of package names / CVE IDs)
    patch_selection     JSONB NOT NULL DEFAULT '[]',
    notes               TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_patch_jobs_status ON patch_jobs (status);
CREATE INDEX IF NOT EXISTS idx_patch_jobs_created ON patch_jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_patch_jobs_user ON patch_jobs (created_by_user_id);

-- ============================================================
-- Patch Job Hosts (per-host status within a batch job)
-- ============================================================

CREATE TABLE IF NOT EXISTS patch_job_hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL REFERENCES patch_jobs(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status          job_status NOT NULL DEFAULT 'queued',
    -- Agent-assigned async job ID
    agent_job_id    TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    -- Output / error from agent
    output          TEXT NOT NULL DEFAULT '',
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    UNIQUE (job_id, host_id)
);

CREATE INDEX IF NOT EXISTS idx_pjh_job ON patch_job_hosts (job_id);
CREATE INDEX IF NOT EXISTS idx_pjh_host ON patch_job_hosts (host_id);
CREATE INDEX IF NOT EXISTS idx_pjh_status ON patch_job_hosts (status);

-- ============================================================
-- Certificates
-- ============================================================

CREATE TABLE IF NOT EXISTS certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL = root CA cert
    host_id         UUID REFERENCES hosts(id) ON DELETE CASCADE,
    serial_number   TEXT NOT NULL UNIQUE,
    common_name     TEXT NOT NULL,
    status          cert_status NOT NULL DEFAULT 'active',
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    -- PEM-encoded certificate (public cert only, no key)
    cert_pem        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certs_host ON certificates (host_id);
CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates (status);
CREATE INDEX IF NOT EXISTS idx_certs_expires ON certificates (expires_at);

-- ============================================================
-- Audit Log (tamper-evident, hash-chained)
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    action          audit_action NOT NULL,
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_username  TEXT,          -- Snapshot at time of action
    target_type     TEXT,          -- 'host', 'user', 'group', 'job', etc.
    target_id       TEXT,          -- UUID or identifier of affected resource
    details         JSONB NOT NULL DEFAULT '{}',
    ip_address      INET,
    request_id      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Hash chain: SHA-256(prev_hash || row_data)
    row_hash        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log (actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log (target_type, target_id);
-- Retained for 6 months (pruned by worker)

-- ============================================================
-- Azure SSO Configuration
-- ============================================================

CREATE TABLE IF NOT EXISTS azure_sso_config (
    id              INTEGER PRIMARY KEY DEFAULT 1,  -- singleton row
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    tenant_id       TEXT NOT NULL DEFAULT '',
    client_id       TEXT NOT NULL DEFAULT '',
    -- Encrypted at rest via hardware-host FDE; stored as-is in DB
    client_secret   TEXT NOT NULL DEFAULT '',
    redirect_uri    TEXT NOT NULL DEFAULT '',
    scopes          TEXT NOT NULL DEFAULT 'openid email profile',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT azure_sso_singleton CHECK (id = 1)
);

-- ============================================================
-- System Configuration (key/value runtime settings)
-- ============================================================

CREATE TABLE IF NOT EXISTS system_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default system config values
INSERT INTO system_config (key, value, description) VALUES
    ('health_poll_interval_secs',  '300',   'Agent health check interval in seconds'),
    ('patch_poll_interval_secs',   '1800',  'Agent patch data poll interval in seconds'),
    ('max_concurrent_agent_calls', '64',    'Maximum concurrent mTLS agent calls'),
    ('data_retention_days',        '30',    'Retention period for operational data (days)'),
    ('audit_retention_days',       '180',   'Retention period for audit log (days)'),
    ('smtp_enabled',               'false', 'Enable email notifications'),
    ('smtp_host',                  '',      'SMTP relay hostname'),
    ('smtp_port',                  '587',   'SMTP relay port'),
    ('smtp_username',              '',      'SMTP auth username'),
    ('smtp_password',              '',      'SMTP auth password'),
    ('smtp_from',                  '',      'From address for notifications'),
    ('smtp_tls_mode',              'starttls', 'SMTP TLS mode: none, starttls, tls'),
    ('web_tls_strategy',           'internal_ca', 'Web UI TLS cert strategy: internal_ca or operator_supplied'),
    ('ip_whitelist',               '[]',    'JSON array of allowed CIDR/IP strings; empty = allow all')
ON CONFLICT (key) DO NOTHING;

-- ============================================================
-- Worker Heartbeat
-- ============================================================

CREATE TABLE IF NOT EXISTS worker_heartbeat (
    id              INTEGER PRIMARY KEY DEFAULT 1,  -- singleton row
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    worker_version  TEXT NOT NULL DEFAULT '',
    CONSTRAINT worker_heartbeat_singleton CHECK (id = 1)
);

-- ============================================================
-- Discovery Results (transient; cleared before each scan)
-- ============================================================

CREATE TABLE IF NOT EXISTS discovery_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL,
    ip_address      INET NOT NULL,
    fqdn            TEXT,
    agent_version   TEXT,
    os_name         TEXT,
    agent_port      INTEGER NOT NULL DEFAULT 12443,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Whether the operator has registered this host
    registered      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_discovery_scan ON discovery_results (scan_id);
CREATE INDEX IF NOT EXISTS idx_discovery_ip ON discovery_results (ip_address);
