-- Migration 007: Health check configuration and results

-- Health checks configured per host (1-5 per host)
CREATE TABLE host_health_checks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    check_type      VARCHAR(20) NOT NULL CHECK (check_type IN ('service', 'http')),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    -- Service check fields (Type 1)
    service_name    VARCHAR(200),
    -- HTTP check fields (Type 2)
    url             TEXT,
    expected_body   VARCHAR(500),
    ignore_cert_errors BOOLEAN DEFAULT true,
    basic_auth_user VARCHAR(100),
    basic_auth_pass_encrypted BYTEA,  -- AES-256-GCM encrypted
    basic_auth_pass_nonce BYTEA,      -- nonce for AES-GCM
    -- Metadata
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Constraint: service checks must have service_name, http checks must have url + expected_body
    CONSTRAINT valid_service_check CHECK (
        (check_type = 'service' AND service_name IS NOT NULL AND url IS NULL)
        OR
        (check_type = 'http' AND url IS NOT NULL AND expected_body IS NOT NULL AND service_name IS NULL)
    )
);

CREATE INDEX idx_health_checks_host ON host_health_checks (host_id);

-- Health check poll results (4-day retention, pruned by worker)
CREATE TABLE host_health_check_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_id    UUID NOT NULL REFERENCES host_health_checks(id) ON DELETE CASCADE,
    healthy     BOOLEAN NOT NULL,
    detail      TEXT,
    latency_ms  INTEGER,
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_health_results_check ON host_health_check_results (check_id, checked_at DESC);
