-- Migration: 016_enrollment_requests
-- Description: Create enrollment_requests table for host self-enrollment

CREATE TABLE enrollment_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_id      TEXT NOT NULL UNIQUE,
    fqdn            TEXT NOT NULL,
    ip_address      INET NOT NULL,
    os_details      JSONB NOT NULL DEFAULT '{}',
    polling_token   TEXT NOT NULL UNIQUE, -- Hashed polling token
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours'
);

CREATE INDEX idx_enrollment_requests_token ON enrollment_requests (polling_token);
CREATE INDEX idx_enrollment_requests_expires ON enrollment_requests (expires_at);
