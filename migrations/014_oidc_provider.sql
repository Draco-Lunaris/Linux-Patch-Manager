-- 014_oidc_provider.sql
-- Migrate from Azure AD-specific SSO to generic OIDC provider support
-- Supports Keycloak, Azure AD, and custom OIDC providers

-- Add new auth_provider enum values for Keycloak and generic OIDC
-- Use DO blocks with exception handling for idempotency
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON e.enumtypid = t.oid WHERE t.typname = 'auth_provider' AND e.enumlabel = 'keycloak') THEN
        ALTER TYPE auth_provider ADD VALUE 'keycloak';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON e.enumtypid = t.oid WHERE t.typname = 'auth_provider' AND e.enumlabel = 'oidc') THEN
        ALTER TYPE auth_provider ADD VALUE 'oidc';
    END IF;
END
$$;

-- Add oidc_sub column for Keycloak/custom OIDC subject IDs
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_sub TEXT;
CREATE INDEX IF NOT EXISTS idx_users_oidc_sub ON users (oidc_sub) WHERE oidc_sub IS NOT NULL;

-- Create oidc_config table (replaces azure_sso_config)
CREATE TABLE IF NOT EXISTS oidc_config (
    id              INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    provider_type   TEXT NOT NULL DEFAULT 'azure' CHECK (provider_type IN ('keycloak', 'azure', 'custom')),
    display_name    TEXT NOT NULL DEFAULT 'Azure AD',
    discovery_url   TEXT NOT NULL DEFAULT '',
    client_id       TEXT NOT NULL DEFAULT '',
    -- Empty string for public clients (Keycloak); non-empty for confidential clients (Azure AD)
    client_secret   TEXT NOT NULL DEFAULT '',
    redirect_uri    TEXT NOT NULL DEFAULT '',
    scopes          TEXT NOT NULL DEFAULT 'openid profile email',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Migrate data from azure_sso_config if it has a row and oidc_config is empty
INSERT INTO oidc_config (enabled, provider_type, display_name, discovery_url, client_id, client_secret, redirect_uri, scopes)
SELECT 
    az.enabled,
    'azure',
    'Azure AD',
    CASE 
        WHEN az.tenant_id IS NOT NULL AND az.tenant_id != '' 
        THEN 'https://login.microsoftonline.com/' || az.tenant_id || '/v2.0/.well-known/openid-configuration'
        ELSE ''
    END,
    az.client_id,
    az.client_secret,
    az.redirect_uri,
    az.scopes
FROM azure_sso_config az
WHERE az.id = 1
ON CONFLICT (id) DO NOTHING;

-- Ensure a default row exists if no data was migrated
INSERT INTO oidc_config (enabled, provider_type, display_name)
SELECT FALSE, 'azure', 'Azure AD'
WHERE NOT EXISTS (SELECT 1 FROM oidc_config WHERE id = 1);
