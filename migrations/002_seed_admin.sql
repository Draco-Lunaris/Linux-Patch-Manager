-- Migration: 002_seed_admin
-- Description: Seed the default admin account.
--
-- Default credentials (CHANGE BEFORE PRODUCTION USE):
--   Username: admin
--   Password: ChangeMe123!
--
-- The password hash below is Argon2id of "ChangeMe123!" with
-- m=65536, t=3, p=1. Replace after first login.

INSERT INTO users (
    id,
    username,
    display_name,
    email,
    role,
    auth_provider,
    password_hash,
    mfa_enabled,
    is_active,
    force_password_reset
)
VALUES (
    gen_random_uuid(),
    'admin',
    'Administrator',
    'admin@localhost',
    'admin',
    'local',
    -- Argon2id hash of "ChangeMe123!" — REPLACE IN PRODUCTION
    '$argon2id$v=19$m=65536,t=3,p=1$Kv8bkGiE81yIuXARq9fwsw$NrBRFvgL1dVsW7bEK6NxEOzIX2q1p4B0K422idAVIDQ',
    FALSE,  -- MFA disabled by default; admin must set up on first login
    TRUE,
    TRUE    -- Force password reset on first login
)
ON CONFLICT (username) DO NOTHING;
