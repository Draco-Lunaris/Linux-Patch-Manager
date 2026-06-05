-- Migration: 002_seed_admin
-- Description: Seed the default admin account.
--
-- IMPORTANT (issue #8): The password_hash below is a PLACEHOLDER
-- that cannot validate any password. On first startup, pm-web detects
-- this placeholder and generates a random admin password, replacing
-- the hash in the database. The generated password is printed once
-- to stderr (visible in systemd journal).
--
-- If the application never starts (e.g., manual migration only),
-- the admin account is inaccessible — this is fail-closed.
--
-- On first successful login with a real password, the admin is forced to
-- set a new password (force_password_reset = TRUE).

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
    -- PLACEHOLDER Argon2id hash (issue #8). Cannot validate any password.
    -- pm-web replaces this with a real hash on first startup.
    '$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    FALSE,
    TRUE,
    TRUE
)
ON CONFLICT (username) DO NOTHING;
