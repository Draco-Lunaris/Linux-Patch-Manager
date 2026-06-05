-- 020_encrypt_secrets_at_rest.sql
-- Encrypt three sensitive secrets at rest with AES-256-GCM:
--   - oidc_config.client_secret
--   - system_config row with key='smtp_password'
--   - users.totp_secret
--
-- Hard cutover (development stage, no dual-read window):
--   1. ADD new BYTEA columns (idempotent)
--   2. Operator runs one-shot migration helper (reads old plaintext, writes to new columns)
--   3. DROP old TEXT columns (this migration)
--
-- The new key file is at /etc/patch-manager/keys/secret-encryption.key
-- (auto-generated on first start, 0600 permissions).
-- See tasks/secret-encryption-spec.md for the full design.

-- ============================================================
-- 1. oidc_config: client_secret
-- ============================================================
ALTER TABLE oidc_config
    ADD COLUMN IF NOT EXISTS client_secret_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS client_secret_nonce BYTEA;

-- DROP old plaintext column (migration helper must have run first)
ALTER TABLE oidc_config
    DROP COLUMN IF EXISTS client_secret;

-- ============================================================
-- 2. system_config: smtp_password (key-value store)
-- ============================================================
-- Approach: add new keys 'smtp_password_encrypted' and 'smtp_password_nonce'
-- (no schema change to system_config), then delete the old 'smtp_password' row.
-- The migration helper reads the old row, encrypts, writes two new rows.
DELETE FROM system_config WHERE key = 'smtp_password';

-- ============================================================
-- 3. users: totp_secret
-- ============================================================
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS totp_secret_nonce BYTEA;

-- DROP old plaintext column (migration helper must have run first)
ALTER TABLE users
    DROP COLUMN IF EXISTS totp_secret;
