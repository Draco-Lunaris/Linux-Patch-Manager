# Secret Encryption at Rest — Issue #6 Spec

**Spec version:** v0.1.0
**Issue:** [#6 — Plaintext storage of secrets in database](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/6)
**Severity:** Medium
**Author:** Draco-Lunaris-Echo
**Status:** Awaiting sign-off

---

## 1. Goal

Encrypt three sensitive secrets that are currently stored in plaintext in the database, using the existing AES-256-GCM crypto helper (`crates/pm-core/src/crypto.rs`) with a new dedicated encryption key.

**Secrets to encrypt:**
| Secret | Table | Current column | Current type |
|--------|-------|----------------|--------------|
| OIDC `client_secret` | `oidc_config` | `client_secret` | `TEXT NOT NULL DEFAULT ''` |
| SMTP `smtp_password` | `system_config` (key-value) | `value` WHERE `key = 'smtp_password'` | `TEXT` |
| TOTP `totp_secret` | `users` | `totp_secret` | `TEXT` (nullable) |

**Why:** Database exfiltration (via SQL injection, backup theft, insider threat) would expose the client_secret to the IdP, SMTP credentials, and persistent TOTP code generation capability for all MFA-enabled users.

---

## 2. Non-Goals

- **NOT** adding a new KMS / Vault integration. AES-256-GCM with a file-based key is sufficient for our threat model and matches the existing health check credential pattern.
- **NOT** rotating the encryption key. This PR establishes the encryption infrastructure; key rotation is a follow-up issue.
- **NOT** encrypting health check credentials (already done in a previous PR).
- **NOT** adding a new master key derivation step. The key file is the only secret to protect at the OS level.
- **NOT** changing the `MASKED` placeholder behavior in API responses. That defense-in-depth pattern continues to apply on top of DB encryption.

---

## 3. Design Decisions (Kelly-approved Q1–Q4)

| Q | Decision | Rationale |
|---|----------|-----------|
| **Q1 — Key management** | **A. New dedicated key** at `/etc/patch-manager/keys/secret-encryption.key` | Blast-radius isolation: if health-check key is compromised (least critical), secrets remain protected. Single-responsibility principle. |
| **Q2 — totp_secret scope** | **A. Encrypt it** | DB exfiltration = persistent TOTP code generation for all MFA-enabled users. Risk is real. |
| **Q3 — Migration path** | **Hard cutover** (development stage) | No dual-read window. The deploy MUST run a one-shot migration that encrypts existing plaintext values before dropping old columns. |
| **Q4 — Key derivation** | **A. Reuse `load_or_create_key()`** | Random 32-byte file, auto-generates on first start, 0600 perms. Same pattern as the health-check key, proven reliable. |

---

## 4. Design

### 4.1 Crypto helper extension (`crates/pm-core/src/crypto.rs`)

**Add a new constant** alongside the existing `KEY_PATH`:

```rust
/// Path to the encryption key for sensitive app secrets
/// (OIDC client_secret, SMTP password, TOTP secret).
/// Separate from `KEY_PATH` (health-check credentials) for blast-radius isolation.
pub const SECRET_ENCRYPTION_KEY_PATH: &str =
    "/etc/patch-manager/keys/secret-encryption.key";
```

**Re-export** from `crates/pm-core/src/lib.rs`:
```rust
pub use crypto::{decrypt, encrypt, load_or_create_key, CryptoError, KEY_PATH, SECRET_ENCRYPTION_KEY_PATH};
```

### 4.2 Migration: `migrations/020_encrypt_secrets_at_rest.sql`

**Schema changes (3 tables):**

```sql
-- 1. oidc_config: replace client_secret TEXT with BYTEA columns
ALTER TABLE oidc_config
    ADD COLUMN IF NOT EXISTS client_secret_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS client_secret_nonce BYTEA;

-- One-shot encryption: read old plaintext, encrypt, write to new columns.
-- Requires the application to be running to provide the key (see §4.6).

ALTER TABLE oidc_config
    DROP COLUMN client_secret;

-- 2. system_config: replace smtp_password row with new key + encrypted+nonce columns
-- Approach: add new keys 'smtp_password_encrypted' and 'smtp_password_nonce';
-- remove the old 'smtp_password' row after migration script encrypts it.
-- (We don't change the system_config schema — we add new keys.)

-- 3. users: replace totp_secret TEXT with BYTEA columns
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS totp_secret_nonce BYTEA;

ALTER TABLE users
    DROP COLUMN totp_secret;
```

**Hard cutover requirement:** The deploy must execute a one-shot Rust helper (see §4.6) BEFORE the `DROP COLUMN` statements run. The migration order is:

1. ADD new BYTEA columns (idempotent, no data loss)
2. **Run one-shot encrypt helper** (reads old plaintext, writes to new columns)
3. DROP old TEXT columns

In development, we'll combine steps 1+2+3 into a single migration script that the operator runs manually before restarting the service.

### 4.3 Code changes (6 read/write sites)

#### A. `crates/pm-web/src/routes/sso.rs` — OIDC client_secret READ

**Location:** `load_oidc_config` function, line 802
**Before:**
```rust
sqlx::query_as(
    "SELECT enabled, provider_type, display_name, discovery_url, client_id, client_secret, redirect_uri, scopes FROM oidc_config WHERE id = 1",
)
```
**After:**
```rust
sqlx::query_as(
    "SELECT enabled, provider_type, display_name, discovery_url, client_id, \
     client_secret_encrypted, client_secret_nonce, redirect_uri, scopes \
     FROM oidc_config WHERE id = 1",
)
// ... then decrypt the secret in the OidcConfig struct construction
```

**OidcConfig struct (line 216) change:**
- `pub client_secret: String` → `pub client_secret_encrypted: Vec<u8>` + `pub client_secret_nonce: Vec<u8>`
- Add a `pub fn decrypt_client_secret(&self, key: &[u8; 32]) -> Result<String, CryptoError>` method

#### B. `crates/pm-web/src/routes/settings.rs` — OIDC client_secret READ+WRITE+MASK

**Read** (line 280): Same query change as A above, then decrypt.
**Write** (line 360–400): Replace plaintext bind with encrypted+nonce binds.
**MASK** (line 295–315): No change — the API still returns `MASKED` if the secret is set.

#### C. `crates/pm-web/src/routes/settings.rs` — SMTP password READ+WRITE

**Read** (line 793, `smtp_password` key in system_config):
- Before: `cfg.get("smtp_password").cloned().unwrap_or_default()`
- After: read `smtp_password_encrypted` + `smtp_password_nonce` keys, decrypt with the same key

**Write** (line 453):
- Before: `update_config_key(&state.db, "smtp_password", v).await?;`
- After: `let (enc, nonce) = crypto::encrypt(v, &key)?;` then write to `smtp_password_encrypted` and `smtp_password_nonce` keys

#### D. `crates/pm-auth/src/session.rs` — TOTP secret READ

**Location:** line 197, `let secret = user.totp_secret.as_deref().unwrap_or("");`

**Before:**
```rust
let secret = user.totp_secret.as_deref().unwrap_or("");
```
**After:**
```rust
let secret = user.totp_secret_encrypted.as_ref()
    .zip(user.totp_secret_nonce.as_ref())
    .map(|(enc, nonce)| crypto::decrypt(enc, nonce, &key))
    .transpose()?
    .unwrap_or_default();
```

**User struct (line 80) change:**
- `totp_secret: Option<String>` → `totp_secret_encrypted: Option<Vec<u8>>` + `totp_secret_nonce: Option<Vec<u8>>`

#### E. `crates/pm-web/src/routes/auth.rs` — TOTP secret WRITE (MFA enrollment)

**Location:** line 363, `sqlx::query("UPDATE users SET totp_secret = $1, mfa_enabled = TRUE WHERE id = $2")`

**Before:**
```rust
.bind(&req.secret_base32)
```
**After:**
```rust
let (enc, nonce) = crypto::encrypt(&req.secret_base32, &key)?;
// ... bind enc and nonce, drop the plaintext
```

#### F. `crates/pm-web/src/routes/users.rs` — TOTP secret NULL write (disable MFA)

**Location:** line 537, `sqlx::query("UPDATE users SET totp_secret = NULL, ... WHERE id = $1")`

**Before:** Sets `totp_secret = NULL`.
**After:** Sets `totp_secret_encrypted = NULL, totp_secret_nonce = NULL`.

#### G. `crates/pm-worker/src/email.rs` — SMTP password READ in worker

**Location:** line 58, `password: get("smtp_password")`

**Before:** Reads plaintext key from system_config.
**After:** Reads `smtp_password_encrypted` + `smtp_password_nonce`, decrypts.

### 4.4 Key loading in pm-web (one-time setup)

The secret-encryption key must be loaded at startup and accessible to all routes that decrypt secrets. **Pattern: load at request time, cache per process.**

**Implementation:** Add a helper module `crates/pm-web/src/secret_key.rs`:

```rust
use once_cell::sync::OnceCell;
use pm_core::crypto;
use std::path::Path;

static SECRET_KEY: OnceCell<[u8; 32]> = OnceCell::new();

/// Load the secret-encryption key at first call. Subsequent calls return the cached value.
/// Returns CryptoError if the key file is missing or invalid.
pub fn get() -> Result<&'static [u8; 32], crypto::CryptoError> {
    SECRET_KEY.get_or_try_init(|| {
        crypto::load_or_create_key(Path::new(crypto::SECRET_ENCRYPTION_KEY_PATH))
    })
}
```

**Note:** `once_cell` is already a workspace dependency. Each route that needs to decrypt calls `secret_key::get()?` and uses the key.

For the worker crate (`pm-worker`), the same pattern is needed in `crates/pm-worker/src/secret_key.rs`.

### 4.5 Migration helper: `migrations/020_migrate_secrets.rs` (one-shot, dev only)

A standalone Rust binary (or an `#[ignore]` integration test) that:

1. Connects to the database using the existing DATABASE_URL
2. Reads the plaintext secrets from the old columns/rows
3. Encrypts each one with the secret-encryption key
4. Writes to the new BYTEA columns
5. Verifies the encrypted values match the plaintext (round-trip check)
6. Reports success and recommends running migration 020 to drop the old columns

**For development:** This helper is run manually before deploying the new code. The migration file `020_encrypt_secrets_at_rest.sql` drops the old columns after the helper completes.

### 4.6 Key generation on first start

On first start of the new code:
1. If `/etc/patch-manager/keys/secret-encryption.key` doesn't exist, the `load_or_create_key()` function generates a new 32-byte key and writes it with 0600 permissions.
2. The new code looks for encrypted columns. If they're NULL and the old plaintext columns are gone, the application will fail with a clear error message ("Secret not initialized — run the migration helper").
3. The migration helper from §4.5 must be run BEFORE the new code's first start, OR the deployment must be ordered: run helper → deploy new code.

---

## 5. Acceptance Criteria

- [ ] `migrations/020_encrypt_secrets_at_rest.sql` adds BYTEA columns for all 3 secrets, then drops the old TEXT columns.
- [ ] `crypto::SECRET_ENCRYPTION_KEY_PATH` constant added; re-exported from pm-core/lib.rs.
- [ ] `pm-web` and `pm-worker` have a `secret_key::get()` helper using `OnceCell`.
- [ ] All 6 read sites (sso.rs:802, settings.rs:280, settings.rs:793, session.rs:197, pm-worker/email.rs:58, plus the write site at auth.rs:363) use `crypto::encrypt`/`decrypt` with the secret-encryption key.
- [ ] All 3 write sites (settings.rs:375 for OIDC, settings.rs:453 for SMTP, auth.rs:363 for TOTP, users.rs:537 for TOTP disable) bind encrypted+nonce instead of plaintext.
- [ ] The `MASKED` placeholder behavior in API responses is preserved.
- [ ] A one-shot migration helper (`020_migrate_secrets.rs` or equivalent) is provided and documented.
- [ ] `cargo fmt --check --all` clean.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] `cargo test -p pm-web --bins --tests` passes (43 existing + 2 new = 45 tests).
- [ ] `cargo test -p pm-worker --bins --tests` passes (existing + 1 new = at least 1 test).
- [ ] No new entries in the audit log (encryption is a data migration, not a user action).
- [ ] The new key file `/etc/patch-manager/keys/secret-encryption.key` is documented in the install/runbook.

---

## 6. Test Plan

**Unit tests (3 new):**
- `crypto::encrypt_decrypt_round_trip` — encrypt a known plaintext, decrypt it, assert equality
- `secret_key::get_returns_same_key` — call `get()` twice, assert pointer equality (caching works)
- `secret_key::get_creates_key_on_first_call` — delete the key file, call `get()`, assert the key file is recreated

**Migration helper test (1 new):**
- `020_migrate_secrets::test_round_trip_oidc` — seed DB with known plaintext, run helper, assert encrypted column matches the expected ciphertext (computed independently)

**Existing tests to verify still pass:**
- `cargo test -p pm-web --bins --tests` — 43 existing tests
- `cargo test -p pm-auth --bins --tests` — session tests for TOTP verification
- `cargo test -p pm-worker --bins --tests` — email tests (if any)

**Manual verification:**
- Start the service, log in as admin, navigate to Settings → OIDC, verify the API response shows `MASKED` (no plaintext leak)
- `psql -c "SELECT client_secret_encrypted FROM oidc_config"` — verify the value is binary (BYTEA), not readable text
- `psql -c "SELECT value FROM system_config WHERE key = 'smtp_password'"` — verify the row is gone (replaced by encrypted+nonce rows)
- `psql -c "SELECT totp_secret FROM users WHERE mfa_enabled = TRUE LIMIT 1"` — verify the column is gone

---

## 7. Risk Analysis

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Deploy order: new code starts before migration helper runs** → service fails to read secrets | Medium | High | Document the deploy order in the runbook. Add a startup check that detects missing encrypted columns and returns a clear error. |
| **Key file lost (deleted, disk failure)** → all secrets unreadable | Low | Critical | Document the key file in the backup runbook. Add a `backup.sh` hook to include the key file in backups. Follow-up issue for key recovery / rotation. |
| **Worker doesn't share key with web** | Low | Medium | Both use the same `load_or_create_key()` with the same path. Key file is filesystem-shared. |
| **TOTP secret encryption breaks existing MFA sessions** | Low | Medium | The one-shot migration helper decrypts old plaintext, re-encrypts, and writes. Existing TOTP seeds remain valid. |
| **Migration helper crashes mid-migration** → partial state | Low | Medium | The helper is idempotent (uses UPSERT). On retry, it re-encrypts and overwrites. |
| **Key file permissions wrong** → OS-level exposure | Very low | Medium | `load_or_create_key()` sets 0600 on creation. `chmod` enforcement in the install script. |
| **Audit log entries leak the secret value** | Very low | N/A | We don't log the plaintext or ciphertext. Only the fact that the column was updated. |

---

## 8. Documentation Updates

### 8.1 `docs/security-review.md` §4.1 (Encryption at Rest)

Add a new evidence row:

| Control | Status | Evidence |
|---------|--------|----------|
| **Secrets encrypted at rest (issue #6 fix)** | ✅ Verified | OIDC `client_secret`, SMTP `smtp_password`, and TOTP `totp_secret` are encrypted with AES-256-GCM using a dedicated per-install key at `/etc/patch-manager/keys/secret-encryption.key`. Encryption/decryption via `pm-core::crypto::encrypt`/`decrypt` (same helper as health check credentials, but with a separate key for blast-radius isolation). Schema migration `020_encrypt_secrets_at_rest.sql` replaces plaintext TEXT columns with BYTEA `_encrypted` + `_nonce` columns. |

### 8.2 `docs/runbooks/restore.md` (or new `docs/runbooks/key-management.md`)

Add a section on the new key file:

```markdown
## Encryption Keys

Two per-install AES-256-GCM keys are auto-generated on first start:

| Key | Path | Protects |
|-----|------|----------|
| `health-check.key` | `/etc/patch-manager/keys/health-check.key` | HTTP basic auth passwords for health check endpoints |
| `secret-encryption.key` | `/etc/patch-manager/keys/secret-encryption.key` | OIDC client_secret, SMTP password, TOTP secrets |

**Backup:** Both key files MUST be included in `/etc/patch-manager` backups. Without them, the encrypted data is unrecoverable.

**Rotation:** Key rotation is not yet supported (follow-up issue). If a key is compromised, generate a new key and re-encrypt all secrets.
```

### 8.3 `docs/REST_API.md` (no changes needed)

The API surface is unchanged — the `MASKED` placeholder behavior is preserved.

---

## 9. Follow-ups

- **Key rotation** — add support for rotating the secret-encryption key without service downtime. Requires wrapping the key in a versioned envelope (e.g., `{key_id, ciphertext, nonce}`).
- **Integration tests** — covered by issue #15. The migration helper has its own unit test.
- **Audit logging** — log the fact that secret-encryption key was loaded at startup (NOT the key itself).
- **Backup verification** — automated test that verifies a fresh install can restore from a backup by decrypting the secrets.

---

## 10. Sign-off

Approve to proceed to Phase 1 (crypto helper extension + one-shot migration helper + 3 new unit tests). Per project rules, I will not commit or push anything until Phase 7.
