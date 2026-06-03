# Key Management Runbook

**Applies to:** Linux Patch Manager production deployments (issue #6 — secret encryption at rest)
**Last updated:** 2026-06-03
**Owner:** SRE / Security

---

## Overview

Linux Patch Manager uses two per-install AES-256-GCM encryption keys for protecting sensitive data at rest. Both keys are auto-generated on first start of the service, stored as 32-byte files with `0600` permissions (owner read/write only).

| Key file | Path | Protects | Used by |
|----------|------|----------|---------|
| `health-check.key` | `/etc/patch-manager/keys/health-check.key` | HTTP basic-auth passwords for health check endpoints | `pm-web`, `pm-worker` |
| `secret-encryption.key` | `/etc/patch-manager/keys/secret-encryption.key` | OIDC `client_secret`, SMTP `smtp_password`, TOTP `totp_secret` | `pm-web`, `pm-auth`, `pm-worker` |

The two keys are separate by design (blast-radius isolation): if the health-check key is ever compromised, the app secrets remain protected by a different key.

---

## Key Generation (First Start)

On first start of `pm-web` or `pm-worker`, the `crypto::load_or_create_key()` function checks for each key file. If missing, it:

1. Creates the `/etc/patch-manager/keys/` directory (mode `0700`)
2. Generates 32 cryptographically random bytes via `OsRng` (the OS CSPRNG)
3. Writes the key to disk
4. Sets permissions to `0600` (owner read/write only)
5. Returns the key to the calling code

The key files are created in the order they are first accessed. If `pm-worker` starts before `pm-web`, it creates the same key file (filesystem-shared). Both processes can read the same key.

---

## Backup

**Both key files MUST be included in `/etc/patch-manager` backups.** Without the key files, encrypted data is unrecoverable. Recommended backup procedure:

```bash
# Include the keys directory in the backup archive
tar -czf /backup/patch-manager-$(date +%F).tar.gz \
    /etc/patch-manager/config.toml \
    /etc/patch-manager/keys/ \
    /var/lib/patch-manager/  # if used

# Verify the keys are in the backup
tar -tzf /backup/patch-manager-*.tar.gz | grep -E 'keys/.*\.key$'
```

The existing `scripts/backup.sh` already excludes secrets from unencrypted backups and supports GPG encryption for the archive. Ensure the backup includes the keys directory.

---

## Verification (Production)

To verify both keys exist and have correct permissions on a running deployment:

```bash
# Check both key files exist with 0600 permissions
for key in health-check.key secret-encryption.key; do
    path="/etc/patch-manager/keys/${key}"
    if [ -f "$path" ]; then
        mode=$(stat -c '%a' "$path")
        size=$(stat -c '%s' "$path")
        echo "[OK]   $path  mode=$mode  size=$size"
    else
        echo "[FAIL] $path  missing"
    fi
done
```

Expected output:
```
[OK]   /etc/patch-manager/keys/health-check.key  mode=600  size=32
[OK]   /etc/patch-manager/keys/secret-encryption.key  mode=600  size=32
```

---

## Recovery (Disaster Scenario)

If a key file is lost (disk failure, accidental deletion):

1. **All encrypted data becomes unrecoverable.** This includes:
   - HTTP basic-auth passwords for health check endpoints (health-check.key)
   - OIDC `client_secret` (secret-encryption.key)
   - SMTP `smtp_password` (secret-encryption.key)
   - TOTP `totp_secret` for all users (secret-encryption.key)

2. **If you have a backup** of the key files: restore them to `/etc/patch-manager/keys/` with `0600` permissions. The service will read the restored keys on next start.

3. **If you do NOT have a backup**: re-provision the affected secrets:
   - For OIDC: re-enter the `client_secret` from the IdP's app registration
   - For SMTP: re-enter the SMTP password
   - For TOTP: all users must re-enroll MFA (their existing TOTP secrets are unrecoverable)
   - For health-check basic auth: re-enter the password in each health check configuration

---

## Key Rotation

Key rotation is **not yet supported** (tracked as a follow-up issue). If a key is compromised:

1. Generate a new key: `rm /etc/patch-manager/keys/secret-encryption.key` (service will auto-generate on next start)
2. Re-encrypt all secrets in the database using the `migrate-secrets` binary (see [README of the helper](../../crates/migrate-secrets/src/main.rs))
3. Update any external systems that depended on the old secrets (e.g., IdP app registration)

For a planned rotation (without compromise), the procedure is the same but coordinated with a maintenance window.

---

## Security Notes

- **Never** log the key bytes or include them in error messages. The `crypto::load_or_create_key()` function returns the key but callers should never `tracing::error!` the value.
- **Never** commit key files to git. The `/etc/patch-manager/keys/` directory should be in `.gitignore` or outside the repo entirely (recommended).
- **Never** copy key files between machines (e.g., for "easy migration"). Each deployment must generate its own key.
- **The `MASKED` placeholder in API responses** (e.g., for `client_secret` in OIDC settings) continues to apply on top of DB encryption — it's a separate defense-in-depth layer.

---

## Related

- [Secret encryption spec](../../tasks/secret-encryption-spec.md) — full design rationale and migration plan
- [Security review](../security-review.md) §4.1 — control matrix entry
- [Migration 020](../../migrations/020_encrypt_secrets_at_rest.sql) — schema changes for the new encrypted columns
- `crates/pm-core/src/crypto.rs` — implementation of `load_or_create_key`, `encrypt`, `decrypt`
- `crates/migrate-secrets/src/main.rs` — one-shot helper for migrating plaintext → encrypted
