# GPG Key Rotation Procedure

**Applies to:** Linux Patch Manager — Manager-Hosted Package Repository
**Issue:** #116
**Last updated:** 2026-06-28

---

## Overview

The manager-hosted package repository uses a GPG signing key to sign packages
and repo metadata. Agents verify these signatures using the GPG public key
distributed during enrollment (via `repo_config` in `PkiBundle`).

The GPG key has a **2-year expiry** as a safety net. Key rotation should be
performed before expiry to ensure continuous operation.

## Current Key

- **Key ID:** `C0600CE1C23A2B7F83EB0A48691E5DEBC54E9AB5`
- **Type:** RSA 4096
- **Created:** 2026-06-28
- **Expires:** 2028-06-27
- **Stored in:** Vaultwarden (`LPA Repo GPG Private Key`, `LPA Repo GPG Public Key`)
- **GPG keyring:** `~/.gnupg` on `lpm.moon-dragon.us` (echo user)

## Key Health Monitoring

GPG key status is monitored via the existing CRL health check system:

- Agents report `gpg_key_status` and `gpg_key_expires_at` in health responses
- Health poller persists these to `hosts.gpg_key_status` and `hosts.gpg_key_expires_at`
- Manager UI displays GPG key status per host alongside CRL status
- The CRL health check worker can trigger automatic renewal when key approaches expiry

## Rotation Procedure

### 1. Generate New Key

```bash
ssh echo@lpm.moon-dragon.us
gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: Linux Patch API Repo
Name-Email: lpa-repo@moon-dragon.us
Expire-Date: 2y
%commit
EOF
```

Verify:
```bash
gpg --list-secret-keys lpa-repo@moon-dragon.us
```

### 2. Export and Store New Key

```bash
# Export public key
gpg --armor --export lpa-repo@moon-dragon.us > /tmp/lpa-repo-public-key-new.asc

# Export private key
gpg --armor --export-secret-keys lpa-repo@moon-dragon.us > /tmp/lpa-repo-private-key-new.asc
```

Store in Vaultwarden (update existing items or create new ones):
- `LPA Repo GPG Private Key` — update with new private key
- `LPA Repo GPG Public Key` — update with new public key

### 3. Update Repo Configuration

```bash
# Copy new public key to repo serve path
cp /tmp/lpa-repo-public-key-new.asc /var/www/lpa-repo/lpa-repo-public-key.asc

# Update reprepro SignWith in distributions config
# Edit /var/www/lpa-repo/apt/conf/distributions
# Replace old key ID with new key ID in all SignWith lines

# Re-sign all repo metadata
reprepro -b /var/www/lpa-repo/apt export
createrepo_c --update /var/www/lpa-repo/dnf/el9
```

### 4. Update CI Secrets

Update `LPA_REPO_GPG_KEY` secret in:
- GitHub Actions repository secrets
- Gitea Actions secrets (if applicable)

### 5. Re-enroll Agents

Agents need the new GPG public key. Options:

- **Option A (recommended):** Trigger re-enrollment for all hosts
- **Option B:** Agents fetch updated key via `GET /api/v1/pki/repo-config`
- **Option C:** Manual key replacement on each agent

### 6. Verify

```bash
# Check agent GPG key status via manager UI or API
curl -s https://lpm.moon-dragon.us/api/v1/hosts | jq '.[] | {fqdn, gpg_key_status, gpg_key_expires_at}'

# Test package install on a canary host
ssh canary-host 'apt-get update && apt-get install --dry-run linux-patch-api'
```

### 7. Revoke Old Key (Optional)

After all agents are migrated:
```bash
gpg --gen-revoke C0600CE1C23A2B7F83EB0A48691E5DEBC54E9AB5 | gpg --import
```

## Automatic Renewal

The CRL health check system monitors GPG key expiry. When a key approaches
expiry (within 90 days), the system can:

1. Generate a new key automatically
2. Store in Vaultwarden
3. Update repo configuration
4. Trigger re-enrollment for affected agents

This behavior is configurable via `config.toml`.

## Troubleshooting

### Agent reports `gpg_key_status: expired`

The GPG key on the agent has expired. Trigger re-enrollment or have the agent
fetch the updated key via `GET /api/v1/pki/repo-config`.

### Agent reports `gpg_key_status: missing`

The agent was enrolled before v2.0.0 and doesn't have a GPG key configured.
Trigger re-enrollment or have the agent fetch via `GET /pki/repo-config`.

### `apt-get update` fails with GPG signature error

The repo metadata was signed with a key the agent doesn't have. Check:
1. GPG public key at `/etc/apt/keyrings/lpa-repo.gpg` on the agent
2. `sources.list.d/lpa.list` has correct `signed-by=` path
3. Manager's `/var/www/lpa-repo/lpa-repo-public-key.asc` matches the signing key
