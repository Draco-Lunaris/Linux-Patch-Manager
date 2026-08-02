# GPG Key Rotation Procedure

**Applies to:** Linux Patch Manager — Manager-Hosted Package Repository
**Issue:** #116
**Last updated:** 2026-06-29

---

## Overview

Each Linux Patch Manager instance generates and manages its own unique GPG signing key for its local package repository. The key is stored alongside the CA root/key in the manager's configuration directory (e.g., `/etc/patch-manager/ca/`).

Agents receive the GPG public key during enrollment via `repo_config` in `PkiBundle`. They use it to verify package signatures when installing updates from the manager-hosted repo.

The GPG key has a **2-year expiry** as a safety net. Key rotation should be performed before expiry to ensure continuous operation.

## Key Properties

- **Type:** RSA 4096
- **Usage:** Signing only
- **Expiry:** 2 years
- **Created:** 2026-06-28
- **Expires:** 2028-06-27
- **Storage:** Per-manager on disk at `/etc/patch-manager/ca/` alongside CA material (NEVER in Vaultwarden or CI secrets — see AGENTS.md Rule 2)
- **Distribution:** Via enrollment `PkiBundle.repo_config.gpg_public_key`
- **GPG keyring:** `~/.gnupg` on the manager host (service user)

## Key Health Monitoring

GPG key status is monitored via the existing CRL health check system:

- Agents report `gpg_key_status` and `gpg_key_expires_at` in health responses
- Health poller persists these to `hosts.gpg_key_status` and `hosts.gpg_key_expires_at`
- Manager UI displays GPG key status per host alongside CRL status
- The CRL health check worker can trigger automatic renewal when key approaches expiry

## Rotation Procedure

### 1. Generate New Key

On the manager host, generate a new GPG signing key:

```bash
gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: Linux Patch API Repo
Name-Email: lpa-repo@localhost
Expire-Date: 2y
%commit
EOF
```

Verify:
```bash
gpg --list-secret-keys lpa-repo@localhost
```

### 2. Export and Store New Key

```bash
# Export public key (for distribution via enrollment)
gpg --armor --export lpa-repo@localhost > /etc/patch-manager/ca/lpa-repo-public-key.asc

# Export private key (keep secure alongside CA private key)
gpg --armor --export-secret-keys lpa-repo@localhost > /etc/patch-manager/ca/lpa-repo-private-key.asc
chmod 600 /etc/patch-manager/ca/lpa-repo-private-key.asc
```

Store on the manager host at `/etc/patch-manager/ca/` (per-manager, NEVER in Vaultwarden or CI secrets — see AGENTS.md Rule 2):
### 3. Update Repo Configuration

```bash
# The manager's GPG key is configured in /etc/patch-manager/ca/lpa-repo-private-key.asc
# After replacing the key files, trigger metadata regeneration:
#   POST /api/v1/admin/repo/regenerate-metadata
# Or trigger a repo sync which regenerates all metadata automatically.
```

### 4. Re-enroll Agents

Agents need the new GPG public key. Options:

- **Option A (recommended):** Trigger re-enrollment for all hosts
- **Option B:** Agents fetch updated key via `GET /api/v1/pki/repo-config`
- **Option C:** Manual key replacement on each agent

### 5. Verify

```bash
# Check agent GPG key status via manager UI or API
curl -s https://<manager-host>/api/v1/hosts | jq '.[] | {fqdn, gpg_key_status, gpg_key_expires_at}'

# Test package install on a canary host
ssh canary-host 'apt-get update && apt-get install --dry-run linux-patch-api'
```

### 6. Revoke Old Key (Optional)

After all agents are migrated:
```bash
gpg --gen-revoke <old-key-id> | gpg --import
```

## Automatic Renewal

The CRL health check system monitors GPG key expiry. When a key approaches expiry (within 90 days), the system can:

1. Generate a new key automatically
2. Store on manager host at `/etc/patch-manager/ca/` (NEVER in Vaultwarden or CI secrets)
3. Update repo configuration
4. Trigger re-enrollment for affected agents

This behavior is configurable via `config.toml`.

## Troubleshooting

### Agent reports `gpg_key_status: expired`
The GPG key on the agent has expired. Trigger re-enrollment or have the agent fetch the updated key via `GET /api/v1/pki/repo-config`.

### Agent reports `gpg_key_status: missing`
The agent was enrolled before v2.0.0 and doesn't have a GPG key configured. Trigger re-enrollment or have the agent fetch via `GET /pki/repo-config`.

### `apt-get update` fails with GPG signature error
The repo metadata was signed with a key the agent doesn't have. Check:
1. GPG public key at `/etc/apt/keyrings/lpa-repo.gpg` on the agent
2. `sources.list.d/lpa.list` has correct `signed-by=` path
3. Manager's `/var/www/lpa-repo/lpa-repo-public-key.asc` matches the signing key
