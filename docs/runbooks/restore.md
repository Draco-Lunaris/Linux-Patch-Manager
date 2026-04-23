# Linux Patch Manager — Backup & Restore Runbook

## Overview

This runbook covers backup and restoration of the Linux Patch Manager.
The application state lives in:
- PostgreSQL database (`patch_manager`)
- Internal CA private key (`/etc/patch-manager/ca/ca.key`)
- JWT signing key (`/etc/patch-manager/jwt/signing.pem`)
- Application config (`/etc/patch-manager/config.toml`)
- Operator-supplied TLS cert/key (if using `operator_supplied` strategy)

## Backup

### 1. Database
```bash
pg_dump -U patch_manager -Fc patch_manager > patch_manager_$(date +%Y%m%d_%H%M%S).dump
```

### 2. Configuration and Keys
```bash
tar -czf patch_manager_config_$(date +%Y%m%d_%H%M%S).tar.gz \
    /etc/patch-manager/
```
> **Security:** The archive contains private keys. Encrypt before storing:
> `gpg --symmetric patch_manager_config_*.tar.gz`

### 3. Recommended Backup Schedule
- Database: daily pg_dump, retained 30 days
- Config/keys: on every change, retained indefinitely (encrypted)

## Restore

### Prerequisites
- Fresh Ubuntu 24.04 host
- Run `scripts/setup.sh` to create user, directories, and PostgreSQL

### 1. Restore Configuration and Keys
```bash
tar -xzf patch_manager_config_<timestamp>.tar.gz -C /
chown -R patch-manager:patch-manager /etc/patch-manager/
chmod 600 /etc/patch-manager/ca/ca.key
chmod 600 /etc/patch-manager/jwt/signing.pem
```

### 2. Restore Database
```bash
# Create empty database (if not already created by setup.sh)
sudo -u postgres createdb -O patch_manager patch_manager

# Restore
pg_restore -U patch_manager -d patch_manager -Fc patch_manager_<timestamp>.dump
```

### 3. Install and Start Services
```bash
# Install binaries
cp pm-web pm-worker /usr/local/bin/

# Install frontend
scripts/build-frontend.sh

# Start services
systemctl enable --now patch-manager-web patch-manager-worker
```

### 4. Verify
```bash
curl -k https://localhost/status/health
# Expected: {"status": "healthy", ...}
```

## Notes
- Migrations run automatically on web process startup.
- The CA private key is the most critical secret — losing it requires re-issuing all mTLS certificates.
- JWT signing key rotation is handled automatically every 90 days; no manual intervention needed.
