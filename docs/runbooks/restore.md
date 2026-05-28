# Linux Patch Manager — Backup & Restore Runbook

## Overview

This runbook covers backup and restoration of the Linux Patch Manager.
The application state lives in:
- PostgreSQL database (`patch_manager`)
- Internal CA private key (`/etc/patch-manager/ca/ca.key`)
- JWT signing key (`/etc/patch-manager/jwt/signing.pem`)
- Application config (`/etc/patch-manager/config.toml`)
- Operator-supplied TLS cert/key (if using `operator_supplied` strategy)

## Recovery Objectives

| Metric | Target | Notes |
|--------|--------|-------|
| RPO    | 24 hours | Nightly pg_dump at 02:00 via cron |
| RTO    | 4 hours  | Fresh host setup + restore + service start |

## Automated Backup

The `scripts/backup.sh` script is installed to `/usr/local/bin/backup.sh` during setup
and scheduled via cron at 02:00 daily. It performs:

1. **Database:** `pg_dump -Fc` to `/var/backups/patch-manager/patch_manager_db_YYYYMMDD_HHMMSS.dump`
2. **CA Material:** Tar+GPG of `/etc/patch-manager/ca/` (encrypted if `GPG_RECIPIENT` set)
3. **Config:** Tar of `/etc/patch-manager/config.toml`, JWT verify key, TLS cert
   - Secrets (JWT signing key, TLS key, config with DB URL) are **excluded** unless `GPG_RECIPIENT` is set
4. **Retention:** 30 days automatic cleanup

### Configuring Encrypted Backups

To enable GPG-encrypted backups (recommended for production):

```bash
# Edit /usr/local/bin/backup.sh or set environment variable
export GPG_RECIPIENT="admin@yourdomain.com"  # Your GPG key ID
```

### Manual Backup

```bash
# Run backup immediately
sudo /usr/local/bin/backup.sh

# Or individual components:
sudo -u postgres pg_dump -Fc patch_manager > patch_manager_$(date +%Y%m%d_%H%M%S).dump
```

## Restore

### Prerequisites
- Fresh Ubuntu 24.04 host
- Run `scripts/setup.sh` to create user, directories, and PostgreSQL
- Backup files available (decrypted if GPG-encrypted)

### 1. Restore Configuration and Keys

**If backups are GPG-encrypted, decrypt first:**
```bash
gpg --decrypt patch_manager_config_<timestamp>.tar.gz.gpg > patch_manager_config_<timestamp>.tar.gz
gpg --decrypt patch_manager_ca_<timestamp>.tar.gz.gpg > patch_manager_ca_<timestamp>.tar.gz
```

**Restore CA material:**
```bash
tar -xzf patch_manager_ca_<timestamp>.tar.gz -C /
chown -R patch-manager:patch-manager /etc/patch-manager/ca/
chmod 600 /etc/patch-manager/ca/ca.key
chmod 644 /etc/patch-manager/ca/ca.crt
```

**Restore config and JWT keys:**
```bash
tar -xzf patch_manager_config_<timestamp>.tar.gz -C /
chown -R patch-manager:patch-manager /etc/patch-manager/
chmod 600 /etc/patch-manager/jwt/signing.pem
chmod 644 /etc/patch-manager/jwt/verify.pem
chmod 640 /etc/patch-manager/config.toml
```

**If secrets were excluded from backup** (no GPG recipient configured):
- Regenerate JWT signing key: `openssl genpkey -algorithm ed25519 -out /etc/patch-manager/jwt/signing.pem`
- All existing JWT sessions will be invalidated
- Re-issue any operator-supplied TLS certificates

### 2. Restore Database

```bash
# Create empty database (if not already created by setup.sh)
sudo -u postgres createdb -O patch_manager patch_manager

# Restore from custom-format dump
pg_restore -U patch_manager -d patch_manager -Fc patch_manager_db_<timestamp>.dump

# If schema already exists (from migrations), use clean restore:
# pg_restore -U patch_manager -d patch_manager --clean --if-exists -Fc patch_manager_db_<timestamp>.dump
```

### 3. Install and Start Services

```bash
# Install binaries
cp pm-web pm-worker /usr/local/bin/

# Build and install frontend
scripts/build-frontend.sh

# Start services (migrations run automatically on web process startup)
systemctl enable --now patch-manager.target
```

### 4. Verify Restoration

```bash
# Health check
curl -k https://localhost/status/health
# Expected: {"status": "healthy", ...}

# Verify database connectivity
sudo -u postgres psql -d patch_manager -c "SELECT count(*) FROM hosts;"

# Verify CA is functional
curl -k https://localhost/api/v1/ca/root.crt

# Verify worker heartbeat
journalctl -u patch-manager-worker --since "5 minutes ago" | grep heartbeat

# Verify backup schedule is active
crontab -l | grep backup
```

### 5. Post-Restore Actions

- [ ] Verify all agent connections are re-established (check host health status)
- [ ] Re-issue client certificates if CA key was restored from a different generation
- [ ] Verify email notifications are working (send test email from Settings page)
- [ ] Review audit log integrity (run verification from Reports page)
- [ ] Update monitoring/alerting to reflect new host if IP changed

## Disaster Recovery Scenarios

### Scenario: Database Corruption
```bash
# Stop services
systemctl stop patch-manager.target

# Drop and recreate database
sudo -u postgres dropdb patch_manager
sudo -u postgres createdb -O patch_manager patch_manager

# Restore from latest backup
pg_restore -U patch_manager -d patch_manager -Fc /var/backups/patch-manager/patch_manager_db_LATEST.dump

# Start services
systemctl start patch-manager.target
```

### Scenario: Complete Host Loss
1. Provision new Ubuntu 24.04 host
2. Copy backup files from off-site storage
3. Run `scripts/setup.sh`
4. Follow restore steps 1-5 above
5. Update DNS/load balancer to point to new host
6. Re-establish agent connections (agents will reconnect automatically if FQDN is unchanged)

### Scenario: CA Key Compromise
1. Revoke all issued certificates (mark revoked in `certificates` table)
2. Generate new CA key pair via the Certificates page
3. Re-issue all client certificates
4. Distribute new root CA cert to all agents
5. Force all agents to reconnect

## Notes
- Migrations run automatically on web process startup.
- The CA private key is the most critical secret — losing it requires re-issuing all mTLS certificates.
- JWT signing key rotation is handled automatically every 90 days; no manual intervention needed.
- Backup retention is 30 days by default; adjust `RETENTION_DAYS` in backup.sh for compliance needs.
- For HIPAA/PCI-DSS compliance, set `GPG_RECIPIENT` to ensure secrets are encrypted at rest in backups.
