# Linux Patch Manager

[![CI](https://github.com/Draco-Lunaris/Linux-Patch-Manager/actions/workflows/ci.yml/badge.svg)](https://github.com/Draco-Lunaris/Linux-Patch-Manager/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Draco-Lunaris/Linux-Patch-Manager?sort=semver)](https://github.com/Draco-Lunaris/Linux-Patch-Manager/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Enterprise-class secure web-based management interface for controlling patching and updates on Linux servers and workstations.**

## Overview

Linux Patch Manager provides a centralized web interface to manage patching and software updates across a fleet of Linux servers and workstations. It communicates with managed devices through the [Linux Patch API](https://github.com/Draco-Lunaris/Linux-Patch-Api), leveraging mTLS-secured RESTful endpoints for all operations.

Because the manager holds mTLS authority over every host it manages, security is a
primary design constraint rather than a feature. See **[Security Model](#security-model)**
for the trust boundaries, [SECURITY.md](SECURITY.md) for the vulnerability disclosure
policy, and [docs/compliance-mapping.md](docs/compliance-mapping.md) for the
HIPAA / PCI-DSS control mapping.

## Key Features

- **Centralized Dashboard** — Monitor patch status across all managed hosts from a single interface
- **Multi-Distribution Support** — Manage Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, and Arch hosts
- **Secure by Design** — mTLS authentication, role-based access control (Admin/Operator/Reporter), tamper-evident audit log with hash-chain integrity
- **Batch Operations** — Apply patches and updates across multiple hosts simultaneously
- **Maintenance Windows** — Schedule patch windows (daily/weekly/monthly recurring or one-time) with auto-apply and configurable reboot delays
- **Self-Enrollment** — Automated agent enrollment with PKI provisioning and admin approval workflow
- **Agent Self-Upgrade** — Manager-hosted GPG-signed package repository with automatic sync from GitHub Releases; agents self-upgrade from the manager's repo
- **Real-Time Job Monitoring** — WebSocket streaming for live patch job status from agents
- **Compliance Reporting** — CSV and PDF exports with charts (compliance, patch history, vulnerability exposure, audit trail)
- **Authentication** — Username/password with TOTP MFA, WebAuthn (passkeys), and SSO via Azure AD / OIDC / Keycloak
- **Email Notifications** — Optional SMTP integration for job completion and maintenance window reminders
- **Health Monitoring** — Agent health polling, CRL status tracking, GPG key expiry monitoring, configurable service/HTTP health checks
- **IP Allowlist** — Configurable IP whitelist with trusted reverse-proxy support

## Architecture

Linux Patch Manager is a web application that acts as a management plane, communicating with the Linux Patch API agent running on each managed host.

```
+---------------------+
|  Linux Patch Manager |  <- Web UI (this project)
|   (Management Plane) |
+----------+----------+
           |  mTLS / REST API
     +-----+-----+
     v     v     v
+------+ +------+ +------+
| Host | | Host | | Host |  <- Linux Patch API agents
|  A   | |  B   | |  C   |
+------+ +------+ +------+
```

The manager consists of two services:
- **pm-web** — Axum web server (REST API, frontend SPA, package repo on port 80)
- **pm-worker** — Background worker (health polling, patch scheduling, package sync, audit verification)

## Security Model

### Trust Boundaries

| Boundary | Control |
|----------|---------|
| **Operator → Web UI** | HTTPS only. Username/password with Argon2id hashing, TOTP MFA, WebAuthn passkeys, or SSO (Azure AD / OIDC / Keycloak). Optional IP allowlist with trusted reverse-proxy support. Per-endpoint rate limiting on auth and enrollment. |
| **Manager → Agent** | Mutual TLS on every request. Agent certificates are issued by the manager's internal CA (ECDSA P-256, 10-year root) and revocable via a CRL served by the manager. |
| **Agent enrollment** | Self-enrollment requires explicit admin approval before a PKI bundle is issued. Bundles are single-retrieval, held in memory only, and expire after 10 minutes. Polling tokens are stored as SHA-256 hashes, never in plaintext. |
| **Manager → Package repo** | Packages are GPG-signed; agents verify signatures before installing. Repo metadata integrity does not depend on TLS. GPG key expiry is monitored and surfaced in the UI. |
| **Within the manager** | Role-based access control with three roles (Admin / Operator / Reporter). All privileged actions are recorded in a tamper-evident audit log chained by SHA-256 hashes; a background verifier checks chain integrity continuously. |
| **Supply chain** | Every release is gated in CI on `cargo audit`, Gitleaks secret scanning over full history, clippy, and the full test suite, plus a guard that refuses to build a tag whose version does not match `Cargo.toml`. Release artifacts ship with SHA-256 checksums, a detached GPG signature, and a signed build-provenance attestation ([docs/release-signing.md](docs/release-signing.md)). |

### Residual Risks

The manager is a high-value target by construction: a compromised manager can push
arbitrary packages to every enrolled host. Deployments should treat it as
tier-0 infrastructure — restrict network reach to the admin UI, keep the CA key on
an encrypted volume, and review the audit log off-box.

Known design tradeoffs, including the current server-generated agent key flow and
its planned replacement with CSR-based enrollment, are documented candidly in
[SECURITY.md](SECURITY.md#enrollment-pki-design-decisions).

Full detail lives in [ARCHITECTURE.md § 7 — Security Architecture](ARCHITECTURE.md#7-security-architecture).

## System Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Ubuntu 24.04 LTS (Noble) — or any Linux with Docker |
| **Database** | PostgreSQL 16 |
| **Memory** | 2 GB RAM minimum, 4 GB recommended |
| **Storage** | 1 GB for application + database space |
| **Network** | HTTPS (port 443) for web UI, HTTP (port 80) for package repo |
| **Supported Hosts** | Up to ~2,500 agents (single-instance; manual sharding beyond that) |

## Installation

### Option A: Debian Package (Recommended for Production)

#### 1. Download the Package

Download the latest release assets — the `.deb`, its `SHA256SUMS`, and the detached
signature — from
[GitHub Releases](https://github.com/Draco-Lunaris/Linux-Patch-Manager/releases/latest).

With the [GitHub CLI](https://cli.github.com/):

```bash
gh release download --repo Draco-Lunaris/Linux-Patch-Manager \
  --pattern '*_amd64.deb' --pattern 'SHA256SUMS*' \
  --pattern 'release-signing-key.asc'
```

Or with `curl` alone (resolves the latest tag, so there is no version to edit):

```bash
REPO=Draco-Lunaris/Linux-Patch-Manager
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep -m1 '"tag_name"' | cut -d'"' -f4)
for f in "linux-patch-manager_${TAG#v}-1_amd64.deb" SHA256SUMS SHA256SUMS.asc; do
  curl -fsSLO "https://github.com/$REPO/releases/download/$TAG/$f"
done
```

#### 2. Verify the Package

This package installs as root, creates the internal CA, and from then on holds mTLS
authority over every host you manage. Verify it before installing.

```bash
# 1. Authenticity — was the checksum list signed by the project's key?
gpg --import release-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS

# 2. Integrity — does the .deb match the list you just verified?
sha256sum --check --ignore-missing SHA256SUMS

# 3. Provenance — was this binary built by this repo's release workflow?
gh attestation verify linux-patch-manager_*_amd64.deb \
  --repo Draco-Lunaris/Linux-Patch-Manager
```

Run them in that order. `SHA256SUMS` is published in the same release as the `.deb`, so
on its own it proves only that the two files agree with each other — anyone able to
replace the package could replace the checksum list with it. The signature and the
attestation are what make the checksum meaningful: the signature proves the list came
from a key the project controls, and the attestation proves the binary came out of a
tagged CI run in this repository.

Expect `Good signature from ...` in step 1. An accompanying `WARNING: This key is not
certified with a trusted signature` is normal — it means you have not signed the key
yourself, not that the check failed. `BAD signature` is a hard stop.

Verify the key's fingerprint against the one recorded in [SECURITY.md](SECURITY.md)
rather than trusting it just because it came from the same release.
[docs/release-signing.md](docs/release-signing.md) covers what each artifact does and
does not prove.

> **Note:** these assets are published by the current release workflow. On an older
> release they are absent and the commands report nothing to check — prefer the latest
> release, or compare the digest shown on the release page by hand.

#### 3. Install the Package

```bash
sudo apt install -y ./linux-patch-manager_*_amd64.deb
```

The post-install script handles everything automatically:
- Creates the `patch-manager` service user
- Creates required directories (`/etc/patch-manager/`, `/var/www/lpa-repo/`, etc.)
- Creates the PostgreSQL database and user with a generated password
- Writes `/etc/patch-manager/config.toml` with the DB connection string
- Generates Ed25519 JWT signing/verification keys
- Generates the internal Certificate Authority (CA)
- Generates a CA-signed web TLS certificate (HTTPS by default)
- Generates the manager's mTLS client certificate
- Enables and starts `patch-manager.target` (pm-web + pm-worker)
- Installs a nightly backup cron job

No manual database setup, key generation, or migration execution is needed — the application runs migrations automatically on startup via sqlx.

#### 4. Retrieve the Initial Admin Password

The admin password is generated on first startup and printed to the journal:

```bash
journalctl -u patch-manager-web | grep -A2 'INITIAL ADMIN PASSWORD' | tail -3
```

You will be forced to change it on first login.

> **Note:** the generated password stays in the systemd journal after you read it.
> Once you have logged in and changed it, clear the entry or rotate the journal
> (`journalctl --rotate && journalctl --vacuum-time=1s`) so the initial credential
> does not persist on disk.

### Option B: Docker Compose

The image is published to `ghcr.io/draco-lunaris/linux-patch-manager`. Compose brings
up PostgreSQL 16 alongside the manager with persistent volumes.

#### 1. Configure

```bash
cp .env.example .env

# Generate a strong database password rather than editing the placeholder by hand
sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=$(openssl rand -base64 24)|" .env

# Pin the image to a release tag instead of 'latest' for reproducible deployments
LPM_TAG=$(curl -fsSL https://api.github.com/repos/Draco-Lunaris/Linux-Patch-Manager/releases/latest \
  | grep -m1 '"tag_name"' | cut -d'"' -f4)
sed -i "s|^TAG=.*|TAG=${LPM_TAG}|" .env
```

#### 2. Start

```bash
docker compose up -d
docker compose logs -f app
```

On first start the entrypoint waits for PostgreSQL, applies migrations, generates the
admin password, generates the Ed25519 JWT signing keys, and writes
`/etc/patch-manager/config.toml` from the shipped example. `pm-web` then generates the
internal CA and the GPG repo signing key on its first run.

#### 3. Retrieve the Initial Admin Password

It is printed once to the container logs and also written to a `0600` file inside the
config volume:

```bash
docker compose logs app | grep -A5 'Admin Credentials'

# or, if the log line has already scrolled away
docker compose exec app cat /etc/patch-manager/admin-password.txt
```

#### Volumes

| Volume | Mount | Contents |
|--------|-------|----------|
| `pm-config` | `/etc/patch-manager` | `config.toml`, internal CA, JWT keys, GPG keys, TLS certs |
| `pm-logs` | `/var/log/patch-manager` | Application logs |
| `pm-data` | `/opt/patch-manager` | Application state |
| `pgdata` | `/var/lib/postgresql/data` | Database |

`pm-config` holds the CA private key and the JWT signing key. Back it up, and encrypt
the volume at rest.

#### Two Differences From the Debian Package

Unlike the `.deb` post-install script, the container entrypoint does **not** generate a
web TLS certificate, and Compose publishes only port 443:

1. **No web TLS certificate is created.** `pm-web` falls back to plain HTTP when
   `/etc/patch-manager/tls/web.crt` and `web.key` are missing, logging
   `TLS certificates not found — falling back to plain HTTP`. It still listens on port
   443, so `https://` will fail and credentials would cross the network in cleartext.
   Before exposing the container, either mount a certificate and key at those two paths,
   or terminate TLS at a reverse proxy in front of it — see
   [docs/runbooks/reverse-proxy-deployment.md](docs/runbooks/reverse-proxy-deployment.md).
   Confirm which path you are on:

   ```bash
   docker compose logs app | grep -E 'Listening \((HTTPS|HTTP)'
   ```

2. **The package repo port is not published.** Agent self-upgrade pulls from the
   manager-hosted repo on port 80. To enable it, add the mapping to the `app` service
   in `docker-compose.yml`:

   ```yaml
   ports:
     - "443:443"
     - "80:80"    # GPG-signed package repo for agent self-upgrade
   ```

### Option C: Build from Source

#### Prerequisites

- **Rust toolchain** (stable) — [rustup](https://rustup.rs/)
- **Node.js** 20+ (for the frontend)
- **System dependencies**: `pkg-config`, `libssl-dev`, `libfontconfig1-dev`, `postgresql-16`

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install system dependencies (Ubuntu/Debian)
sudo apt install -y pkg-config libssl-dev libfontconfig1-dev postgresql-16
```

#### Build

```bash
# Build the Rust backend (release)
cargo build --release

# Build the frontend
cd frontend
npm ci
npm run build
cd ..

# Build a .deb package (optional)
chmod +x scripts/build-package.sh
./scripts/build-package.sh
```

The release binaries will be at `target/release/pm-web` and `target/release/pm-worker`.

## Configuration

The main configuration file is at `/etc/patch-manager/config.toml`. A fully commented example is available at [`config/config.example.toml`](config/config.example.toml).

Key sections:

| Section | Purpose |
|---------|---------|
| `[server]` | Bind address, HTTPS port, static file path |
| `[database]` | PostgreSQL connection URL, pool sizing |
| `[worker]` | Health/patch polling intervals, concurrency limits |
| `[security]` | IP whitelist, trusted proxies, JWT keys, TLS certs, CA paths, SSO callback |
| `[repo]` | Manager-hosted package repo (GPG signing, base URL, port 80) |
| `[worker.package_sync]` | GitHub Releases sync (repo, interval, max releases) |
| `[rate_limit]` | Per-endpoint rate limiting (enrollment, auth, API) |
| `[logging]` | Log level and format (json/pretty) |

Environment variable overrides follow the pattern `PATCH_MANAGER__SECTION__KEY=value` (e.g., `PATCH_MANAGER__DATABASE__URL=postgres://...`).

## Starting Services

```bash
# Enable and start both pm-web and pm-worker
sudo systemctl enable --now patch-manager.target

# Verify
systemctl status patch-manager-web
systemctl status patch-manager-worker

# Check logs
journalctl -u patch-manager-web -f
journalctl -u patch-manager-worker -f
```

## Initial Access

1. Open a web browser and navigate to: `https://your-server-ip`
2. Log in with username `admin` and the generated password (see above)
3. Complete the initial setup: change admin password, configure MFA
4. Enroll your first host via the Self-Enrollment workflow

## Post-Installation Hardening

The `.deb` installer gets you to a working, HTTPS-serving manager (Docker needs the
TLS step above first). These items take it from working to production-ready — and the
first two matter most, because the manager can push packages to every host it manages.

- [ ] **Replace the web TLS certificate.** The post-install script issues the web cert
      from the manager's own internal CA, so browsers will not trust it and operators
      get click-through warnings that train them to ignore certificate errors. Install a
      certificate from a CA your clients trust, set
      `web_tls_strategy = 'operator_supplied'` in system config, and point
      `web_tls_cert_path` / `web_tls_key_path` at it.
- [ ] **Restrict reach to the admin UI.** Port 443 should be reachable only from
      operator networks or a bastion — firewall it, and set `[security].ip_whitelist`
      with `trusted_proxies` if you front the manager with a reverse proxy.
- [ ] **Scope the package repo on port 80.** It serves GPG-signed metadata over plain
      HTTP by design (signatures provide integrity), but it needs to be reachable only
      from managed hosts. Do not expose it to the internet.
- [ ] **Protect the CA and signing keys.** `/etc/patch-manager/ca/` holds the CA private
      key and the GPG repo signing key — compromise of either is fleet-wide. Keep them
      on an encrypted volume and confirm the nightly backup cron is writing somewhere
      off-box. See [docs/runbooks/key-management.md](docs/runbooks/key-management.md).
- [ ] **Enforce MFA for every operator**, not just the initial admin, and prefer
      WebAuthn passkeys or SSO over TOTP where you can.
- [ ] **Clear the initial admin password** from the systemd journal (`.deb`) or
      `/etc/patch-manager/admin-password.txt` (Docker) once you have logged in.
- [ ] **Ship the audit log off-box.** The hash chain is tamper-evident, not
      tamper-proof — detection only helps if a copy survives the host. Schedule
      **Reports > Audit Integrity Verification** and export regularly.
- [ ] **Set GPG key expiry monitoring thresholds** so repo signing keys are rotated
      before they lapse. See [docs/gpg-key-rotation.md](docs/gpg-key-rotation.md).
- [ ] **Test a restore** before you need one:
      [docs/runbooks/restore.md](docs/runbooks/restore.md).

## Upgrading

### Debian Package

```bash
# Download and verify the new release exactly as in installation, then
sudo apt install -y ./linux-patch-manager_*_amd64.deb
sudo systemctl restart patch-manager.target
```

Your `/etc/patch-manager/config.toml`, CA, and keys are preserved; `.deb` upgrades do
not overwrite existing configuration. Schema migrations run automatically on startup via
sqlx, so no manual migration step is needed. Confirm the upgrade landed:

```bash
journalctl -u patch-manager-web -n 50 | grep -iE 'version|migration'
```

### Docker Compose

```bash
# Set TAG to the release you are upgrading to, then
docker compose pull && docker compose up -d
```

Back up the `pm-config` and `pgdata` volumes before a major-version upgrade. Migrations
are forward-only — a rollback needs a database restore, so take the backup first.

## Documentation

| Document | Description |
|----------|-------------|
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy, supported versions, PKI design decisions |
| [docs/compliance-mapping.md](docs/compliance-mapping.md) | HIPAA / PCI-DSS control mapping |
| [SPEC.md](SPEC.md) | Full project specification |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture and design decisions (§ 7 covers security architecture) |
| [REQUIREMENTS.md](REQUIREMENTS.md) | Functional and non-functional requirements |
| [INTERFACE_CONTRACT.md](INTERFACE_CONTRACT.md) | Manager-agent API interface contract |
| [docs/REST_API.md](docs/REST_API.md) | Complete REST API reference |
| [docs/security-review.md](docs/security-review.md) | Security audit findings |
| [docs/release-signing.md](docs/release-signing.md) | Release artifact signing, verification, and key setup |
| [docs/gpg-key-rotation.md](docs/gpg-key-rotation.md) | Package-repository GPG key rotation procedure |
| [docs/runbooks/restore.md](docs/runbooks/restore.md) | Disaster recovery procedures |
| [docs/runbooks/key-management.md](docs/runbooks/key-management.md) | Key management runbook |
| [docs/runbooks/reverse-proxy-deployment.md](docs/runbooks/reverse-proxy-deployment.md) | Reverse proxy deployment guide |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, commit conventions, PR requirements |

## Related Projects

- **[Linux Patch API](https://github.com/Draco-Lunaris/Linux-Patch-Api)** — The agent that runs on each managed host

## Troubleshooting

### Services Won't Start

```bash
# Check service status
systemctl status patch-manager-web.service
systemctl status patch-manager-worker.service

# Check logs for errors
journalctl -u patch-manager-web -n 50
journalctl -u patch-manager-worker -n 50

# Check database connectivity
sudo -u postgres psql -h localhost -U patch_manager patch_manager -c "SELECT 1"

# Check port availability (web UI on 443, repo on 80)
sudo ss -tlnp | grep -E '443|80'
```

### Database Migration Issues

Migrations run automatically on startup via sqlx. If migrations fail:

```bash
# Check migration status
sudo -u postgres psql patch_manager -c "SELECT version, success FROM _sqlx_migrations ORDER BY version;"

# Check logs for migration errors
journalctl -u patch-manager-web | grep -i migration
```

### Audit Integrity Errors

If the audit verifier reports hash chain errors:

```bash
# Check audit verifier logs
journalctl -u patch-manager-worker | grep -i "audit chain"
```

Use the **Reports > Audit Integrity Verification** page in the web UI to verify and repair the chain. The "Repair Chain" button recomputes all hash values from row 1 forward (admin-only).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, commit conventions, and PR requirements.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright 2025-2026 Draco Lunaris