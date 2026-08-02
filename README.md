# Linux Patch Manager

**Enterprise-class secure web-based management interface for controlling patching and updates on Linux servers and workstations.**

## Overview

Linux Patch Manager provides a centralized web interface to manage patching and software updates across a fleet of Linux servers and workstations. It communicates with managed devices through the [Linux Patch API](https://github.com/Draco-Lunaris/Linux-Patch-Api), leveraging mTLS-secured RESTful endpoints for all operations.

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

Download the latest `.deb` package from the [GitHub Releases](https://github.com/Draco-Lunaris/Linux-Patch-Manager/releases) page:

```bash
# Replace vX.Y.Z with the latest release tag
wget https://github.com/Draco-Lunaris/Linux-Patch-Manager/releases/download/v1.5.5/linux-patch-manager_1.5.5-1_amd64.deb
```

#### 2. Install the Package

```bash
sudo apt install -y ./linux-patch-manager_1.5.5-1_amd64.deb
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

#### 3. Retrieve the Initial Admin Password

The admin password is generated on first startup and printed to the journal:

```bash
journalctl -u patch-manager-web | grep -A2 'INITIAL ADMIN PASSWORD' | tail -3
```

You will be forced to change it on first login.

### Option B: Docker Compose

```bash
cp .env.example .env
# Edit .env to set DB_PASSWORD
docker compose up -d
```

The Docker image is published to `ghcr.io/draco-lunaris/linux-patch-manager`. Docker Compose starts PostgreSQL 16 and the manager with persistent volumes for config, logs, and database data.

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

## Documentation

| Document | Description |
|----------|-------------|
| [SPEC.md](SPEC.md) | Full project specification |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture and design decisions |
| [REQUIREMENTS.md](REQUIREMENTS.md) | Functional and non-functional requirements |
| [INTERFACE_CONTRACT.md](INTERFACE_CONTRACT.md) | Manager-agent API interface contract |
| [docs/REST_API.md](docs/REST_API.md) | Complete REST API reference |
| [docs/security-review.md](docs/security-review.md) | Security audit findings |
| [docs/compliance-mapping.md](docs/compliance-mapping.md) | HIPAA/PCI-DSS compliance mapping |
| [docs/gpg-key-rotation.md](docs/gpg-key-rotation.md) | GPG signing key rotation procedure |
| [docs/runbooks/restore.md](docs/runbooks/restore.md) | Disaster recovery procedures |
| [docs/runbooks/key-management.md](docs/runbooks/key-management.md) | Key management runbook |
| [docs/runbooks/reverse-proxy-deployment.md](docs/runbooks/reverse-proxy-deployment.md) | Reverse proxy deployment guide |

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