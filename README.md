# Linux Patch Manager

**Enterprise-class secure web-based management interface for controlling patching and updates on Linux servers and workstations.**

## Overview

Linux Patch Manager provides a centralized web interface to manage patching and software updates across a fleet of Linux servers and workstations. It communicates with managed devices through the [Linux Patch API](https://gitea.moon-dragon.us/echo/linux_patch_api), leveraging mTLS-secured RESTful endpoints for all operations.

## Key Features

- **Centralized Dashboard** — Monitor patch status across all managed hosts from a single interface
- **Multi-Distribution Support** — Manage Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, and Arch hosts
- **Secure by Design** — mTLS authentication, role-based access control, audit logging
- **Batch Operations** — Apply patches and updates across multiple hosts simultaneously
- **Scheduling** — Plan and schedule patch windows with approval workflows
- **Self-Enrollment** — Automated agent enrollment with PKI provisioning and admin approval workflow
- **Reporting** — Compliance reporting and patch status dashboards

## Architecture

Linux Patch Manager is a web application that acts as a management plane, communicating with the Linux Patch API agent running on each managed host.

```
┌─────────────────────┐
│  Linux Patch Manager │  ← Web UI (this project)
│   (Management Plane) │
└──────────┬──────────┘
           │  mTLS / REST API
    ┌──────┼──────┐
    ▼      ▼      ▼
┌──────┐┌──────┐┌──────┐
│ Host ││ Host ││ Host │  ← Linux Patch API agents
│  A   ││  B   ││  C   │
└──────┘└──────┘└──────┘
```

## System Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Ubuntu 24.04 LTS (Noble) |
| **Database** | PostgreSQL 16 |
| **Memory** | 2 GB RAM minimum, 4 GB recommended |
| **Storage** | 1 GB for application + database space |
| **Network** | HTTPS access (port 443 recommended) |

## Installation

### 1. Download the Package

Download the latest `.deb` package from the [Gitea Releases](https://gitea-lxc.moon-dragon.us/echo/linux_patch_manager/releases) page:

```bash
wget https://gitea-lxc.moon-dragon.us/echo/linux_patch_manager/releases/download/v0.1.7/linux-patch-manager_0.1.7-1_amd64.deb
```

### 2. Install Dependencies

```bash
sudo apt update
sudo apt install -y postgresql-16 libssl3
```

### 3. Install the Package

```bash
sudo dpkg -i linux-patch-manager_0.1.7-1_amd64.deb
```

Or with automatic dependency resolution:

```bash
sudo apt install ./linux-patch-manager_0.1.7-1_amd64.deb
```

## Configuration

### 1. Database Setup

Create the PostgreSQL database and user:

```bash
sudo -u postgres psql <<EOF
CREATE DATABASE patch_manager;
CREATE USER patch_manager WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE patch_manager TO patch_manager;
\q
EOF
```

### 2. Generate JWT Keys

```bash
sudo mkdir -p /etc/patch-manager/jwt
sudo openssl genpkey -algorithm ed25519 -out /etc/patch-manager/jwt/signing.pem
sudo openssl pkey -in /etc/patch-manager/jwt/signing.pem -pubout -out /etc/patch-manager/jwt/verify.pem
sudo chmod 600 /etc/patch-manager/jwt/signing.pem
```

### 3. Configure the Application

Edit the configuration file:

```bash
sudo nano /etc/patch-manager/config.toml
```

Example configuration:

```toml
[database]
url = "postgres://patch_manager:your_secure_password@localhost/patch_manager"

[server]
host = "0.0.0.0"
port = 443

[security]
ip_whitelist = []
jwt_signing_key_path = "/etc/patch-manager/jwt/signing.pem"
jwt_verify_key_path = "/etc/patch-manager/jwt/verify.pem"
```

### 4. Run Database Migrations

```bash
sudo -u postgres psql patch_manager < /usr/share/patch-manager/migrations/001_initial_schema.sql
sudo -u postgres psql patch_manager < /usr/share/patch-manager/migrations/002_seed_admin.sql
sudo -u postgres psql patch_manager < /usr/share/patch-manager/migrations/003_jobs_scheduling.sql
sudo -u postgres psql patch_manager < /usr/share/patch-manager/migrations/004_maintenance_windows.sql
sudo -u postgres psql patch_manager < /usr/share/patch-manager/migrations/005_audit_hardening.sql
```

## Starting Services

### Start the Application

```bash
sudo systemctl enable --now patch-manager.target
```

### Verify Services are Running

```bash
systemctl status patch-manager-web
systemctl status patch-manager-worker
```

### Check Logs

```bash
journalctl -u patch-manager-web -f
journalctl -u patch-manager-worker -f
```

## Initial Access

1. Open a web browser and navigate to: `https://your-server-ip:443`

2. Default admin credentials (change immediately!):
   - **Username:** `admin`
   - **Password:** Check the migration output or set during setup

3. Complete the initial setup wizard to configure:
   - Admin password change
   - MFA setup
   - First host enrollment

## Building from Source

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Node.js 18+
sudo apt install -y nodejs npm

# Build dependencies
sudo apt install -y pkg-config libssl-dev postgresql-16
```

### Build the Package

```bash
cd /path/to/linux_patch_manager
chmod +x scripts/build-package.sh
./scripts/build-package.sh
```

The `.deb` package will be created in the project root directory.

## Documentation

| Document | Description |
|----------|-------------|
| [docs/REST_API.md](docs/REST_API.md) | Complete REST API reference (including Self-Enrollment endpoints) |
| [SPEC.md](SPEC.md) | Full project specification |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture and design decisions |
| [REQUIREMENTS.md](REQUIREMENTS.md) | Functional and non-functional requirements |
| [docs/security-review.md](docs/security-review.md) | Security audit findings |
| [docs/runbooks/restore.md](docs/runbooks/restore.md) | Disaster recovery procedures |

## Related Projects

- **[Linux Patch API](https://gitea-lxc.moon-dragon.us/echo/linux_patch_api)** — The API agent that runs on each managed host

## Troubleshooting

### Services Won't Start

```bash
# Check configuration syntax
sudo patch-manager-web --validate-config

# Check database connectivity
sudo -u postgres psql -h localhost -U patch_manager patch_manager -c "SELECT 1"

# Check port availability
sudo ss -tlnp | grep 8080
```

### Database Migration Issues

```bash
# Check migration status
sudo -u postgres psql patch_manager -c "\dt"

# Re-run specific migration
sudo -u postgres psql patch_manager < /usr/share/patch-manager/migrations/001_initial_schema.sql
```

## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright 2025-2026 Draco Lunaris

---

**Version:** 1.0.0-1  
**Release:** v0.0.2  
**Build Date:** 2026-04-28
