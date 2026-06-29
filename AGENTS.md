# AGENTS.md — Linux Patch Manager

**Repository:** `Draco-Lunaris/Linux-Patch-Manager`
**Purpose:** Centralized patch management platform for Linux hosts
**Language:** Rust (backend) + TypeScript/React (frontend)
**Default Branch:** `master`

---

## Project Overview

The Linux Patch Manager is the server-side component of the Linux Patch Management system. It manages hosts, schedules patches, issues certificates, and hosts a GPG-signed package repository for agent self-updates.

### Key Components

| Crate | Purpose |
|-------|---------|
| `pm-web` | Axum web server (API + frontend + repo server) |
| `pm-worker` | Background worker (health polling, patch scheduling, package sync) |
| `pm-core` | Shared models, config, database, crypto |
| `pm-auth` | JWT authentication, RBAC |
| `pm-ca` | Internal certificate authority |
| `pm-agent-client` | mTLS client for agent communication |
| `pm-reports` | PDF report generation |
| `migrate-secrets` | Secret encryption migration tool |

---

## Build & Test Commands

```bash
# Check compilation
cargo check

# Format code
cargo fmt --all

# Lint
cargo clippy --all-targets --all-features

# Run tests
cargo test --workspace --all-features --lib --bins --tests

# Security audit
cargo audit

# Frontend lint
cd frontend && npx eslint src/ --ext .ts,.tsx --max-warnings 0 && npx tsc --noEmit

# Build release
cargo build --release
```

---

## Critical Architectural Rules

### 1. Manager Pull Model ONLY

The ONLY valid package delivery mechanism for agent self-updates is the **Manager Pull model**. The manager pulls packages from GitHub Releases via standard HTTP, signs them with its own GPG key, and hosts them in a local package repository.

**NEVER implement or reference a CI push model.** CI push is logistically impossible, requires non-existent infrastructure, and was never the intended design.

### 2. Per-Manager GPG Key

Each manager instance generates and manages its own unique GPG signing key. The key is stored alongside the CA root/key in the manager's configuration directory (e.g., `/etc/patch-manager/ca/`).

**NEVER store GPG keys in Vaultwarden, CI secrets, or any shared location.** Each manager is self-contained.

### 3. No Embedded Credentials

This is an open-source project. Managers may number in the thousands. **NEVER embed credentials, tokens, or secrets in code or configuration.** Package pulling must use standard HTTP GET (wget/curl) from public GitHub Releases API.

### 4. Plain HTTP Repo Server

The package repository is served on port 80 (plain HTTP) for internal network access. Package integrity is verified by the agent's native package manager via GPG signatures — no TLS or authentication is needed on the repo paths.

### 5. Database Migrations

- All schema changes must have a migration file in `migrations/`
- Use `ALTER TYPE ... ADD VALUE IF NOT EXISTS` for enum types (NOT `INSERT INTO`)
- Migrations are run automatically on startup by sqlx

### 6. Agent Communication

- All agent communication uses mTLS (client certificates issued by the manager's CA)
- Agent health polling includes CRL status and GPG key status
- Self-upgrade jobs use exponential backoff for reconnect confirmation

---

## Git Conventions

- **Branch naming:** `feat/`, `fix/`, `docs/`, `chore/`, `release/` prefixes
- **Commit format:** Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`)
- **PR required for master:** Branch protection is enabled
- **Tag format:** `vX.Y.Z` for releases, `vX.Y.Z-N` for hotfix revisions

---

## Related Repositories

- **Agent:** `Draco-Lunaris/Linux-Patch-Api` — The agent that runs on managed hosts
- **Shared Spec:** `SPEC.md` in this repo defines the manager-agent contract

---

## Lessons Learned

1. **Migration 028 crash:** Used `INSERT INTO audit_action` but `audit_action` is an ENUM TYPE, not a table. Fixed with `ALTER TYPE ... ADD VALUE IF NOT EXISTS`.
2. **CI push hallucination:** Design docs described a CI push model that referenced non-existent servers and impossible infrastructure. Removed and replaced with Manager Pull model.
3. **Repo sync never completes:** `trigger_sync` handler was an empty stub. Fixed by implementing actual sync logic.
4. **GPG key in wrong location:** Initially stored in Vaultwarden. Corrected to per-manager storage alongside CA.
