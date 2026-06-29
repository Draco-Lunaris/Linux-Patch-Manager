# Manager-Side Self-Update Architecture — Manager Pull Model

**Version:** 2.0.0
**Date:** 2026-06-29
**Status:** Active
**Repository:** linux-patch-manager

---

## 1. Overview

The manager-side self-update architecture enables the Linux Patch Manager to host a GPG-signed package repository that agents use for self-updates. The manager pulls packages from GitHub Releases via standard HTTP, signs them with its own unique GPG key, and serves them to agents over plain HTTP on port 80.

### Key Design Principles

1. **Manager Pull Model** — The manager pulls packages from GitHub Releases; no CI push, no embedded credentials
2. **Per-Manager GPG Key** — Each manager generates and manages its own unique GPG signing key, stored alongside its CA root/key
3. **Standard HTTP Pull** — Packages are fetched via standard HTTP GET (wget/curl) from GitHub Releases API; no Git-specific code, no embedded tokens
4. **Native Package Manager Compatibility** — Packages are signed and hosted in a format compatible with apt, dnf, apk, and pacman
5. **Self-Contained** — No shared secrets, no Vaultwarden for GPG keys, no external infrastructure dependencies

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          MANAGER HOST                                    │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐   │
│  │ Patch Manager    │  │ Repo Server      │  │ GPG Key Management   │   │
│  │ (Rust API)       │  │ (axum ServeDir)  │  │                      │   │
│  │                  │  │                  │  │ Key generation:       │   │
│  │ Enrollments      │  │ /apt/            │  │   manager init       │   │
│  │ CRL issuance     │  │ /dnf/            │  │ Key storage:         │   │
│  │ Upgrade API      │  │ /apk/            │  │   alongside CA       │   │
│  │ Health polls     │  │ /pacman/         │  │ Key distribution:    │   │
│  │                  │  │                  │  │   enrollment         │   │
│  │ Package Sync     │  │ Port 80 (HTTP)   │  │                      │   │
│  │ Worker           │  │                  │  │ Repo signing:        │   │
│  │ (pulls from      │  │                  │  │   manager            │   │
│  │  GitHub)         │  │                  │  │                      │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────────┘   │
│         │                       ▲                       ▲                │
│         │                       │                       │                │
│  ┌──────┴───────┐         ┌─────┴──────┐         ┌──────┴──────┐        │
│  │ Enrollment   │         │ Package    │         │ GPG Key     │        │
│  │ Response     │         │ Sync       │         │ Generation  │        │
│  │ + repo config│         │ Worker     │         │ (init)      │        │
│  │ + GPG key    │         │ (scheduled │         │             │        │
│  └──────────────┘         │  or manual)│         └─────────────┘        │
│                           └────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 GPG Key Management

Each manager generates its own unique GPG signing key during initialization. The key is stored alongside the CA root/key in the manager's configuration directory.

**Key properties:**
- RSA 4096-bit signing key
- 2-year expiry with automatic renewal
- Stored in the same directory as CA certificates (e.g., `/etc/patch-manager/ca/`)
- Public key distributed to agents via enrollment `PkiBundle.repo_config`
- Private key used to sign repo metadata (apt Release, dnf repomd.xml, etc.)

**Key generation command:**
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

### 3.2 Package Sync Worker

The package sync worker runs as a background task in `pm-worker`. It fetches the last N releases from GitHub Releases via the public API, downloads package assets, imports them into the local repo, and signs the repo metadata.

**Workflow:**
1. Fetch releases from `GET https://api.github.com/repos/Draco-Lunaris/Linux-Patch-Api/releases?per_page=N`
2. Filter out prereleases, take last N releases
3. For each release, download package assets (`.deb`, `.rpm`, `.apk`, `.pkg.tar.zst`)
4. Import into local repo:
   - `.deb` → `reprepro includedeb <codename>`
   - `.rpm` → copy to dnf repo + `createrepo_c --update`
   - `.apk` → copy to apk repo + `apk index`
   - `.pkg.tar.zst` → copy to pacman repo + `repo-add`
5. Sign repo metadata with manager's GPG key
6. Record packages in `repo_packages` table
7. Update `repo_sync_log` with results

**Configuration:**
```toml
[worker.package_sync]
enabled = true
interval_secs = 3600
github_repo = "Draco-Lunaris/Linux-Patch-Api"
max_releases = 3
```

**Manual trigger:** `POST /api/v1/admin/repo/sync`

### 3.3 Repo Server

The repo server is a second axum listener on port 80 (plain HTTP) serving static files via `tower-http::ServeDir`.

**Routes:**
| Path | Content |
|------|---------|
| `/apt/` | reprepro output (Packages, Release, InRelease) |
| `/dnf/` | createrepo_c output (repodata/) |
| `/apk/` | APKINDEX.tar.gz + .apk files |
| `/pacman/` | repo database + .pkg.tar.zst files |

**No authentication required** — package integrity is verified by the agent's native package manager via GPG signatures.

### 3.4 Enrollment Integration

During enrollment approval, the manager:
1. Detects the agent's distro from `os_details`
2. Generates distro-specific `sources_config` (apt sources.list line, dnf repo file, etc.)
3. Reads the GPG public key from the manager's keyring
4. Determines the distro-specific `keyring_path`
5. Includes `repo_config` in the `PkiBundle` returned to the agent

**Fallback:** Agents enrolled before v2.0.0 can fetch `repo_config` via `GET /api/v1/pki/repo-config?distro_id=...`

### 3.5 Admin Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/admin/repo/sync` | POST | Trigger manual package sync |
| `/api/v1/admin/repo/sync-status` | GET | View recent sync logs and package count |
| `/api/v1/admin/repo/packages` | GET | List all packages in the repo |

All admin endpoints require Admin role (RBAC).

---

## 4. Database Schema

### repo_sync_log
Tracks each sync run (scheduled or manual).

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| triggered_by | TEXT | 'scheduler', 'manual', or 'ci' |
| status | TEXT | 'running', 'success', 'failed', 'partial' |
| packages_synced | INTEGER | Count of packages successfully imported |
| packages_skipped | INTEGER | Count of packages skipped |
| error_message | TEXT | Error details if failed/partial |
| started_at | TIMESTAMPTZ | When sync started |
| finished_at | TIMESTAMPTZ | When sync completed |

### repo_packages
Tracks individual packages in the manager-hosted repo.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| filename | TEXT | Package filename |
| version | TEXT | Release version |
| distro | TEXT | 'apt', 'dnf', 'apk', 'pacman' |
| distro_codename | TEXT | 'noble', 'jammy', 'bookworm', 'el9', etc. |
| arch | TEXT | 'amd64' |
| file_size | BIGINT | File size in bytes |
| sha256 | TEXT | SHA-256 checksum |
| gpg_signed | BOOLEAN | Whether package is GPG signed |
| source | TEXT | 'github' or 'manual' |
| synced_at | TIMESTAMPTZ | When package was synced |
| sync_log_id | UUID | FK to repo_sync_log |

---

## 5. Trust Chain

```
Manager generates own GPG key (alongside CA)
        ↓
  GPG public key delivered via mTLS enrollment (PkiBundle.repo_config)
        ↓
  Agent provisions GPG key to native package manager keyring
        ↓
  Manager pulls packages from GitHub Releases via HTTP
        ↓
  Manager signs packages with its own GPG key
        ↓
  Manager hosts signed packages in local repo (HTTP, port 80)
        ↓
  Agent's native package manager (apt/dnf/apk/pacman) verifies GPG signature before install
```

---

## 6. Threat Model

| Trust Boundary | Key Threat | Mitigation |
|----------------|-----------|------------|
| GitHub Releases → Manager | Package tampering in transit | GPG signing by manager after download; GitHub TLS |
| Manager → Agent (enrollment) | MITM during enrollment | TLS encryption, manager approval workflow |
| Agent → Package Repo | Repo server compromised | GPG-signed packages, key delivered via separate mTLS channel |
| Manager GPG Key | Key compromise | 2-year expiry, stored alongside CA, rotation via re-enrollment |

---

## 7. File Manifest

### Manager-Side Files

| File | Purpose |
|------|---------|
| `crates/pm-core/src/models.rs` | `RepoConfig` struct, `detect_distro_id()`, `generate_distro_config()` |
| `crates/pm-core/src/config.rs` | `RepoServerConfig`, `PackageSyncConfig` |
| `crates/pm-web/src/routes/pki.rs` | `GET /pki/repo-config` endpoint |
| `crates/pm-web/src/routes/repo_admin.rs` | Admin sync endpoints + `run_manual_sync()` |
| `crates/pm-web/src/routes/enrollment.rs` | Enrollment handler with `repo_config` population |
| `crates/pm-web/src/lib.rs` | `build_repo_router()` for port 80 ServeDir |
| `crates/pm-web/src/main.rs` | Second axum listener on port 80 |
| `crates/pm-worker/src/package_sync_worker.rs` | Background sync worker |
| `crates/pm-worker/src/health_poller.rs` | GPG key health check in health poller |
| `migrations/028_repo_sync_tables.sql` | DB schema for repo sync tracking |
| `frontend/src/pages/RepoManagementPage.tsx` | Repo management UI |
| `frontend/src/api/client.ts` | `repoApi` client methods |
| `docs/gpg-key-rotation.md` | GPG key rotation procedure |

---

## 8. References

- **Agent-Side Architecture:** `linux-patch-api/tasks/self-update-architecture.md`
- **GPG Key Rotation:** `docs/gpg-key-rotation.md`
- **Issue #116:** https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/116
