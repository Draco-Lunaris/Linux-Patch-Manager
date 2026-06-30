# Manager-Agent Interface Contract

**Version:** 1.0.0
**Status:** Canonical
**Location:** Linux Patch Manager repo (canonical source)
**Agent reference:** The Agent repo's AGENTS.md references this document as the authoritative contract.

This document defines the interface contract between the Linux Patch Manager (management plane) and the Linux Patch API (agent on managed hosts). Both repos must conform to this contract. Changes require updating this document first, then each repo's implementation.

---

## 1. Agent API Endpoints Consumed by Manager

All agent endpoints use base path `/api/v1/`, port 12443, TLS 1.3, mTLS authentication.

### 1.1 Package Management

| Method | Path | Sync/Async | Purpose |
|--------|------|------------|---------|
| GET | `/packages` | Sync | List installed packages (filters: name, status, upgradable, sort, order) |
| GET | `/packages/{name}` | Sync | Get specific package details |
| POST | `/packages` | Async (202) | Install package(s) with optional version pinning |
| PUT | `/packages/{name}` | Async (202) | Update specific package |
| DELETE | `/packages/{name}` | Async (202) | Remove package |

### 1.2 Patch Management

| Method | Path | Sync/Async | Purpose |
|--------|------|------------|---------|
| GET | `/patches` | Sync | List available updates/patches |
| POST | `/patches/apply` | Async (202) | Apply all or specific patches (optional reboot) |

### 1.3 System Endpoints

| Method | Path | Sync/Async | Purpose |
|--------|------|------------|---------|
| GET | `/system/info` | Sync | OS version, kernel, architecture, last update, pending reboot |
| GET | `/health` | Sync | Agent health (status, uptime, version, CRL status, GPG key status) |
| POST | `/system/reboot` | Async (202) | Reboot host (optional delay, force flag) |
| POST | `/system/update` | Async (202) | Trigger agent self-update from manager-hosted repo |
| GET | `/system/update/status` | Sync | Get most recent self-update result |

### 1.4 PKI Endpoints

| Method | Path | Sync/Async | Purpose |
|--------|------|------------|---------|
| GET | `/pki/repo-config` | Sync | Fallback fetch of repo config (for agents enrolled before repo provisioning) |

### 1.5 Job Management

| Method | Path | Sync/Async | Purpose |
|--------|------|------------|---------|
| GET | `/jobs` | Sync | List all jobs (optional status filter, limit) |
| GET | `/jobs/{id}` | Sync | Get specific job status (progress, logs) |
| POST | `/jobs/{id}/rollback` | Async (202) | Rollback a completed/failed job (exclusive mode) |
| WS | `/ws/jobs` | WebSocket | Real-time job status streaming (subscribe by job_id or all) |

### 1.6 Standard Response Envelope

All agent responses use:
```json
{
  "success": boolean,
  "request_id": "UUID",
  "timestamp": "ISO 8601",
  "data": object | null,
  "error": { "code": string, "message": string, "details": object, "retryable": boolean } | null
}
```

---

## 2. Enrollment Protocol

### 2.1 Phase 1: Registration (Agent → Manager)

**Endpoint:** `POST /api/v1/enroll` (unauthenticated)

**Request payload:**
```json
{
  "machine_id": "string (from /etc/machine-id)",
  "fqdn": "string",
  "ip_address": "string (non-loopback IPv4)",
  "os_details": {
    "distro": "string",
    "version": "string",
    "id_like": "string",
    "codename": "string",
    "kernel": "string"
  }
}
```

**Response (202):**
```json
{
  "polling_token": "string"
}
```

**Rate limit:** 1 request/minute per IP (HTTP 429 on violation)

### 2.2 Phase 2: Polling (Agent → Manager)

**Endpoint:** `GET /api/v1/enroll/status/{token}` (unauthenticated)

| Status | HTTP | Response |
|--------|------|----------|
| Pending | 202 | Empty body |
| Approved | 200 | PkiBundle (see §2.3) |
| Denied | 403 | Error with `ENROLLMENT_DENIED` |
| Expired/Purged | 404 | Error with `ENROLLMENT_EXPIRED` |

**Polling constraints:**
- Default interval: 60 seconds (configurable)
- Hard timeout: 24 hours (1440 attempts max)
- Polling token persisted to agent config.yaml for resume after restart
- Token is single-retrieval: bundle is atomically removed from manager cache on fetch
- Bundle TTL: 10 minutes after approval

### 2.3 PkiBundle Structure (Approved Response)

This is the canonical structure. Both repos' code already matches this.

```json
{
  "ca_crt": "PEM string — leaf-most CA certificate",
  "ca_chain": "PEM string — full CA chain (intermediates + root, concatenated). For root mode, same as ca_crt",
  "server_crt": "PEM string — agent server certificate",
  "server_key": "PEM string — agent server private key (PKCS#8)",
  "crl_pem": "PEM string — CRL signed by CA. Empty string if CRL generation failed (agent falls back to degraded mode)",
  "repo_config": null or {
    "gpg_public_key": "ASCII-armored GPG public key",
    "sources_config": "Distro-specific repo config text (apt sources.list line, dnf .repo file, apk URL, pacman include)",
    "distro_id": "Distro identifier WITHOUT version (e.g., \"ubuntu\", \"debian\", \"fedora\", \"alpine\", \"arch\")",
    "keyring_path": "Filesystem path for GPG key (e.g., \"/etc/apt/keyrings/lpa-repo.gpg\")"
  }
}
```
**⚠ distro_id format:** The Agent expects `distro_id` WITHOUT version (e.g., `"ubuntu"`, not `"ubuntu-24.04"`). The Manager's `RepoConfig` struct comments currently show version-suffixed examples — this is a **known mismatch**. The contract specifies: **no version suffix**. Manager must strip the version when building `repo_config`.

**Current Manager gap:** Enrollment approval handler (`crates/pm-web/src/routes/enrollment.rs` line 322) sets `repo_config: None`. The struct and types exist, but the handler does not populate `repo_config` during approval. This must be implemented.

### 2.4 Phase 3: Admin-Facing Endpoints (Manager Internal)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/admin/enrollments` | Admin | List pending enrollment requests |
| POST | `/api/v1/admin/enrollments/{id}/approve` | Admin | Approve, generate PKI, migrate to hosts table |
| DELETE | `/api/v1/admin/enrollments/{id}/deny` | Admin | Deny and purge request |

### 2.5 Enrollment Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `ENROLLMENT_DENIED` | 403 | Admin rejected enrollment request |
| `ENROLLMENT_EXPIRED` | 404 | Polling token expired or purged |
| `ENROLLMENT_TIMEOUT` | — | 24-hour polling limit exceeded (agent-side) |
| `ENROLLMENT_RATE_LIMITED` | 429 | Rate limit exceeded (1/minute per IP) |
| `PKI_PROVISION_FAILED` | — | Certificate write or PEM validation failed (agent-side) |

---

## 3. Certificate File Naming Convention

Per actual code (`src/enroll/provision.rs` in the Agent), the canonical cert file paths are:

| File | Path | Permissions | Format |
|------|------|------------|--------|
| CA certificate | `/etc/linux_patch_api/certs/ca.pem` | 0644 | PEM (X.509) |
| Server certificate | `/etc/linux_patch_api/certs/server.pem` | 0644 | PEM (X.509) |
| Server private key | `/etc/linux_patch_api/certs/server.key.pem` | 0600 | PEM (PKCS#8) |
| CRL | `/etc/linux_patch_api/certs/crl.pem` | 0644 | PEM (CRL) |

**Note:** The server key file is `server.key.pem` (with `.pem` suffix), NOT `server.key`. This matches the Agent's `DEPLOYMENT_GUIDE.md`, `README.md`, `configs/CA_SETUP.md`, and `src/enroll/provision.rs` code. The Agent's `SPEC.md` and `ARCHITECTURE.md` say `server.key` — those docs are wrong and must be corrected.

The PkiBundle JSON fields use logical names (`ca_crt`, `server_crt`, `server_key`) — these are NOT file names. The agent writes them to the paths above.

---

## 4. Self-Update Protocol

### 4.1 Manager-Hosted Package Repository

- **Port:** 80 (plain HTTP)
- **Scheme:** HTTP (no TLS — GPG signatures provide integrity)
- **Base URL:** `http://<manager-host>/`
- **Repo paths:** `/apt/`, `/dnf/`, `/apk/`, `/pacman/`
- **Integrity:** All packages and repo metadata signed by the Manager's GPG key
- **GPG key:** Per-manager, stored alongside CA in `/etc/patch-manager/ca/`
- **GPG key delivery:** Via enrollment bundle `repo_config.gpg_public_key` or fallback `GET /api/v1/pki/repo-config`

### 4.2 Manager-Initiated Self-Update

**Endpoint:** `POST /api/v1/system/update` (Manager calls Agent)

**Request body:**
```json
{
  "target_version": "string | null",
  "restart": true,
  "restart_delay_seconds": 5
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target_version` | string \| null | No | null | Specific package version to install. null = latest available |
| `restart` | boolean | No | true | Restart agent service after successful upgrade |
| `restart_delay_seconds` | integer | No | 5 | Delay before restart (clamped to max 300) |

**Response (202):**
```json
{
  "success": true,
  "request_id": "UUID",
  "timestamp": "ISO 8601",
  "data": {
    "job_id": "UUID",
    "status": "pending",
    "operation": "self_update",
    "target_version": "1.5.6-1",
    "restart": true,
    "restart_delay_seconds": 5,
    "source": "manager_repo"
  }
}
```

**Error codes:**
| Code | HTTP | Description |
|------|------|-------------|
| `INVALID_VERSION` | 400 | Version format invalid or not in repo |
| `UPDATE_IN_PROGRESS` | 409 | A self-update is already running |
| `UPDATE_SERVICE_START_ERROR` | 500 | Self-update systemd unit failed to start |

### 4.3 Self-Update Status Query

**Endpoint:** `GET /api/v1/system/update/status` (Manager calls Agent)

**Response (200):**
```json
{
  "success": true,
  "request_id": "UUID",
  "timestamp": "ISO 8601",
  "data": {
    "previous_version": "1.4.3-1",
    "new_version": "1.5.6-1",
    "changed": true,
    "status": "success",
    "error": null,
    "at": "2026-06-27T14:03:12Z"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `previous_version` | string \| null | Agent version before update (null if first install) |
| `new_version` | string \| null | Agent version after update (null if failed before install) |
| `changed` | boolean | true if package version changed |
| `status` | string | `success`, `rollback`, `failed`, `health_check_timeout`, `pending` |
| `error` | string \| null | Error message if status != success |
| `at` | ISO 8601 \| null | Timestamp when self-update completed |

**Response (404):** `NO_SELF_UPDATE_RECORD` — no self-update has been performed.

### 4.4 Fallback Repo Config Fetch

**Endpoint:** `GET /api/v1/pki/repo-config` (Agent calls Manager, mTLS authenticated)

**Response (200):**
```json
{
  "success": true,
  "request_id": "UUID",
  "timestamp": "ISO 8601",
  "data": {
    "repo_config": {
      "gpg_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
      "sources_config": "deb [signed-by=/etc/apt/keyrings/lpa-repo.gpg] http://manager.moon-dragon.us/apt noble main",
      "distro_id": "ubuntu",
      "keyring_path": "/etc/apt/keyrings/lpa-repo.gpg",
      "repo_base_url": "http://manager.moon-dragon.us"
    }
  }
}
```

**Note:** `sources_config` uses `http://` (port 80), NOT `https://`.

**Error (404):** `PKI_REPO_CONFIG_UNAVAILABLE` — Manager has not provisioned repo config for this host's distro.

### 4.5 Agent Execution Model

- Agent writes request to `/var/lib/linux_patch_api/self-update.request`
- Triggers `self-update.sh` via detached systemd unit (`linux-patch-api-update.service`)
- The update unit has its own cgroup — no `Requires=`, `BindsTo=`, `PartOf=` coupling to the agent service
- This allows the update to survive the agent being killed by dpkg prerm
- After install: 60-second health check; auto-rollback to `previous_version` on failure
- Marker file `/var/lib/linux_patch_api/last_self_update.json` is source of truth (not in-memory job state)

---

## 5. Health Reporting Contract

### 5.1 Agent Health Endpoint

**Endpoint:** `GET /api/v1/health` (Manager calls Agent)

**Response (200 — Healthy):**
```json
{
  "success": true,
  "request_id": "UUID",
  "timestamp": "ISO 8601",
  "data": {
    "status": "healthy",
    "uptime_seconds": 12345,
    "version": "1.5.6-1",
    "crl_status": "valid",
    "crl_age_seconds": 3600,
    "crl_next_update": "2026-07-01T00:00:00Z",
    "gpg_key_status": "valid",
    "gpg_key_expires_at": "2028-06-27T00:00:00Z"
  }
}
```

### 5.2 CRL Status Values

| Value | Meaning | Manager Health Impact |
|-------|---------|---------------------|
| `valid` | CRL present and not expired | Natural status (no override) |
| `expired` | CRL present but past next_update | `degraded` if natural status is `healthy` |
| `missing` | CRL file not found | `degraded` if host registered > 24h ago; natural if ≤ 24h |
| `invalid` | CRL fails to parse or signature verification fails | `unreachable` (security event) |
| `degraded` | CRL loaded but verification in degraded mode | Natural status |
| `null` | Agent doesn't report CRL (older agent) | Natural status |

### 5.3 GPG Key Status Values

| Value | Meaning |
|-------|---------|
| `valid` | GPG key present and not expired |
| `expired` | GPG key past expiration date |
| `missing` | GPG key not found (agent enrolled before repo feature) |
| `revoked` | GPG key has been revoked |

### 5.4 Manager Liveness Endpoint (Not Agent)

The Manager has its own liveness endpoint at `GET /status/health` (unauthenticated). This is distinct from the Agent's `GET /api/v1/health`. Do not confuse the two.

---

## 6. Manager Admin Endpoints for Enrollment (Internal to Manager)

These are the Manager's own API for admin enrollment management. Documented here because they produce the PkiBundle that the Agent consumes.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/admin/enrollments` | Admin JWT | List pending enrollment requests |
| POST | `/api/v1/admin/enrollments/{id}/approve` | Admin JWT | Approve → generate PKI → migrate to hosts |
| DELETE | `/api/v1/admin/enrollments/{id}/deny` | Admin JWT | Deny and purge request |

---

## 7. Known Gaps Requiring Implementation

These gaps exist in the current codebase as of 2026-06-29 and must be resolved for full contract compliance:

| Gap | Side | Description | Priority |
|-----|------|-------------|----------|
| G-01 | Manager | Enrollment handler does not populate `repo_config` in PkiBundle (line 322: `repo_config: None`) | P0 |
| G-02 | Manager | `GET /api/v1/pki/repo-config` endpoint may not be fully implemented (fallback path) | P1 |
| G-03 | Manager | `RepoConfig.distro_id` comments show version-suffixed format; code must strip version to match agent expectation | P1 |
| G-04 | Manager | Package repo directory infrastructure (`/var/www/lpa-repo/`) not set up | P1 |
| G-05 | Manager | GPG key not generated on manager host | P1 |
| G-06 | Manager | ServeDir for `/apt/`, `/dnf/`, `/apk/`, `/pacman/` repo paths not configured in router | P1 |
| G-07 | Manager | Manager SPEC/ARCHITECTURE/REQUIREMENTS do not mention self-update or package repo feature | P0 |
| G-08 | Manager | Manager ARCHITECTURE §12.1 missing 3 self-update endpoints from integration table | P0 |
| G-09 | Agent | Agent SPEC.md says `server.key` but code uses `server.key.pem` — doc must be corrected | P1 |
| G-10 | Agent | Agent ARCHITECTURE.md says `server.key` but code uses `server.key.pem` — doc must be corrected | P1 |
| G-11 | Both | API repo version numbers are inconsistent (SPEC=2.0.0, README=1.0.0, health example=0.0.1) | P1 |
| G-12 | Manager | Manager README port confusion (config says 443, access instructions say 8080) | P2 |
| G-13 | Manager | Manager SPEC (0.0.2) behind SDD (0.0.3) — needs version bump and content sync | P2 |

---

## 8. Change Management

When either repo changes an interface element:
1. Update this document first
2. Update the implementing repo's code
3. Update the consuming repo's code if needed
4. Both repos' AGENTS.md files reference this document as the authoritative contract

---

*End of contract — v1.0.0 — 2026-06-29*
