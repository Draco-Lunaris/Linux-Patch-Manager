# Linux_Patch_Manager — Requirements Document

## Document Control

| Field | Value |
|-------|-------|
| Title | Linux_Patch_Manager — Requirements Document |
| Version | 1.1.19 |
| Status | Current |
| Last Updated | 2026-06-12 |
| Related Docs | `SPEC.md`, `ARCHITECTURE.md`, `README.md` |

### Revision History

| Version | Date | Summary |
|---------|------|---------|
| 0.0.1 | 2026-04-21 | Initial draft |
| 0.0.2 | 2026-04-23 | Aligned with SDD v0.0.3: hardware-host encryption at rest (no OS-level LUKS), Argon2id, EdDSA JWTs, Azure SSO configuration GUI, web-UI TLS cert strategy, SMTP runtime configurability |
| 1.1.19 | 2026-06-12 | Updated version to match release; added port 12443 inbound requirement; updated all Gitea references to GitHub |

---

## Project Overview
**Title:** Linux_Patch_Manager
**Description:** Enterprise-class, secure, web-based management interface for controlling patching and updates on Linux servers and workstations
**Version:** 1.1.19
**Status:** Current

## Functional Requirements

### FR-01: Host Management

- Manual host registration by FQDN or IP address (FQDN resolved to IP at add time)
- On-demand auto-discovery targeting a CIDR subnet range (scans for Linux Patch API agents on port 12443)
- Host metadata tracked: hostname, IP, OS, kernel, agent version, last seen, health status
- Static group-based organization with many-to-many relationships (hosts can belong to multiple groups)
- Ungrouped hosts can be managed by any operator or admin
- Host removal with audit logging

### FR-02: Patch Monitoring

- Scheduled background polling: 5-minute intervals for health checks, 30-minute intervals for patch data
- On-demand refresh triggered by operator/admin from the UI
- Visual dashboard alerts for unhealthy or unreachable agents (red/yellow status indicators)
- CVE severity, patch priority, and reboot requirement display per host

### FR-03: Patch Deployment

- Patches queue for the next available maintenance window by default
- Immediate-apply override option for urgent patches
- No approval gate required — operator/admin triggers deployment directly
- Auto-retry failed patch jobs once if still within the maintenance window, then surface failure prominently
- Batch operations across multiple hosts with partial failure handling (auto-retry once, then report failures)
- Rollback support via upstream Linux Patch API rollback endpoint

### FR-04: Scheduling

- Maintenance windows are per-device (not per-group)
- Recurring schedules: daily, weekly, or monthly
- One-time maintenance windows
- Patch operations execute automatically when a maintenance window opens

### FR-05: Reporting

- Compliance report: percentage of hosts fully patched, by group or fleet-wide
- Patch history: log of all patch operations per host or per group
- Vulnerability exposure: hosts with known CVEs pending patches
- Audit trail: who did what, when (user actions, patch operations)
- Charts and graphs required in PDF exports (compliance trends, patch-status distributions)
- Export formats: CSV and PDF

### FR-06: User Management

- **Admin role**: Full access to manage all aspects of Linux Patch Manager
- **Operator role**: Can add/remove clients, manage schedules and patches only for devices in their group memberships
- Operators can belong to multiple groups
- Local accounts with MFA required (TOTP or WebAuthn)
- Azure SSO integration (optional, with Azure's built-in MFA)
- Group membership management for users and hosts

### FR-07: System Configuration

- Azure SSO configuration GUI in the Settings page (tenant ID, client ID, client secret, redirect URI, scopes)
- "Test connection" action in the Azure SSO config GUI that performs a round-trip against Azure AD and reports success/failure without enabling SSO
- SMTP configuration GUI (host, port, auth mode, username/password, TLS mode, from-address); disabled by default
- "Send test email" action in the SMTP config GUI
- Polling-interval tuning (health and patch pollers)
- Web UI TLS certificate strategy selection: self-signed from the internal CA (default) or operator-supplied certificate/key (e.g., existing infrastructure wildcard)

## Non-Functional Requirements

### NFR-01: Security

- Combination authentication: local accounts + Azure SSO
- MFA required for all users (TOTP or WebAuthn; Azure MFA for SSO users)
- Password hashing: **Argon2id**
- Session management: short-lived JWT access tokens (15 min, signed with **EdDSA / Ed25519**) + server-side opaque refresh tokens (1-hour inactivity timeout, rotated on use, revocable)
- JWT signing key rotation every 90 days with a 24-hour overlap window for in-flight tokens
- mTLS for all agent communication (certificate-based, **TLS 1.3 only**)
- HTTPS enforced for web UI (TLS 1.3 only)
- Internal CA managed by Patch Manager for mTLS certificate issuance and renewal
- Certificate distribution to managed clients is manual (server administrators responsible)
- RBAC with group-scoped access control
- IP whitelist enforcement on all connection points

### NFR-02: Performance

- Support 500 typical managed hosts, up to 2,500
- Dashboard load time under 5 seconds for full fleet view
- Background polling must not degrade UI responsiveness
- Concurrent batch operations (e.g., patch 500 hosts simultaneously) must not overwhelm the system
- Login latency budget: 250–500 ms on target hardware (Intel Xeon, 4 cores, 16 GB RAM); Argon2id parameters calibrated to land in this window
- CIDR auto-discovery of a `/22` network (~1,024 hosts) across sites completes within 10 seconds wall-clock

### NFR-03: Scalability

- Single-instance design on bare metal/VM (Ubuntu 24.04)
- Manual horizontal scaling by dividing clients between multiple Patch Manager hosts if needed
- No automatic clustering or load balancing required

### NFR-04: Reliability

- Agent communication failures: retry with exponential backoff (3 retries, max 30 minutes between retries)
- Patch job failures: auto-retry once within maintenance window, then surface to operators
- Batch partial failures: auto-retry once, then report remaining failures to operator
- Continue processing healthy hosts regardless of individual host failures

### NFR-05: Usability

- 11-page web UI (React + TypeScript SPA)
- Responsive design for desktop/laptop screens
- Dark mode support
- Certificate download links integrated into dashboard (root CA) and host detail (host-specific mTLS)
- Long-running scans (CIDR discovery, full-fleet operations) must display progress and offer a cancel action

## Interface Requirements

### IR-01: Web Interface

- React + TypeScript SPA served by Axum backend
- Real-time job status via WebSocket relay (agent WebSocket → Patch Manager → browser)
- RESTful API backend for all UI operations
- Certificate download endpoints for root CA and host-specific mTLS certs
- Unauthenticated liveness endpoint at `/status/health` (minimal: process up, DB reachable, worker heartbeat fresh)
- Authenticated fleet-aggregate endpoint at `/api/v1/status/fleet` (counts of healthy / degraded / unreachable agents)

### IR-02: Linux Patch API Integration

- All managed device communication via Linux Patch API (upstream agent)
- mTLS client certificate authentication to each agent
- Base path: `/api/v1/`, Port: 12443, TLS 1.3 only
- Sync operations: GET endpoints (packages, patches, system info, health)
- Async operations: POST/PUT/DELETE endpoints (install, update, remove, patch apply, reboot)
- Job status tracking via `GET /api/v1/jobs/{id}` and WebSocket `/api/v1/ws/jobs`
- Rollback via `POST /api/v1/jobs/{id}/rollback`

## Data Requirements

- **Database:** PostgreSQL 16+
- **Operational data retention:** 30 days (host patch history, job history, health history)
- **Audit log retention:** 6 months
- **Data storage:** All data on Patch Manager host

## Compliance Requirements

### HIPAA (Health Insurance Portability and Accountability Act)

- **Audit Controls (§164.312(b)):** Comprehensive audit logging of all system activity (hash-chained rows for integrity)
- **Access Controls (§164.312(a)(1)):** RBAC with group-scoped access, unique user identification, MFA enforcement
- **Integrity Controls (§164.312(c)(1)):** Audit log integrity protection via hash chaining
- **Transmission Security (§164.312(e)(1)):** mTLS for all agent communication, HTTPS for web UI, TLS 1.3 minimum
- **Encryption at Rest:** Provided by the underlying hardware host (infrastructure-level full-disk encryption). The application does not manage disk encryption.
- **Automatic Logoff (§164.312(a)(2)(iii)):** 1-hour inactivity session timeout

### PCI-DSS (Payment Card Industry Data Security Standard)

- **Requirement 3:** Protect stored data — encryption at rest provided by the hardware host
- **Requirement 4:** Encrypt transmission — mTLS (TLS 1.3) for agent communication, HTTPS (TLS 1.3) for web UI
- **Requirement 6:** Vulnerability management — patch management is the core function; system tracks and enforces timely patching
- **Requirement 7:** Restrict access to need-to-know — RBAC with group-scoped operator access
- **Requirement 8:** Identify and authenticate users — MFA required, unique IDs, session timeouts
- **Requirement 10:** Track and monitor all access — comprehensive audit logging with 6-month retention

## Audit Logging

**Captured Events:**
- All user login/logout events (success and failure)
- All patch operations (who triggered, which hosts, what patches, queue vs. immediate)
- All host registration/removal events
- All group membership changes (hosts and users)
- All certificate operations (issue, renew, download, revoke)
- All maintenance window changes
- All configuration changes (including Azure SSO and SMTP configuration)

**Integrity:** Tamper-evident via hash-chained rows (`prev_hash`, `row_hash`). Periodic and on-demand integrity verification.

**Retention:** 6 months

## Constraints

- Single bare metal/VM host running Ubuntu 24.04
- Systemd service management
- Internal network only (no public internet exposure)
- Rust/Axum backend, React/TypeScript frontend, PostgreSQL 16+ database
- No direct permissions on managed clients
- Certificate distribution to clients is manual
- Encryption at rest is provided by the hardware host; the application does not configure or manage disk encryption
