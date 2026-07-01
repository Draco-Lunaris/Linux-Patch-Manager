# Linux_Patch_Manager — Specification Document

## Document Control

| Field | Value |
|-------|-------|
| Title | Linux_Patch_Manager — Specification Document |
| Version | 0.0.2 |
| Status | Draft |
| Last Updated | 2026-04-23 |
| Related Docs | `REQUIREMENTS.md`, `ARCHITECTURE.md`, `README.md` |

### Revision History

| Version | Date | Summary |
|---------|------|---------|
| 0.0.1 | 2026-04-21 | Initial draft |
| 0.0.2 | 2026-04-23 | Aligned with SDD v0.0.3: portable ASCII diagram, hardware-host encryption at rest, Argon2id / EdDSA / TLS 1.3 called out, Settings page scope expanded (Azure SSO, SMTP, web-UI TLS), IP whitelist enforcement |

---

## Project Overview
**Title:** Linux_Patch_Manager
**Description:** Enterprise-class, secure, web-based management interface for controlling patching and updates on Linux servers and workstations
**Version:** 0.0.3
**Status:** Draft

## Scope

**In Scope:**
- Centralized dashboard for fleet-wide patch status monitoring (5 min health polling, 30 min patch polling, on-demand refresh) with visual alerts for unhealthy/unreachable agents
- Multi-distribution support (Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, Arch)
- Batch patch operations across multiple hosts
- Maintenance window scheduling (per-device, daily/weekly/monthly recurring + one-time) with immediate-apply override
- Compliance reporting and patch status dashboards (compliance, patch history, vulnerability exposure, audit trail — exportable as CSV and PDF, with charts/graphs in PDF output)
- User management with RBAC
- Secure mTLS communication with Linux Patch API agents (TLS 1.3 only)
- Real-time job status via WebSocket relay
- Host registration (manual FQDN/IP + on-demand CIDR auto-discover)
- Static group-based device organization with group-scoped operator access
- Email notifications (optional, disabled by default, runtime-configurable SMTP)
- Azure SSO configuration GUI with "test connection" action (runtime-configurable)
- Web UI TLS certificate strategy selection (self-signed from internal CA or operator-supplied)

**Out of Scope:**
- Configuration management (Ansible/Puppet/Chef territory)
- OS provisioning, imaging, or bootstrapping
- Vulnerability scanning (manager consumes CVE data from agents, does not scan)
- Mobile UI / native apps
- Automated certificate distribution to agents
- Agent installation/management (separate concern)
- Webhook/Slack/other external notification integrations
- Multi-instance clustering / automatic horizontal scaling

## Objectives

**Primary Objective:** Provide a centralized web interface to monitor and control patch operations across a fleet of Linux hosts via the Linux Patch API.

**Key Goals:**
- Fleet-wide visibility into patch status and compliance
- Zero-friction patch deployment via maintenance windows
- Secure-by-design architecture (Rust core, mTLS, MFA, Argon2id, EdDSA JWTs)
- Single-instance simplicity supporting up to 2,500 managed hosts

## Constraints

**Deployment:**
- Single bare metal/VM host running Ubuntu 24.04
- Systemd service management
- Internal network access only (same network as managed agents, no public internet exposure)
- Encryption at rest provided by the hardware host (infrastructure-level); the application does not manage disk encryption

**Technical:**
- Backend: Rust with Axum framework, Tokio async runtime
- Frontend: React + TypeScript SPA (Vite build)
- Database: PostgreSQL 16+ with SQLx for type-safe queries; migrations via `sqlx-cli`
- Real-time: Axum native WebSocket support for agent-to-browser relay
- Single-instance design (manual horizontal scaling by dividing clients between multiple Patch Manager hosts if needed)
- Fleet capacity: ~500 typical, up to 2,500 hosts
- PDF generation: `printpdf` + `plotters` for charts (in-process, no sidecar)

**Security:**
- Combination authentication: local accounts + Azure SSO
- MFA required for all users (TOTP or WebAuthn)
- Azure SSO users may use Azure's built-in MFA
- Password hashing: Argon2id
- JWT access tokens signed with EdDSA / Ed25519 (15-minute TTL), 90-day key rotation with 24-hour overlap
- Refresh tokens: opaque, server-side stored, 1-hour inactivity timeout, rotated on use, revocable
- mTLS for all agent communication (TLS 1.3 only)
- HTTPS for web UI (TLS 1.3 only)
- **IP whitelist enforcement on all connection points** (with `security.trusted_proxies` to optionally honor `X-Forwarded-For` from a configured proxy; empty default = strict mode that uses the socket peer IP and ignores `X-Forwarded-For`; non-empty allowlist + unresolvable peer IP = fail-closed `403 forbidden_ip`) [Issue #3 / `tasks/ip-allowlist-spec.md`]
- Role-based access control:
  - **Admin**: Full access to manage all aspects of Linux Patch Manager
  - **Operator**: Can add/remove clients, manage schedules and patches only for devices in their group memberships
  - Groups are static; devices and operators can belong to multiple groups
  - Ungrouped devices can be managed by any operator or admin

## Architecture Overview

Management plane web application communicating with Linux Patch API agents on each managed host.

```
+-----------------------------+
|    Linux Patch Manager      |  <- Web UI (this project)
|     (Management Plane)      |     Rust/Axum + React/TS
|     PostgreSQL + WebSocket  |
+--------------+--------------+
               |
               |  mTLS / REST + WSS (TLS 1.3, port 12443)
       +-------+-------+
       v       v       v
   +------+ +------+ +------+
   | Host | | Host | | Host |  <- Linux Patch API agents
   |  A   | |  B   | |  C   |     (up to 2,500)
   +------+ +------+ +------+
```

## API Integration

**Upstream Dependency:** [Linux Patch API](https://gitea.moon-dragon.us/echo/linux_patch_api)
- All managed device access uses the Linux Patch API
- mTLS certificate-based authentication to agents (TLS 1.3 only)
- Hybrid sync/async operation model (sync for queries, async jobs for patch operations)
- WebSocket streaming for real-time job status from agents
- Base path: `/api/v1/`, Port: 12443, TLS 1.3 only

## Host Self-Enrollment

**1. Database Architecture**
- **Table:** A new `enrollment_requests` table to isolate unverified data from the active `hosts` table.
- **Schema Fields:** `id`, `machine_id` (from `/etc/machine-id`), `fqdn`, `ip_address`, `os_details`, `polling_token` (hashed), `created_at`, `expires_at`.

**2. REST API Contract (Client-Facing)**
- `POST /api/v1/enroll`: 
  - **Payload:** `{ machine_id, fqdn, ip_address, os_details }`
  - **Response:** Returns a temporary `polling_token`.
- `GET /api/v1/enroll/status/{token}`: 
  - **Pending:** HTTP 202.
  - **Approved:** HTTP 200 containing the PKI bundle (see [INTERFACE_CONTRACT.md](INTERFACE_CONTRACT.md) §2.3 for canonical structure: `ca_crt`, `ca_chain`, `server_crt`, `server_key`, `crl_pem`, `repo_config`).
  - **Denied/Expired:** HTTP 404 or 403.

**3. REST API Contract (Admin-Facing)**
- `GET /api/v1/admin/enrollments`: Lists the pending queue.
- `POST /api/v1/admin/enrollments/{id}/approve`: Generates client PKI, moves record to `hosts` table.
- `DELETE /api/v1/admin/enrollments/{id}/deny`: Purges the request.

**4. Security & Lifecycle Guardrails**
- **Rate Limiting:** Strict IP-based rate limits on the initial `POST` endpoint to prevent DoS.
- **Auto-Purge:** A background task to delete unapproved pending requests older than 24 hours.
- **PKI Handoff:** The manager (`pm-ca`) acts as the Certificate Authority and generates the server auth certificate to maintain parity with the existing trusted deployment model.

**5. User Interface (UI)**
- **Visibility:** Pending hosts integrated into the main Hosts view.
- **Indicators:** Queue counter/visual badge on the interface, with pending rows highlighted.
- **Filtering:** Dedicated filter to toggle the enrollment queue.
- **Conflict Resolution:** Interactive "merge/overwrite" prompt if approval detects an `fqdn` or `ip_address` collision with the active `hosts` table.

## Agent Self-Update (Manager Pull Model)

The Manager hosts a GPG-signed package repository for agent self-updates. The agent receives repo configuration (GPG public key + distro-specific sources config) during enrollment or via fallback `GET /api/v1/pki/repo-config`.

- **Repo server:** Port 80 (plain HTTP — GPG metadata signatures provide integrity)
- **Repo paths:** `/apt/`, `/dnf/`, `/apk/`, `/pacman/` on the manager host
- **GPG key:** Per-manager, stored alongside CA in `/etc/patch-manager/ca/`
- **Manager triggers:** Standard `PUT /api/v1/packages/{name}` on the agent (optional `target_version`)
- **Agent execution:** Native package manager (apt/dnf/apk/pacman) with standard maintainer scripts
- **Delayed restart:** Maintainer scripts schedule a 300s delayed service restart after package replacement
- **Fallback:** `GET /api/v1/pki/repo-config` for agents enrolled before repo provisioning

See [INTERFACE_CONTRACT.md](INTERFACE_CONTRACT.md) §4 for the full self-update protocol.

## Certificate Management

- Internal CA managed by Patch Manager, installed on the same host
- Patch Manager issues and renews client certificates for mTLS communication
- Certificate distribution to managed target clients is manual (server administrators responsible)
- Patch Manager has no direct permissions on managed clients
- Web UI TLS certificate: self-signed from the internal CA by default; operator may supply an external certificate (e.g., infrastructure wildcard) via configuration

## User Interface

### Pages/Views

1. **Dashboard** — Fleet overview: patch compliance %, host health summary, pending patches, upcoming maintenance windows. Includes root CA certificate download icon.
2. **Hosts** — List of all managed hosts with filtering by group, health status, OS, patch status
3. **Host Detail** — Single host view: system info, installed packages, available patches, job history, maintenance window config. Includes host-specific mTLS certificate download icon.
4. **Patch Deployment** — Select hosts → review available patches → deploy (queue for window or apply now)
5. **Jobs** — Real-time job monitoring with WebSocket status updates
6. **Maintenance Windows** — Create/edit recurring and one-time windows per device
7. **Groups** — Manage static groups, assign hosts and operators
8. **Reports** — Generate and export compliance, patch history, vulnerability, audit reports (CSV and PDF with charts)
9. **Users** — Manage local accounts, MFA setup, group assignments
10. **Certificates** — View/manage internal CA, issue/renew client certs
11. **Settings** — System configuration including:
    - Azure SSO setup (tenant ID, client ID/secret, redirect URI, scopes) with "Test Connection" action
    - SMTP configuration (host, port, auth, TLS mode, from-address) with "Send Test Email" action
    - Polling intervals (health, patch data)
    - Web UI TLS certificate strategy (internal CA vs. operator-supplied)
    - IP whitelist management

### Navigation

All authenticated pages share a persistent sidebar navigation layout:

**Layout Structure:**
- **AppBar** (top): Page title, user avatar with role display, dropdown menu (profile info, sign out)
- **Sidebar** (left, 240px): Grouped navigation menu with icons, version label at bottom
- **Main content** (center): Routed page content with padding and scroll

**Menu Groups:**

| Group | Items | RBAC |
|-------|-------|------|
| Overview | Dashboard | All users |
| Fleet | Hosts, Groups, Deploy | All users |
| Operations | Jobs, Maintenance | All users |
| Administration | Users, Certificates, Settings | Admin only |
| Administration | Reports | All users |

**Behavior:**
- Active page highlighted with primary color background on sidebar item
- Admin-only items hidden from operators (entire group hidden if all items are admin-only)
- Mobile responsive: collapsible drawer with hamburger toggle on small screens, permanent drawer on desktop
- User menu: avatar shows first letter of display name, dropdown shows display name + role, sign out action clears tokens and navigates to login via React Router
- Login page renders without sidebar (standalone layout)

**Theme:** Dark mode (MUI dark palette). Primary: #42A5F5, Secondary: #26C6DA.

### Frontend Error Handling

**Login Errors:**
- Network errors (server unreachable): "Unable to connect to the server. Please check your network connection and try again."
- Rate limiting (HTTP 429): "Too many login attempts. Please wait a moment and try again."
- Invalid credentials (HTTP 401): "Invalid username or password."
- Account disabled: "This account has been disabled. Contact your administrator."
- MFA required: Show TOTP input field with info alert
- Server errors (5xx): "A server error occurred. Please try again later."
- All errors displayed as dismissible MUI Alert components (no blank error pages)

**Auth Token Expiry:**
- 401 responses trigger automatic token refresh using stored refresh token
- If refresh fails, auth state is cleared via Zustand store (no `window.location` hard redirects)
- React Router `<RequireAuth>` guard redirects unauthenticated users to `/login`

## Error Handling

**Agent Communication Failures:**
- Mark host as unhealthy in dashboard
- Retry with exponential backoff (3 retries, max 30 minutes between retries)
- Continue processing other hosts without blocking

**Patch Job Failures:**
- Auto-retry failed patch jobs once if still within the maintenance window
- If retry fails or window has closed, surface failure prominently to operators

**Batch Operations with Partial Failures:**
- Auto-retry failed hosts once
- If retry fails, report which hosts failed and let operator decide next steps
- Successful hosts proceed normally regardless of failures

## Assumptions

- Patch Manager host has network connectivity to all managed agents
- Linux Patch API agent is installed and running on each managed host
- Server administrators manually distribute mTLS and root certificates to managed clients
- PostgreSQL 16+ is available on the Patch Manager host
- Hardware host provides full-disk encryption (no OS-level disk encryption managed by the application)

## Dependencies

- Linux Patch API (upstream agent on each managed host)
- PostgreSQL 16+
- Internal CA for mTLS certificates
- Azure AD (optional, for SSO)
- SMTP relay (optional, runtime-configurable, for email notifications)

## Audit Logging

**Captured Events:**
- All user login/logout events (success and failure)
- All patch operations (who triggered, which hosts, what patches, queue vs. immediate)
- All host registration/removal events
- All group membership changes (hosts and users)
- All certificate operations (issue, renew, download, revoke)
- All maintenance window changes
- All configuration changes (including Azure SSO, SMTP, IP whitelist, TLS cert strategy)

**Integrity:** Hash-chained rows (tamper-evident). Periodic and on-demand verification.

**Retention:** 6 months

---

## Appendix: App-Level Secret Encryption (Issue #6, May 2026)

In addition to the hardware-level full-disk encryption described above, issue #6 (PR [TBD]) added **application-level AES-256-GCM encryption** for three specific sensitive fields that DB exfiltration would otherwise expose:

| Field | Table | Encryption key |
|-------|-------|----------------|
| `client_secret` | `oidc_config` | `/etc/patch-manager/keys/secret-encryption.key` |
| `smtp_password` | `system_config` (key-value row) | same key |
| `totp_secret` | `users` | same key |

**Why app-level on top of hardware-level?** Hardware-level encryption protects against disk theft; app-level encryption protects against DB exfiltration (SQL injection, backup theft, insider threat) where the attacker already has the running process's privileges. The two are complementary.

**Blast-radius isolation:** A separate per-install key is used for app secrets (`secret-encryption.key`), distinct from the health-check key (`health-check.key`). If the health-check key is ever compromised, app secrets remain protected.

**API surface:** No change. The `MASKED` placeholder behavior in API responses is preserved on top of the new DB encryption — defense in depth.

**Backup:** Both key files must be included in `/etc/patch-manager` backups. Without the key file, encrypted data is unrecoverable. See [docs/runbooks/key-management.md](docs/runbooks/key-management.md) for the full procedure.

**Key rotation:** Not yet supported (follow-up issue). If a key is compromised, generate a new key and re-provision affected secrets.
