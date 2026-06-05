# Linux_Patch_Manager — Software Design Document (SDD)

## Document Control

| Field | Value |
|-------|-------|
| Title | Linux_Patch_Manager — Software Design Document |
| Version | 0.0.3 |
| Status | Draft |
| Standard | Aligned with IEEE 1016-2009 |
| Owner | Draco Lunaris |
| Last Updated | 2026-04-23 |
| Related Docs | `SPEC.md`, `REQUIREMENTS.md`, `README.md` |

### Revision History

| Version | Date | Author | Summary |
|---------|------|--------|---------|
| 0.0.1 | 2026-04-23 | Initial | First draft of architecture document |
| 0.0.2 | 2026-04-23 | Echo | SDD review pass: IEEE 1016 alignment, ASCII diagram fixes, added stakeholders, rationale, error handling, rollback flow, config/secrets, migrations, backup/DR, observability, glossary, and open issues sections |
| 0.0.3 | 2026-04-23 | Echo | Closed OI-01 through OI-06 with concrete decisions; encryption at rest moved to hardware-host (no OS-level LUKS); committed Argon2id parameters, EdDSA JWT signing, CIDR scan tuning, PDF stack (`printpdf`+`plotters`), health-endpoint split; added AD-15 (web UI TLS cert strategy) and AD-16 (Azure SSO / SMTP config GUI); added IP whitelist enforcement |

---

## 1. Introduction

### 1.1 Purpose

This Software Design Document (SDD) describes the architecture and detailed design of the **Linux_Patch_Manager**, an enterprise-class, secure, web-based management interface used to control patching and updates on a fleet of Linux servers and workstations. It translates the requirements in `REQUIREMENTS.md` and the product scope in `SPEC.md` into a concrete technical design that implementers can build from and reviewers can evaluate against.

### 1.2 Scope

The design covers the management plane only: the web server, background worker, PostgreSQL database, internal Certificate Authority (CA), and the React SPA. Managed hosts run the upstream **Linux Patch API** agent, which is a separate project (`linux_patch_api`) and is treated here as an external dependency.

### 1.3 Intended Audience

- Software engineers implementing the system
- Security and compliance reviewers (HIPAA / PCI-DSS)
- Operators / administrators deploying and maintaining the system
- Future maintainers performing changes or audits

### 1.4 Document Conventions

- **MUST / SHOULD / MAY** follow RFC 2119 semantics.
- Code, paths, and identifiers appear in `monospace`.
- ASCII box diagrams use pure ASCII (`+ - | >`) for portability; Unicode box-drawing is avoided to prevent alignment drift across editors.
- "Manager API" refers to this project's own REST API; "Agent API" refers to the upstream Linux Patch API running on managed hosts.

### 1.5 References

- IEEE Std 1016-2009, *IEEE Standard for Information Technology — Systems Design — Software Design Descriptions*
- RFC 2119, *Key words for use in RFCs to Indicate Requirement Levels*
- RFC 8446, *TLS 1.3*
- HIPAA Security Rule, 45 CFR §164.312
- PCI-DSS v4.0
- Upstream: [Linux Patch API](https://gitea.moon-dragon.us/echo/linux_patch_api)
- Internal: `SPEC.md`, `REQUIREMENTS.md` (same repository)

### 1.6 Glossary

| Term | Definition |
|------|------------|
| Agent | The Linux Patch API service running on each managed host |
| Manager | This project — the Linux_Patch_Manager web application |
| mTLS | Mutual TLS; both client and server present X.509 certificates |
| RBAC | Role-Based Access Control |
| SPA | Single-Page Application |
| CA | Certificate Authority |
| JWT | JSON Web Token |
| TOTP | Time-based One-Time Password |
| WebAuthn | W3C Web Authentication standard (FIDO2) |
| SSO | Single Sign-On |
| FQDN | Fully Qualified Domain Name |
| CIDR | Classless Inter-Domain Routing (network range notation) |

---

## 2. Stakeholders and Design Concerns

| Stakeholder | Primary Concerns |
|-------------|------------------|
| Administrator | Full fleet control, user management, CA management, SSO config, auditability |
| Operator | Group-scoped patch deployment, scheduling, job monitoring, reporting |
| Security / Compliance Officer | MFA, audit log integrity, encryption at rest and in transit, HIPAA / PCI-DSS mapping |
| Server Administrator (managed host owner) | Minimal agent footprint, predictable maintenance windows, manual cert control |
| System Implementer | Clear component boundaries, testable data flows, deterministic error handling |
| System Operator (of the Manager host) | systemd-friendly deployment, structured logs, health endpoint, backup/restore |

---

## 3. Architecture Decisions

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| AD-01 | Backend language / framework | Rust with Axum | Memory-safe, high async throughput, aligned with `linux_patch_api` stack |
| AD-02 | Frontend framework | React + TypeScript SPA (Vite) | Rich ecosystem for enterprise dashboards, strong typing, fast dev loop |
| AD-03 | Database | PostgreSQL with SQLx | Enterprise-grade, type-safe compile-time checked queries, strong concurrency |
| AD-04 | Async runtime | Tokio | De facto Rust async runtime; required by Axum |
| AD-05 | Deployment model | Single bare-metal / VM host | Simplicity; sized to support up to 2,500 agents |
| AD-06 | Frontend serving | Axum serves static assets | Single process, one TLS endpoint, simplest deployment |
| AD-07 | Background processing | Separate worker process | Isolation of long-running work from request path; independent restart |
| AD-08 | Web ↔ Worker coordination | PostgreSQL job queue + `LISTEN/NOTIFY` | Avoids extra broker (Redis / RabbitMQ); sub-second wake for immediate-apply |
| AD-09 | Session management | Short-lived JWT access + DB-backed refresh | 15-minute access token; 1-hour inactivity-based refresh; revocable |
| AD-10 | Encryption at rest | Hardware-host full-disk encryption | Provided by the underlying infrastructure; application does not manage disk encryption; satisfies HIPAA / PCI-DSS storage protection |
| AD-11 | Certificate management | Internal CA on Manager host | Issues and renews mTLS certs; distribution to agents is manual by design |
| AD-12 | API versioning | URL path versioning (`/api/v1/…`) | Consistent with upstream Agent API convention; clear breaking-change boundary |
| AD-13 | TLS | TLS 1.3 only, both Agent and Web UI | Eliminates legacy cipher risk; required for compliance posture |
| AD-14 | Observability transport | Structured JSON logs via `tracing` | Machine-readable; no hard dependency on external stack |
| AD-15 | Web UI TLS certificate | Self-signed from internal CA by default; operator may supply external cert | Zero-touch default for internal deployments; easy upgrade path to infrastructure wildcard certs |
| AD-16 | Azure SSO and SMTP | Runtime-configured via Settings GUI with test actions | Operators can change tenants / mail relays without redeploy; test-connection closes configuration loop |
| AD-17 | PDF generation | `printpdf` + `plotters` (in-process) | Charts required; avoids sidecar (e.g., wkhtmltopdf) and its operational surface; all rendering stays in the Rust process |
| AD-18 | IP whitelist enforcement | Enforced at every listener and on agent-call origination | Mandatory security control; reduces attack surface beyond TLS and mTLS |

---

## 4. System Architecture

### 4.1 Context Diagram

```
                   +------------------------+
  Browser (HTTPS)  |   Admin / Operator     |
  ---------------->|   Workstation          |
                   +-----------+------------+
                               |
                               | HTTPS (TLS 1.3) / WSS
                               v
                   +------------------------+
                   |  Linux Patch Manager   |
                   |   (this project)       |
                   +-----------+------------+
                               |
                   mTLS / REST + WSS (port 12443)
                               |
            +------------------+------------------+
            v                  v                  v
        +--------+         +--------+         +--------+
        | Host A |         | Host B |    ...  | Host N |
        | Agent  |         | Agent  |         | Agent  |
        +--------+         +--------+         +--------+
          (Linux Patch API agents, up to 2,500)

            Optional: Azure AD (OAuth2 / OIDC SSO)
```

### 4.2 Logical View — Host-Internal Components

```
+---------------------------------------------------------------+
|              Linux Patch Manager Host (Ubuntu 24.04)           |
|                                                               |
|  +-----------------------+    +-----------------------------+ |
|  |   Axum Web Server     |    |   Background Worker         | |
|  |   (systemd unit)      |    |   (systemd unit)            | |
|  |                       |    |                             | |
|  |  +-----------------+  |    |  +-----------------------+  | |
|  |  |  REST API       |  |    |  |  Health Poller        |  | |
|  |  |  (CRUD, auth)   |  |    |  |  (5 min intervals)    |  | |
|  |  +-----------------+  |    |  +-----------------------+  | |
|  |  +-----------------+  |    |  +-----------------------+  | |
|  |  |  WebSocket      |  |    |  |  Patch Data Poller    |  | |
|  |  |  Relay          |  |    |  |  (30 min intervals)   |  | |
|  |  +-----------------+  |    |  +-----------------------+  | |
|  |  +-----------------+  |    |  +-----------------------+  | |
|  |  |  Static Files   |  |    |  |  Job Scheduler        |  | |
|  |  |  (React SPA)    |  |    |  |  (maintenance windows)|  | |
|  |  +-----------------+  |    |  +-----------------------+  | |
|  |  +-----------------+  |    |  +-----------------------+  | |
|  |  |  mTLS Client    |  |    |  |  Job Executor +       |  | |
|  |  |  (agent comm)   |  |    |  |  Retry Engine         |  | |
|  |  +-----------------+  |    |  +-----------------------+  | |
|  |                       |    |  +-----------------------+  | |
|  |                       |    |  |  Email Notifier       |  | |
|  |                       |    |  |  (optional/disabled)  |  | |
|  |                       |    |  +-----------------------+  | |
|  |                       |    |  +-----------------------+  | |
|  |                       |    |  |  Data Pruner          |  | |
|  |                       |    |  +-----------------------+  | |
|  +----------+------------+    +--------------+--------------+ |
|             |                                |                |
|             |     +--------------------------+                |
|             v     v                                           |
|  +------------------------------------------------------+    |
|  |                    PostgreSQL                         |    |
|  |  (hosts, groups, users, jobs, schedules, audit, ...)  |    |
|  |  Coordination: LISTEN/NOTIFY channels                 |    |
|  +------------------------------------------------------+    |
|                                                               |
|  +------------------------------------------------------+    |
|  |               Internal CA (mTLS certs)                |    |
|  +------------------------------------------------------+    |
|                                                               |
|  Host-level: hardware-host full-disk encryption (infrastructure)|
+---------------------------------------------------------------+
```

### 4.3 Deployment View

All components co-reside on a single Ubuntu 24.04 host. Two `systemd` units run the application:

- `patch-manager-web.service` — Axum web server; listens on TCP `443` (HTTPS) for browsers.
- `patch-manager-worker.service` — Background worker; no inbound listener.

Both connect to a local `postgresql.service`. Outbound agent calls go to TCP `12443` on each managed host. See §10 for deployment details.

### 4.4 Process View

- **Web process** handles HTTP requests, serves the SPA, validates JWTs, authorizes via RBAC, and performs on-demand mTLS calls to agents (e.g., manual refresh, immediate patch triggers that are short-lived).
- **Worker process** runs scheduled polls, scans CIDR ranges on-demand, executes queued jobs at maintenance-window boundaries, and prunes expired data.
- **PostgreSQL** is the single source of truth. The web and worker processes communicate indirectly through rows in `patch_jobs`, `patch_job_hosts`, and related tables, using `LISTEN / NOTIFY` channels (`job_enqueued`, `job_cancelled`) to wake the worker without polling latency.

---

## 5. Component Design

### 5.1 Axum Web Server

**Responsibility:** Handle all HTTP/HTTPS requests from browsers and serve the React SPA.

- **Manager REST API** at `/api/v1/…` — CRUD for hosts, groups, users, schedules, certificates, reports.
- **WebSocket Relay** at `/api/v1/ws/jobs` — Authenticated WSS endpoint; Manager opens an upstream mTLS WSS to the relevant agent(s) and multiplexes events to the browser.
- **Static File Server** — Serves compiled React SPA (HTML, JS, CSS, assets) from a single directory.
- **Authentication** — JWT access-token validation, refresh-token issuance/rotation, MFA enforcement, Azure OIDC flow.
- **Authorization** — RBAC middleware enforcing `admin`, `operator`, and group-scoped access (see §7.2).
- **mTLS Client** — Rustls-based HTTP client holding the Manager's client certificate for on-demand calls to agents.

**API versioning:** The Manager's own API uses URL path versioning (`/api/v1/…`). This is independent of the Agent API version, even though the convention matches.

**Browser → WebSocket authentication:** The client obtains a short-lived WS ticket from `POST /api/v1/ws/ticket` (JWT-authenticated), then opens `wss://…/api/v1/ws/jobs?ticket=…`. The ticket is single-use and expires in 60 seconds.

### 5.2 Background Worker

**Responsibility:** All scheduled and asynchronous background processing.

- **Health Poller** — Periodic health checks to all registered agents (5-minute interval; configurable).
- **Patch Data Poller** — Periodic patch-availability queries to all agents (30-minute interval; configurable).
- **Job Scheduler** — Opens maintenance windows and dispatches queued jobs.
- **Job Executor** — Invokes agent endpoints for patch apply / install / remove / reboot; tracks async job IDs returned by the agent.
- **Retry Engine** — Exponential backoff for transient agent communication failures: up to **3 retries**, max **30 minutes** between retries (see §8).
- **Email Notifier** — Optional; disabled by default.
- **Data Pruner** — Daily job that deletes operational data older than 30 days and audit-log rows older than 6 months.

**Concurrency bounds:** The worker uses a bounded Tokio `Semaphore` (default **64 concurrent agent calls**, configurable) to avoid saturating the host's network or file-descriptor limits when polling thousands of agents.

**Coordination:**
- Scheduled pollers run on Tokio intervals.
- Immediate-apply and on-demand actions are enqueued by the web process with `INSERT … RETURNING id` followed by `NOTIFY job_enqueued, '<id>'`. The worker holds a `LISTEN job_enqueued` connection and wakes immediately.

### 5.3 PostgreSQL Database

**Responsibility:** Persistent storage and coordination primitive for the system.

**Key tables (logical; exact DDL lives in `migrations/`):**

| Table | Purpose |
|-------|---------|
| `hosts` | Registered hosts, metadata, health status, last-seen timestamp |
| `groups` | Static groups for access control |
| `host_groups` | Many-to-many host ↔ group membership |
| `users` | Local accounts with Argon2 hashes, MFA secrets |
| `user_groups` | Many-to-many user ↔ group membership |
| `refresh_tokens` | Server-side refresh tokens; revocable |
| `maintenance_windows` | Per-device recurring and one-time schedules |
| `patch_jobs` | Queued, running, completed, failed patch operations |
| `patch_job_hosts` | Per-host status within a batch job |
| `host_patch_data` | Cached patch availability snapshots |
| `host_health_data` | Cached health check results |
| `certificates` | Issued mTLS client certificates (metadata, not private keys) |
| `audit_log` | Tamper-evident audit trail (hash-chained) |
| `azure_sso_config` | Azure AD SSO configuration |
| `system_config` | Key/value runtime configuration (polling intervals, etc.) |

**Data retention:**
- Operational tables (`host_patch_data`, `host_health_data`, `patch_jobs`, `patch_job_hosts`): 30 days.
- `audit_log`: 6 months.

**Migrations:** Managed via `sqlx-cli` (`sqlx migrate add / run`). Migrations are embedded into the binaries via `sqlx::migrate!` and applied automatically at startup of the web process (single-writer election via advisory lock).

### 5.4 React + TypeScript SPA

**Responsibility:** User-facing web interface.

**Pages:**

1. **Dashboard** — Fleet overview: compliance %, health summary, upcoming windows, root CA download.
2. **Hosts** — Filterable host list by group, status, OS.
3. **Host Detail** — System info, packages, patches, jobs, maintenance-window config, host cert download.
4. **Patch Deployment** — Select hosts, review patches, deploy (queue or immediate).
5. **Jobs** — Real-time job monitoring via WebSocket.
6. **Maintenance Windows** — Per-device recurring / one-time schedule management.
7. **Groups** — Manage static groups; assign hosts and operators.
8. **Reports** — Generate / export compliance, patch history, vulnerability, audit (CSV / PDF).
9. **Users** — Local account management, MFA setup, group assignments.
10. **Certificates** — View / manage internal CA; issue / renew client certs.
11. **Settings** — System config: Azure SSO setup (with "Test Connection"), SMTP setup (with "Send Test Email"), polling intervals, Web UI TLS certificate strategy (internal CA vs. operator-supplied), IP whitelist management.

### 5.5 Internal CA

**Responsibility:** mTLS certificate lifecycle for agent communication.

- Runs in-process within the web server (library-level, `rcgen` + `rustls`).
- Issues client certificates for mTLS communication with agents.
- Supports renewal; revocation is performed by issuing a new cert and marking the old one revoked in `certificates`.
- Root CA certificate downloadable from Dashboard for manual distribution.
- Host-specific mTLS certificates downloadable from each Host Detail page.
- **No automated distribution to managed clients** — server administrators install them manually.
- CA private key is stored on the Manager host at `/etc/patch-manager/ca/ca.key` with `0600` permissions, owned by the service user. Disk-level protection is provided by hardware-host full-disk encryption.


---

## 6. Data Flow

### 6.1 Host Registration

```
1. Admin enters FQDN / IP -> Web validates and resolves FQDN to IP.
2. Web inserts row in `hosts` (status = pending).
3. Web NOTIFYs `host_registered` -> Worker performs initial mTLS health check.
4. Worker updates `hosts.health_status` and `host_health_data` -> visible in Dashboard.
```

### 6.2 Auto-Discovery (CIDR scan)

```
1. Admin triggers CIDR scan -> Web inserts a discovery job and NOTIFYs `discovery_enqueued`.
2. Worker scans the subnet for agents listening on port 12443 (bounded concurrency, TLS probe).
3. Discovered agents written to a transient `discovery_results` table.
4. Admin reviews and selects which to register; each selection follows the 6.1 flow.
```

### 6.3 Patch Deployment — Queued

```
1. Operator selects hosts + patches -> "Queue for next window".
2. Web creates `patch_jobs` row (status = queued) and `patch_job_hosts` rows.
3. Job Scheduler detects the next applicable maintenance window per host.
4. At window open, Worker calls the Agent API to start patch operations.
5. Worker polls agent job status (and/or consumes WebSocket events) and updates rows.
6. WebSocket Relay pushes updates to subscribed browsers in real time.
7. Failed hosts are auto-retried once if still within the window (see §8).
```

### 6.4 Patch Deployment — Immediate

```
1. Operator selects hosts + patches -> "Apply Now".
2. Web creates `patch_jobs` row (status = pending) and NOTIFYs `job_enqueued`.
3. Worker wakes immediately and triggers the agent calls.
4. Same monitoring and retry logic as the queued flow.
```

### 6.5 Rollback

```
1. Operator opens a completed or failed job and clicks "Rollback".
2. Web creates a `patch_jobs` row with kind = rollback, parent_job_id = <original>.
3. Worker calls POST /api/v1/jobs/{id}/rollback on each affected agent.
4. Results are tracked like any other job; audit log records the rollback actor.
```

### 6.6 Health / Patch Polling

```
1. Worker polls each agent on schedule (5 min health, 30 min patches).
2. Results cached in `host_health_data` and `host_patch_data`.
3. Unhealthy agents are flagged with visual alerts in the Dashboard.
4. On-demand refresh: operator clicks refresh -> Web NOTIFYs `refresh_requested`; Worker queries immediately.
```

---

## 7. Security Architecture

### 7.1 Authentication

- **Local accounts:** Argon2id-hashed passwords; TOTP or WebAuthn for MFA (enforced).
- **Azure SSO:** OAuth2 / OIDC Authorization Code flow with PKCE; Azure's built-in MFA satisfies the MFA requirement.
- **Access tokens:** JWT, signed with **EdDSA / Ed25519**; 15-minute TTL. Signing keys rotated every 90 days with a 24-hour overlap window. The web process holds the signing key; the worker process holds only the verifying (public) key.
- **Refresh tokens:** Opaque, 256-bit, stored hashed in `refresh_tokens`; **1-hour sliding inactivity timeout** (rotated on use; revocable).
- **Revocation:** Admins can force-revoke a user's refresh tokens; the next access-token expiry terminates all sessions.

### 7.2 Authorization (RBAC)

- **Admin** — Full access to all resources and settings.
- **Operator** — Can add / remove hosts and manage schedules / patches only for devices in their assigned groups.
- **Group scoping** — Enforced by middleware at every API endpoint that touches host-scoped data.
- **Ungrouped hosts** — Accessible by any operator or admin (explicit product decision).

### 7.3 Agent Communication

- **mTLS** — Client certificate authentication for every agent call and WebSocket.
- **TLS 1.3 only** — Older TLS versions are refused at the Rustls configuration layer.
- **Internal CA** — Manager issues and renews client certificates.
- **Manual distribution** — Server administrators install certs on managed clients; the Manager holds no credentials for managed hosts and cannot push files to them.

### 7.4 Data Protection

- **Encryption at rest** — Provided by the underlying hardware host (infrastructure-level full-disk encryption). The application does not configure or manage disk encryption; this is delegated to the infrastructure layer and satisfies HIPAA / PCI-DSS storage protection requirements.
- **Encryption in transit** — TLS 1.3 for all agent and browser connections.
- **Audit log integrity** — Hash-chained rows (`audit_log.prev_hash`, `audit_log.row_hash`); integrity verified by a periodic check job and on-demand from the UI.
- **Password storage** — Argon2id with per-user salt. Starting parameters: `m_cost = 65536 KiB (64 MiB)`, `t_cost = 3`, `p_cost = 1`; calibrated to land in the 250–500 ms login-latency budget on the target hardware (Intel Xeon, 4 cores, 16 GB RAM). Final calibration result recorded in `system_config`.
- **Secrets on disk** — Configuration secrets (JWT signing key, CA private key, DB password) are stored in `/etc/patch-manager/secrets/` with `0600` permissions, owned by the service user; not committed to the repository.

### 7.5 Compliance Mapping

- **HIPAA §164.312:** Audit controls (§7.4), access controls (§7.2 + MFA), integrity controls (hash-chained audit), transmission security (TLS 1.3 / mTLS), automatic logoff (1-hour inactivity).
- **PCI-DSS:** Requirement 6 (vulnerability management — core function), Requirement 7 (need-to-know via group scoping), Requirement 8 (MFA, unique IDs), Requirement 10 (audit with 6-month retention), Requirements 3 & 4 (encryption at rest and in transit).

---

## 8. Error Handling and Reliability

### 8.1 Agent Communication Failures

- Mark host as **unhealthy** in the Dashboard.
- Retry with **exponential backoff**: up to **3 retries**, capped at **30 minutes** between attempts (example schedule: 1 min, 5 min, 30 min).
- Continue processing other hosts without blocking.
- After exhausting retries, the host is flagged and reported in the next compliance report.

### 8.2 Patch Job Failures

- Auto-retry a failed patch job **once** if still within the maintenance window.
- If the retry fails, or the window has closed, surface the failure prominently in the Jobs view and in any configured email notifications.

### 8.3 Batch Operations with Partial Failures

- Auto-retry failed hosts **once**.
- If retry fails, report the failed hosts in the job detail view and let the operator decide next steps.
- Successful hosts complete normally regardless of failures elsewhere in the batch.

### 8.4 API Error Response Format

All Manager API errors use a consistent JSON envelope:

```json
{
  "error": {
    "code": "host_not_found",
    "message": "No host with id 42 in any group you can access.",
    "request_id": "01JF8Q...",
    "details": {}
  }
}
```

HTTP status codes follow standard REST semantics (`400`, `401`, `403`, `404`, `409`, `422`, `429`, `500`, `503`). Every response carries an `X-Request-Id` header to correlate logs and user reports.

### 8.5 Input Validation

- All request bodies are validated with strongly-typed Rust structs (`serde` + `validator`); validation errors return `422` with field-level details.
- FQDNs, IPs, and CIDR ranges are parsed with the standard library / `ipnet` and rejected early.

---

## 9. Technology Stack

| Layer | Technology | Notes |
|-------|-----------|-------|
| Backend | Rust + Axum | Tokio async runtime, Tower middleware |
| Database | PostgreSQL 16+ | SQLx for type-safe queries; migrations via `sqlx-cli` |
| Frontend | React 18+ + TypeScript | Vite build tooling |
| UI Components | MUI (Material UI) | Enterprise dashboard components, dark mode, theming |
| WebSocket | Axum native WebSocket | Agent -> Manager -> Browser relay |
| Auth (Local) | Argon2id + TOTP / WebAuthn | MFA enforcement |
| Auth (SSO) | OAuth2 / OIDC (Azure AD) | Optional; Azure MFA |
| Session | JWT (access) + DB-backed refresh | 15-min access, 1-hr inactivity refresh |
| mTLS Client | Rustls + client certs | TLS 1.3 only |
| Internal CA | Rustls / `rcgen` | Certificate issuance and renewal |
| Email | Lettre | Optional; disabled by default |
| PDF Export | `printpdf` + `plotters` | In-process pure-Rust PDF + charts; no sidecar |
| CSV Export | `csv` crate | Data export for all report types |
| Service Management | systemd | Ubuntu 24.04 |
| Static Files | Axum built-in static serving | React SPA served directly |
| Logging / Tracing | `tracing` + `tracing-subscriber` (JSON) | Structured logs |

---

## 10. Deployment Architecture

```
+---------------------------------------------+
|   Patch Manager Host (Ubuntu 24.04, bare    |
|   metal or VM)                               |
|                                             |
|  +---------------------------------------+  |
|  | systemd: patch-manager-web.service    |  |
|  | (Axum web server + static SPA)        |  |
|  | Listens: 443/tcp (HTTPS, TLS 1.3)     |  |
|  +---------------------------------------+  |
|                                             |
|  +---------------------------------------+  |
|  | systemd: patch-manager-worker.service |  |
|  | (Background polling + jobs)           |  |
|  | No inbound listener                   |  |
|  +---------------------------------------+  |
|                                             |
|  +---------------------------------------+  |
|  | systemd: postgresql.service           |  |
|  | (Local, Unix socket or 127.0.0.1)     |  |
|  +---------------------------------------+  |
|                                             |
|  +---------------------------------------+  |
|  | /etc/patch-manager/                    | |
|  |   config.toml, secrets/*, ca/*         | |
|  +---------------------------------------+  |
|                                             |
|  Hardware-host full-disk encryption (infra) |
+---------------------------------------------+
```

- Two systemd services: `patch-manager-web` and `patch-manager-worker`; independent restart and logging.
- PostgreSQL runs on the same host; connections via Unix domain socket.
- Internal CA material lives in `/etc/patch-manager/ca/` with `0600` permissions.
- No Docker / LXC in production — bare-metal / VM deployment. Containerized **development** environments are acceptable and do not affect production design.
- Internal network only — no public internet exposure. Ingress limited to the Manager's HTTPS port; egress to agents on `12443` and, optionally, Azure AD / SMTP.

### 10.1 Configuration

- Primary config file: `/etc/patch-manager/config.toml` (non-secret tunables: bind address, DB URL, polling intervals, concurrency caps, log level, feature flags).
- Secrets: separate files in `/etc/patch-manager/secrets/` referenced by path from the config — never inlined.
- Environment variables may override any config key (`PATCH_MANAGER__SECTION__KEY`) for operator convenience; env-based overrides are logged at startup.
- Runtime-tunable values (polling intervals, Azure SSO settings) are stored in `system_config` and editable from the Settings page; static values (bind address, DB URL) require a service restart.

### 10.2 Database Migrations

- Managed with `sqlx migrate`; migration files live under `migrations/` and are embedded into the web binary via `sqlx::migrate!`.
- Applied on web-process startup; a PostgreSQL advisory lock ensures only one instance runs migrations at a time.
- Worker process waits for the expected schema version before accepting work (`SELECT version FROM _sqlx_migrations ORDER BY installed_on DESC LIMIT 1`).

### 10.3 Backup and Disaster Recovery

- **Database:** Nightly `pg_dump` to `/var/backups/patch-manager/`, with an external copy to an encrypted off-host location (operator-configured).
- **CA material:** Included in the nightly backup; treated as highest-sensitivity.
- **Configuration:** `/etc/patch-manager/` included in the backup, excluding secret files unless the backup destination is encrypted.
- **Restore procedure:** Documented in `docs/runbooks/restore.md` (to be created during implementation).
- **RPO target:** 24 hours. **RTO target:** 4 hours on comparable hardware.

---

## 11. Scalability

- **Single-instance design:** Supports ~500 typical hosts comfortably, tested target up to 2,500.
- **Sizing basis:** 2,500 hosts × one health poll / 5 min = ~8.3 req/s average; 2,500 × one patch poll / 30 min = ~1.4 req/s; bursts during maintenance windows bounded by the worker semaphore (default 64 concurrent calls). These rates are trivial for Axum + Tokio on the target hardware (Intel Xeon, 4 cores, 16 GB RAM).
- **Manual horizontal scaling:** Divide the fleet between multiple Manager hosts if the fleet grows beyond 2,500. There is no automatic sharding.
- **Connection pooling:** SQLx `PgPool` (default 20 connections, tunable) shared across request handlers.
- **Background worker:** Independent process — its polling load does not compete with user request latency.
- **No automatic clustering or load balancing.** Multi-instance deployments are explicitly out of scope.

---

## 12. Integration Points

**Upstream dependency:** [Linux Patch API](https://gitea.moon-dragon.us/echo/linux_patch_api)

| Integration | Protocol | Direction | Purpose |
|-------------|----------|-----------|---------|
| Agent REST API | HTTPS / mTLS (TLS 1.3) on port 12443 | Manager -> Agent | Queries and patch operations |
| Agent WebSocket | WSS / mTLS on port 12443 | Agent -> Manager | Real-time job status streaming |
| Azure AD | HTTPS / OAuth2 / OIDC | Manager -> Azure | SSO authentication (optional) |
| SMTP | SMTPS | Manager -> SMTP relay | Optional email notifications |

### 12.1 Agent API Endpoints Consumed

- `GET  /api/v1/health` — Agent health check
- `GET  /api/v1/system/info` — Host system information
- `GET  /api/v1/packages` — List installed packages
- `GET  /api/v1/patches` — List available patches
- `POST /api/v1/patches/apply` — Apply patches
- `PUT  /api/v1/packages/{name}` — Update a specific package
- `DELETE /api/v1/packages/{name}` — Remove a package
- `POST /api/v1/packages` — Install packages
- `GET  /api/v1/jobs` — List jobs
- `GET  /api/v1/jobs/{id}` — Get job status
- `POST /api/v1/jobs/{id}/rollback` — Rollback a job
- `POST /api/v1/system/reboot` — Reboot host
- `WS   /api/v1/ws/jobs` — Real-time job status

### 12.2 Manager's Own API Surface (selected)

- `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`
- `POST /api/v1/auth/mfa/totp/setup`, `POST /api/v1/auth/mfa/webauthn/register`
- `GET  /api/v1/hosts`, `POST /api/v1/hosts`, `GET /api/v1/hosts/{id}`, `DELETE /api/v1/hosts/{id}`
- `POST /api/v1/discovery/cidr`
- `GET  /api/v1/groups`, `POST /api/v1/groups`, …
- `GET  /api/v1/jobs`, `POST /api/v1/jobs` (queue / immediate), `POST /api/v1/jobs/{id}/rollback`
- `GET  /api/v1/reports/compliance`, `GET /api/v1/reports/patch-history`, `GET /api/v1/reports/audit` (with `?format=csv|pdf`)
- `GET  /api/v1/ca/root.crt`, `GET /api/v1/hosts/{id}/client.crt`
- `POST /api/v1/ws/ticket`, `WS /api/v1/ws/jobs?ticket=...`
- `GET  /status/health` — **Manager's own** unauthenticated liveness endpoint (distinct namespace from the agent's `/api/v1/health`)

---

## 13. Monitoring and Observability

- **Structured logging:** JSON lines via the `tracing` crate; one field schema for both services.
- **Log levels:** Configurable at runtime (`DEBUG`, `INFO`, `WARN`, `ERROR`) per module.
- **Request correlation:** Every HTTP request is tagged with `request_id` (ULID), propagated into logs and error responses.
- **Liveness / readiness:** `GET /status/health` on the Manager (unauthenticated, Manager's own namespace — do not confuse with the agent's `/api/v1/health`). Returns `200` when the process can reach the database and worker heartbeat is fresh.
- **Worker heartbeat:** Worker writes a row to `worker_heartbeat` every 30 seconds; the web process surfaces stale heartbeats as a banner alert.
- **Dashboard alerts:** Visual indicators for unhealthy / unreachable agents (red / yellow status).
- **Audit logging:** All significant events logged to PostgreSQL with tamper-evident hash chaining.
- **Optional metrics (future):** `tracing` lends itself to an OpenTelemetry exporter; Prometheus scrape endpoint at `/metrics` is a candidate future addition (see §17). Not required for v0.0.x.

---

## 14. Design Rationale

- **Why Rust + Axum, not Node / Go / Python?** A patch manager is a high-trust, long-running administrative control plane. Memory safety and strong typing are high-value there; Rust's async story via Tokio is mature; Axum keeps the HTTP layer thin and composable. Aligning with the upstream Agent API's stack also reduces cognitive load for maintainers.
- **Why a single process per role (web + worker), not monolith or microservices?** A monolith couples polling jitter into request latency; microservices require a broker and more operational surface area than a fleet of ≤2,500 agents justifies. Two processes + PostgreSQL coordination is the smallest design that satisfies the non-functional requirements.
- **Why PostgreSQL as the queue?** At our scale (tens of req/s), PostgreSQL's `LISTEN/NOTIFY` plus `SELECT ... FOR UPDATE SKIP LOCKED` is more than sufficient and avoids introducing Redis or a dedicated broker as a second stateful dependency.
- **Why no automatic cert distribution?** Pushing certificates onto managed hosts would require elevated credentials on those hosts, materially expanding the Manager's blast radius. Manual distribution is a deliberate least-privilege choice.
- **Why hardware-host encryption and not column-level?** The hardware host provides full-disk encryption transparently at a layer below the OS, covering every byte — PostgreSQL data, WAL, backups, temporary files, logs, and swap — with zero application complexity. Column-level encryption would duplicate protection for some data, leave other data unprotected, and add key-management burden without improving the compliance posture on a single-host deployment.
- **Why URL path versioning (`/api/v1/…`)?** It is explicit, easy to operate behind a proxy, matches the Agent API, and makes breaking-change boundaries unambiguous.
- **Why JWT + refresh, not session cookies only?** Short-lived JWTs keep the authorization path stateless and cheap; refresh tokens give admins a server-side revocation hook. Inactivity timeout comes from the refresh token, not the JWT.

---

## 15. Risks and Trade-offs

| # | Risk / Trade-off | Mitigation |
|---|------------------|------------|
| R-01 | Single-host deployment = single point of failure | Documented backup/restore (§10.3); operator may run a warm standby restored from nightly backups |
| R-02 | PostgreSQL as queue has lower throughput ceiling than a dedicated broker | Bounded-scope design (≤2,500 agents); revisit if scale expands |
| R-03 | Manual cert distribution creates human error risk | Clear UX: per-host download, audit log records who downloaded which cert and when |
| R-04 | Hash-chained audit is tamper-evident but not tamper-proof | Document that integrity checks detect — not prevent — tampering; recommend off-host log shipping for high-assurance environments |
| R-05 | Hardware-host encryption does not protect running-process memory | Out of scope; treated as an OS / hypervisor / hardware concern |
| R-06 | WebSocket ticket pattern adds a round-trip | Acceptable; keeps WS auth simple and avoids query-string JWT exposure in access logs |
| R-07 | Configuration via TOML + env overrides can be surprising | Startup log dumps the effective config (redacting secrets) |
| R-08 | Agent API changes could break the Manager | Pin to `/api/v1/`; integration tests run against a known Agent version |

---

## 16. Open Issues

| # | Issue | Owner | Target |
|---|-------|-------|--------|
| OI-01 | **CLOSED** — Encryption at rest delegated to hardware-host (infrastructure-level). `REQUIREMENTS.md` v0.0.2 and `SPEC.md` v0.0.2 updated to match. No OS-level LUKS; no column-level encryption. | — | Closed 2026-04-23 |
| OI-02 | **CLOSED** — Argon2id starting parameters: `m_cost = 65536 KiB (64 MiB)`, `t_cost = 3`, `p_cost = 1`; targets ~400 ms on Intel Xeon 4-core / 16 GB RAM. Final calibration performed at deploy time and recorded in `system_config`. | — | Closed 2026-04-23 |
| OI-03 | **CLOSED** — JWT signing algorithm: **EdDSA / Ed25519**. Keys rotated every 90 days with a 24-hour overlap window; signing key lives with web process, verifying key published to worker. | — | Closed 2026-04-23 |
| OI-04 | **CLOSED** — CIDR scan defaults: concurrency = **128**, per-host TCP+TLS probe timeout = **1.5 s**. Sized to complete a `/22` (~1,024 hosts) across sites in under 10 s. Progress UI and cancel action are required (NFR-05). | — | Closed 2026-04-23 |
| OI-05 | **CLOSED** — PDF generation: **`printpdf`** for document layout, **`plotters`** for charts. Both are in-process pure-Rust crates; no sidecar required. Company branding and digital signatures are not required. | — | Closed 2026-04-23 |
| OI-06 | **CLOSED** — `/status/health` is Manager-only minimal liveness (web up, DB reachable, worker heartbeat fresh), unauthenticated. Fleet aggregates exposed on authenticated **`/api/v1/status/fleet`** to avoid leaking fleet size to unauthenticated probes. | — | Closed 2026-04-23 |

---

## 17. Future Considerations (non-binding)

- Prometheus `/metrics` endpoint and OpenTelemetry traces.
- Optional webhook / Slack notifier (currently out of scope).
- Multi-instance active/passive failover using PostgreSQL streaming replication.
- CRL or OCSP responder for the internal CA (currently: revocation by re-issuance + `certificates.revoked_at`).
- Automated cert distribution via an opt-in agent endpoint (requires Agent API change; pure opt-in with operator approval).
- Per-group maintenance-window templates to reduce per-host configuration effort.

---

## 18. Change Log (this review pass)

| # | Change | Reason |
|---|--------|--------|
| C-01 | Renamed title to "Software Design Document (SDD)" and added Document Control + Revision History | Aligns with IEEE 1016; establishes versioning discipline |
| C-02 | Added §1 Introduction (Purpose, Scope, Audience, Conventions, References, Glossary) | Standard SDD front matter was missing |
| C-03 | Added §2 Stakeholders and Design Concerns | IEEE 1016 viewpoint prerequisite; clarifies who the design serves |
| C-04 | Replaced Unicode box-drawing in diagrams with pure ASCII and fixed misaligned borders in the original logical view | Original diagram (lines 26–73 of v0.0.1) had truncated right borders and an ambiguous bidirectional arrow between the web-server mTLS client and the worker's retry engine, which did not match the described data flow |
| C-05 | Split the single architecture diagram into Context View (§4.1), Logical View (§4.2), Deployment View (§4.3), and Process View (§4.4) | Matches IEEE 1016 viewpoint model; each diagram now has a single responsibility |
| C-06 | Numbered architecture decisions (AD-01 … AD-14) and added AD-08 (PG `LISTEN/NOTIFY` coordination), AD-12 (API versioning), AD-13 (TLS 1.3), AD-14 (observability) | Original table had implicit/overlapping decisions; numbering enables cross-reference; added decisions were previously only implied |
| C-07 | Clarified Web ↔ Worker coordination uses `LISTEN/NOTIFY` + `SELECT ... FOR UPDATE SKIP LOCKED` | Original said the worker "reads job queue from PostgreSQL" without specifying how it wakes for immediate-apply jobs; this would have left implementation undefined |
| C-08 | Added concurrency bound (default 64 concurrent agent calls via Tokio `Semaphore`) | Polling 2,500 agents without bounds would exhaust FDs and network resources; bound was a known implicit requirement |
| C-09 | Clarified API-versioning statement: Manager's own API uses `/api/v1/`; this is independent of the Agent API version even though the convention matches | Original text conflated the two, creating ambiguity about what "v1" refers to |
| C-10 | Added explicit WebSocket authentication flow (single-use ticket from `POST /api/v1/ws/ticket`) | Original listed "WebSocket Relay" but did not specify browser-side authentication, leaving a security gap in the design |
| C-11 | Added §6.5 Rollback data flow | REQUIREMENTS FR-03 calls for rollback support, but the original SDD had no rollback flow |
| C-12 | Expanded §7 Security: Argon2id (not just "Argon2"), rotating JWT signing key, refresh-token rotation on use, secret storage paths/permissions, audit-chain verification | Tightens vague or missing details; aligns with HIPAA/PCI-DSS control expectations |
| C-13 | v0.0.2 committed to LUKS-only for encryption at rest and flagged `REQUIREMENTS.md` inconsistency as OI-01. v0.0.3 supersedes this: encryption at rest is now delegated to the hardware host (see C-24). | The v0.0.2 commitment was based on a prior LUKS mandate; updated operator guidance from Kelly replaces OS-level LUKS with hardware-host encryption |
| C-24 | (v0.0.3) Replaced OS-level LUKS with hardware-host full-disk encryption throughout AD-10, §4.2, §4.3, §5.5, §7.4, §10, §14, §15 | Kelly directed that encryption at rest is handled by the hardware host; preserves compliance intent while reducing operational burden on the guest OS |
| C-25 | (v0.0.3) Closed OI-01 through OI-06 with concrete decisions in §16 | Implementer needs unambiguous values; closing OIs finalizes SDD for v0.1.0 planning |
| C-26 | (v0.0.3) Added AD-15 (Web UI TLS cert strategy), AD-16 (Azure SSO / SMTP runtime config GUI), AD-17 (PDF stack), AD-18 (IP whitelist enforcement) | Captures new binding decisions; AD-18 reflects the standing IP-whitelist security mandate that was previously implicit |
| C-27 | (v0.0.3) `REQUIREMENTS.md` bumped to 0.0.2: added FR-07 (System Configuration), NFR updates for Argon2id / EdDSA / CIDR timing, IP whitelist, TLS 1.3 on web UI | Brings REQUIREMENTS into line with SDD; adds previously-implicit configuration-GUI requirements |
| C-28 | (v0.0.3) `SPEC.md` bumped to 0.0.2: portable ASCII diagram, expanded Settings page scope, TLS 1.3 explicit, IP whitelist, hardware-host encryption note | Three-document alignment across REQUIREMENTS / SPEC / ARCHITECTURE |
| C-29 | (v0.0.3) Added `system_config` as a runtime-tunable table reference throughout | Runtime configuration via Settings GUI requires a persistent store for tunable values |
| C-30 | (v0.0.3) Added progress / cancel requirement for long-running scans aligned with NFR-05 | 10-second `/22` scan target plus operator UX demands explicit progress feedback |
| C-14 | Added §8.4 API Error Response Format and `X-Request-Id` correlation | Error schema was undefined, making client-side handling and log correlation unreliable |
| C-15 | Added §10.1 Configuration, §10.2 Database Migrations, §10.3 Backup / DR | Production deployment concerns entirely absent from v0.0.1; each is required by enterprise operations and by compliance audit |
| C-16 | Clarified "No Docker/LXC" applies to production; development may use containers | Original blanket statement conflicted with the actual development environment and would confuse contributors |
| C-17 | Added sizing basis (req/s math) to §11 Scalability | Original claim of "supports 2,500 hosts" had no justification; now traceable |
| C-18 | Separated Manager's liveness endpoint (`/status/health`) from the Agent's `/api/v1/health` in §12 and §13 | Original used `/api/v1/health` for both, creating an endpoint-namespace collision and ambiguity |
| C-19 | Added §12.2 Manager's Own API Surface | Original documented only the Agent endpoints consumed; the Manager's own API was undocumented |
| C-20 | Added §13 worker heartbeat mechanism and request correlation | Needed to detect a dead worker process; otherwise the system could silently stop processing jobs |
| C-21 | Added §14 Design Rationale, §15 Risks and Trade-offs, §16 Open Issues, §17 Future Considerations | IEEE 1016 §7 (Design Rationale) was missing; risks and open issues give reviewers a clear audit surface |
| C-22 | Replaced the Email Notifier arrow that pointed back into the web server's mTLS client on the original diagram with a correct component placement in §4.2 | Original diagram implied email flowed through the mTLS client, which is not the design |
| C-23 | Added C-X change IDs throughout this log | Enables traceability in future reviews |
