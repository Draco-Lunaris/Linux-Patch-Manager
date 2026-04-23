# Linux_Patch_Manager - Architecture Document

## Project Overview
**Title:** Linux_Patch_Manager
**Version:** 0.0.1
**Status:** Draft

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backend language/framework | Rust with Axum | Security-aligned with linux_patch_api, memory-safe, high async performance |
| Frontend framework | React + TypeScript SPA | Rich ecosystem for enterprise dashboards, strong typing |
| Database | PostgreSQL with SQLx | Enterprise-grade, type-safe Rust queries, handles concurrent access |
| Async runtime | Tokio | Standard Rust async runtime, integrates with Axum |
| Deployment model | Single bare metal/VM | Simplicity, supports up to 2,500 managed hosts |
| Frontend serving | Axum serves static files | Simplest deployment, single process |
| Background processing | Separate worker process | Clean separation of concerns, communicates via PostgreSQL |
| Session management | JWT + refresh tokens | Short-lived access tokens (15 min), revocable refresh tokens (1 hr) |
| Encryption at rest | LUKS full-disk (infrastructure) | HIPAA/PCI-DSS compliant, handled at infrastructure level |
| Certificate management | Internal CA on Patch Manager host | Issues/renews mTLS certs, manual distribution to clients |

## System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Linux Patch Manager Host                    │
│                        (Ubuntu 24.04)                          │
│                                                               │
│  ┌─────────────────────┐    ┌──────────────────────────────┐  │
│  │   Axum Web Server   │    │    Background Worker          │  │
│  │                     │    │                              │  │
│  │  ┌───────────────┐  │    │  ┌────────────────────────┐  │  │
│  │  │  REST API     │  │    │  │  Health Poller         │  │  │
│  │  │  (CRUD, auth) │  │    │  │  (5 min intervals)     │  │  │
│  │  └───────────────┘  │    │  └────────────────────────┘  │  │
│  │  ┌───────────────┐  │    │  ┌────────────────────────┐  │  │
│  │  │  WebSocket    │  │    │  │  Patch Data Poller     │  │  │
│  │  │  Relay        │  │    │  │  (30 min intervals)    │  │  │
│  │  └───────────────┘  │    │  └────────────────────────┘  │  │
│  │  ┌───────────────┐  │    │  ┌────────────────────────┐  │  │
│  │  │  Static Files │  │    │  │  Job Scheduler         │  │  │
│  │  │  (React SPA)  │  │    │  │  (maintenance windows) │  │  │
│  │  └───────────────┘  │    │  └────────────────────────┘  │  │
│  │  ┌───────────────┐  │    │  ┌────────────────────────┐  │  │
│  │  │  mTLS Client  │  │    │  │  Retry Engine          │  │  │
│  │  │  (agent comm) │◄─┼────┼─►│  (exp. backoff)       │  │  │
│  │  └───────────────┘  │    │  └────────────────────────┘  │  │
│  └─────────┬─────────┘    │  ┌────────────────────────┐  │  │
│            │              │  │  Email Notifier        │  │  │
│            │              │  │  (optional/disabled)   │  │  │
│            │              │  └────────────────────────┘  │  │
│            │              └──────────────┬───────────────┘  │
│            │                             │                  │
│            │         ┌───────────────────┘                  │
│            │         │                                      │
│  ┌─────────▼─────────▼──────────────────────────────────┐  │
│  │                  PostgreSQL                            │  │
│  │  (hosts, groups, users, jobs, schedules, audit, etc.) │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │               Internal CA (mTLS certs)                │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                               │
                    mTLS / REST API (port 12443)
                ┌──────┼──────┐
                ▼      ▼      ▼
           ┌──────┐┌──────┐┌──────┐
           │ Host ││ Host ││ Host │  ← Linux Patch API agents
           │  A   ││  B   ││  C   │     (up to 2,500)
           └──────┘└──────┘└──────┘
```

## Component Design

### 1. Axum Web Server

**Responsibility:** Handle all HTTP/HTTPS requests from browsers and serve the React SPA.

- **REST API:** CRUD operations for hosts, groups, users, schedules, certificates, reports
- **WebSocket Relay:** Proxy real-time job status from agent WebSocket streams to browser clients
- **Static File Server:** Serve compiled React SPA (HTML, JS, CSS, assets)
- **Authentication:** JWT access token validation, refresh token management, MFA enforcement
- **Authorization:** RBAC middleware enforcing admin/operator/group-scoped access
- **mTLS Client:** HTTP client with client certificates for communicating with Linux Patch API agents

**API Versioning:** URL path versioning (`/api/v1/`) to match the upstream Linux Patch API convention.

### 2. Background Worker

**Responsibility:** All scheduled and asynchronous background processing.

- **Health Poller:** Periodic health checks to all registered agents (5-minute intervals)
- **Patch Data Poller:** Periodic patch availability queries to all agents (30-minute intervals)
- **Job Scheduler:** Execute queued patch operations when maintenance windows open
- **Retry Engine:** Handle agent communication failures with exponential backoff (3 retries, max 30 min)
- **Job Executor:** Trigger patch operations on agents, track async job status
- **Email Notifier:** Optional email notifications (disabled by default)
- **Data Pruner:** Clean up operational data older than 30 days, audit logs older than 6 months

**Communication:** Worker reads job queue from PostgreSQL, updates results back to PostgreSQL. Web server reads results from PostgreSQL for API responses.

### 3. PostgreSQL Database

**Responsibility:** Persistent storage for all application data.

**Key Tables:**
- `hosts` — registered hosts, metadata, health status, last seen
- `groups` — static groups for access control
- `host_groups` — many-to-many host ↔ group membership
- `users` — local accounts with hashed passwords, MFA secrets
- `user_groups` — many-to-many user ↔ group membership
- `refresh_tokens` — server-side refresh tokens for session management
- `maintenance_windows` — per-device recurring and one-time schedules
- `patch_jobs` — queued, running, completed, failed patch operations
- `patch_job_hosts` — per-host status within a batch job
- `host_patch_data` — cached patch availability data from agents
- `host_health_data` — cached health check results
- `certificates` — issued mTLS client certificates
- `audit_log` — tamper-evident audit trail
- `azure_sso_config` — Azure AD SSO configuration

**Data Retention:**
- Operational data (health, patches, jobs): 30 days
- Audit logs: 6 months

### 4. React + TypeScript SPA

**Responsibility:** User-facing web interface.

**Pages:**
1. Dashboard — fleet overview, compliance %, health summary, upcoming windows, root CA download
2. Hosts — filterable host list by group, status, OS
3. Host Detail — system info, packages, patches, jobs, maintenance window config, host cert download
4. Patch Deployment — select hosts, review patches, deploy (queue or immediate)
5. Jobs — real-time job monitoring with WebSocket updates
6. Maintenance Windows — per-device recurring/one-time schedule management
7. Groups — manage static groups, assign hosts and operators
8. Reports — generate/export compliance, patch history, vulnerability, audit (CSV/PDF)
9. Users — local account management, MFA setup, group assignments
10. Certificates — view/manage internal CA, issue/renew client certs
11. Settings — system config, Azure SSO, polling intervals

### 5. Internal CA

**Responsibility:** mTLS certificate management for agent communication.

- Runs on the same Patch Manager host
- Issues client certificates for mTLS communication with agents
- Manages certificate renewal
- Root CA certificate downloadable from dashboard for manual distribution
- Host-specific mTLS certificates downloadable from host detail page
- No automated distribution to clients — server administrators handle this manually

## Data Flow

### Host Registration Flow
```
1. Admin enters FQDN/IP → Axum validates & resolves FQDN
2. Axum stores host in PostgreSQL
3. Worker picks up new host → initial health check via mTLS
4. Health result stored in PostgreSQL → visible in dashboard
```

### Auto-Discovery Flow
```
1. Admin triggers CIDR scan → Axum sends request to Worker
2. Worker scans subnet for agents on port 12443
3. Discovered agents reported back → Admin selects which to register
4. Selected hosts stored in PostgreSQL
```

### Patch Deployment Flow (Queued)
```
1. Operator selects hosts + patches → chooses "Queue for next window"
2. Axum creates patch job in PostgreSQL (status: queued)
3. When maintenance window opens → Worker triggers patch operations on agents
4. Worker monitors async job status via agent API
5. Results stored in PostgreSQL → WebSocket relay pushes updates to browser
6. Failed jobs auto-retried once if still within window
```

### Patch Deployment Flow (Immediate)
```
1. Operator selects hosts + patches → chooses "Apply Now"
2. Axum creates patch job in PostgreSQL (status: pending)
3. Worker immediately triggers patch operations on agents
4. Same monitoring and retry logic as queued flow
```

### Health/Patch Polling Flow
```
1. Worker polls each agent on schedule (5 min health, 30 min patches)
2. Results cached in PostgreSQL
3. Unhealthy agents marked with visual alerts in dashboard
4. On-demand refresh: operator clicks refresh → Worker queries agent immediately
```

## Technology Stack

| Layer | Technology | Version/Notes |
|-------|-----------|---------------|
| Backend | Rust + Axum | Tokio async runtime, Tower middleware |
| Database | PostgreSQL | SQLx for type-safe queries, migrations via sqlx-cli |
| Frontend | React + TypeScript | Vite build tooling |
| UI Components | MUI (Material UI) | Enterprise dashboard components, dark mode, theming |
| WebSocket | Axum native WebSocket | Agent → Manager → Browser relay |
| Auth (Local) | Argon2 password hashing + TOTP/WebAuthn | MFA enforcement |
| Auth (SSO) | OAuth2/OIDC via Azure AD | Optional, with Azure MFA |
| Session | JWT (access) + PostgreSQL (refresh) | 15 min access, 1 hr refresh |
| mTLS Client | Rustls + client certs | TLS 1.3 only |
| Internal CA | Rustls/RCGen | Certificate issuance and renewal |
| Email | Lettre (Rust email crate) | Optional, disabled by default |
| PDF Export | Rust PDF generation crate | Compliance and audit reports |
| CSV Export | Rust CSV crate | Data export for all report types |
| Service Management | systemd | Ubuntu 24.04 |
| Static Files | Axum built-in static file serving | React SPA served directly |

## Security Architecture

### Authentication
- **Local accounts:** Argon2-hashed passwords + TOTP or WebAuthn for MFA
- **Azure SSO:** OAuth2/OIDC flow with Azure AD, using Azure's built-in MFA
- **Session tokens:** Short-lived JWT (15 min) for API access, server-side refresh tokens (1 hr inactivity timeout)
- **Refresh token revocation:** Stored in PostgreSQL, can be immediately revoked for forced logout

### Authorization (RBAC)
- **Admin:** Full access to all resources and settings
- **Operator:** Can add/remove clients, manage schedules and patches only for devices in their group memberships
- **Group scoping:** Operators can only interact with hosts in their assigned groups
- **Ungrouped hosts:** Accessible by any operator or admin

### Agent Communication
- **mTLS:** Client certificate authentication for all agent communication
- **TLS 1.3 only:** No older TLS versions
- **Internal CA:** Patch Manager manages CA, issues and renews client certificates
- **Manual distribution:** Server administrators manually install certs on managed clients

### Data Protection
- **Encryption at rest:** LUKS full-disk encryption (infrastructure-managed)
- **Encryption in transit:** TLS 1.3 for all connections (agent and web UI)
- **Audit log integrity:** Tamper-evident logging (hash chaining)
- **Password storage:** Argon2 with salt

### Compliance
- **HIPAA:** Audit controls, access controls, integrity controls, transmission security, automatic logoff
- **PCI-DSS:** Vulnerability management (core function), access restrictions, user identification, audit tracking, data protection

## Deployment Architecture

```
┌─────────────────────────────────────────┐
│        Patch Manager Host (Ubuntu 24.04)  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  systemd: patch-manager-web         │  │
│  │  (Axum web server + static files)   │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  systemd: patch-manager-worker      │  │
│  │  (Background polling + jobs)        │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  PostgreSQL                         │  │
│  │  (Database)                          │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  Internal CA                         │  │
│  │  (Certificate management)            │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  LUKS (Full-disk encryption)         │  │
│  │  (Infrastructure-managed)            │  │
│  └─────────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

- Two systemd services: `patch-manager-web` and `patch-manager-worker`
- PostgreSQL runs on the same host
- Internal CA runs on the same host
- LUKS full-disk encryption managed by infrastructure
- No Docker/LXC — bare metal/VM deployment
- Internal network only — no public internet exposure

## Scalability

- **Single-instance design:** Supports 500 typical hosts, up to 2,500
- **Manual horizontal scaling:** Divide clients between multiple Patch Manager hosts if needed
- **Connection pooling:** Axum handles thousands of concurrent connections with Tokio
- **Background worker:** Independent scaling of polling/jobs from web serving
- **Database:** PostgreSQL handles the workload easily on a single host
- **No automatic clustering or load balancing required**

## Integration Points

**Upstream Dependency:** [Linux Patch API](https://gitea.moon-dragon.us/echo/linux_patch_api)

| Integration | Protocol | Direction | Purpose |
|-------------|----------|-----------|----------|
| Agent REST API | HTTPS/mTLS (TLS 1.3) | Manager → Agent | Queries, patch operations |
| Agent WebSocket | WSS/mTLS | Agent → Manager | Real-time job status streaming |
| Azure AD | HTTPS/OAuth2 | Manager → Azure | SSO authentication (optional) |

**API Endpoints Used:**
- `GET /api/v1/health` — Agent health checks
- `GET /api/v1/system/info` — Host system information
- `GET /api/v1/packages` — List installed packages
- `GET /api/v1/patches` — List available patches
- `POST /api/v1/patches/apply` — Apply patches
- `PUT /api/v1/packages/{name}` — Update specific package
- `DELETE /api/v1/packages/{name}` — Remove package
- `POST /api/v1/packages` — Install packages
- `GET /api/v1/jobs` — List jobs
- `GET /api/v1/jobs/{id}` — Get job status
- `POST /api/v1/jobs/{id}/rollback` — Rollback a job
- `POST /api/v1/system/reboot` — Reboot host
- `WebSocket /api/v1/ws/jobs` — Real-time job status

## Monitoring and Observability

- **Application logging:** Structured JSON logging (tracing crate)
- **Log levels:** Configurable at runtime (DEBUG, INFO, WARN, ERROR)
- **Health endpoint:** `GET /api/v1/health` on the Patch Manager's own API for infrastructure monitoring
- **Dashboard alerts:** Visual indicators for unhealthy/unreachable agents (red/yellow status)
- **Audit logging:** All significant events logged to PostgreSQL with tamper-evident hash chaining
- **No external monitoring integration required** (dashboard-only alerts)
