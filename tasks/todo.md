# Linux Patch Manager — Implementation Plan

## Project Structure

```
linux_patch_manager/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── pm-web/                   # Axum web server binary crate
│   ├── pm-worker/                # Background worker binary crate
│   ├── pm-core/                  # Shared library: config, DB pool, models, errors, types
│   ├── pm-agent-client/          # mTLS HTTP client for agent communication
│   ├── pm-auth/                  # Auth: JWT (EdDSA), Argon2id, TOTP, WebAuthn, RBAC, Azure SSO
│   ├── pm-ca/                    # Internal CA: rcgen + rustls certificate management
│   └── pm-reports/               # PDF (printpdf + plotters) and CSV generation
├── migrations/                   # SQLx database migrations
│   ├── 001_initial_schema.sql
│   ├── 002_auth_system.sql
│   ├── 003_host_management.sql
│   ├── 004_jobs_and_scheduling.sql
│   ├── 005_audit_logging.sql
│   └── 006_system_config.sql
├── frontend/                      # React + TypeScript SPA
│   ├── src/
│   │   ├── api/                  # API client (axios/fetch)
│   │   ├── components/           # Shared MUI components
│   │   ├── pages/                # 11 page components
│   │   ├── hooks/                # Custom React hooks
│   │   ├── store/                # State management (zustand or context)
│   │   ├── theme/                # MUI theme (light + dark)
│   │   ├── types/                # TypeScript interfaces
│   │   └── utils/                # Utilities
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── index.html
├── config/
│   └── config.example.toml       # Example configuration
├── systemd/
│   ├── patch-manager-web.service
│   └── patch-manager-worker.service
├── docs/
│   └── runbooks/
│       └── restore.md            # Backup/restore runbook
├── scripts/
│   ├── setup.sh                  # Initial host setup script
│   └── build-frontend.sh         # Frontend build script
├── SPEC.md
├── REQUIREMENTS.md
├── ARCHITECTURE.md
├── README.md
└── .gitignore
```

---

## Milestones

Each milestone produces a **testable vertical slice** — backend + frontend + database working together.

### M1: Project Scaffolding + Database Schema + Core Infrastructure
**Goal:** Runnable workspace with DB, config, logging, error handling.

- [x] Initialize Rust workspace with 7 crates (pm-web, pm-worker, pm-core, pm-agent-client, pm-auth, pm-ca, pm-reports)
- [x] Initialize React + TypeScript + Vite + MUI frontend project
- [x] Create `config.example.toml` with all configuration keys
- [x] Implement `pm-core::config` — TOML config loading + env overrides (`PATCH_MANAGER__SECTION__KEY`)
- [x] Implement `pm-core::db` — SQLx PgPool initialization, connection from config
- [x] Implement `pm-core::error` — Unified error type with API error envelope (`error.code`, `error.message`, `error.request_id`, `error.details`)
- [x] Implement `pm-core::request_id` — ULID generation + `X-Request-Id` header middleware
- [x] Implement `pm-core::logging` — `tracing` + `tracing-subscriber` JSON formatter, configurable log levels
- [x] Create initial database migrations (001_initial_schema.sql): `hosts`, `groups`, `host_groups`, `users`, `user_groups`, `refresh_tokens`, `maintenance_windows`, `patch_jobs`, `patch_job_hosts`, `host_patch_data`, `host_health_data`, `certificates`, `audit_log`, `azure_sso_config`, `system_config`, `worker_heartbeat`, `discovery_results`
- [x] Implement `pm-web` binary: Axum app skeleton, static file serving placeholder, `/status/health` endpoint
- [x] Implement `pm-worker` binary: Tokio runtime skeleton, DB connection, worker heartbeat writer (30s interval)
- [x] Implement `sqlx::migrate!` embedded migrations in pm-web, advisory lock for single-writer
- [x] Worker waits for expected schema version before accepting work
- [x] Create `systemd/patch-manager-web.service` and `systemd/patch-manager-worker.service` unit files
- [x] Create `scripts/setup.sh` for initial host setup
- [x] Create `scripts/build-frontend.sh`
- [x] Verify: both services start, `/status/health` returns 200, worker heartbeat updates

### M2: Authentication & Authorization + Frontend Shell
**Goal:** Users can log in with MFA, JWT auth works, RBAC middleware enforces roles.

- [x] Implement `pm-auth::password` — Argon2id hashing with calibrated parameters (`m_cost=65536`, `t_cost=3`, `p_cost=1`)
- [x] Implement `pm-auth::jwt` — EdDSA/Ed25519 JWT issuance and validation, 15-min TTL, 90-day key rotation with 24-hour overlap
- [x] Implement `pm-auth::refresh` — Opaque 256-bit refresh tokens, hashed storage in `refresh_tokens`, 1-hour sliding inactivity timeout, rotation on use
- [x] Implement `pm-auth::mfa_totp` — TOTP setup, verify, QR code generation
- [x] Implement `pm-auth::mfa_webauthn` — WebAuthn registration and authentication
- [x] Implement `pm-auth::rbac` — Admin/Operator role middleware, group-scoped access enforcement
- [x] Implement `pm-auth::session` — Login flow (password → MFA → access+refresh tokens), logout (revoke refresh), force-revoke
- [x] Implement `pm-web` auth routes: `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`, MFA setup endpoints
- [x] Implement IP whitelist middleware on all connection points
- [x] Frontend: App shell with React Router, MUI theme (light + dark), auth context, login page, MFA setup page
- [x] Frontend: API client with JWT interceptors (auto-refresh), 401 redirect to login
- [x] Create seed migration: default admin account
- [x] Verify: login with MFA, JWT validation, refresh token rotation, RBAC blocks unauthorized access, IP whitelist blocks unknown IPs

### M3: Host Management + Groups + Frontend Pages
**Goal:** Full host CRUD, group management, auto-discovery.

- [x] Implement host CRUD routes: `GET/POST /api/v1/hosts`, `GET/DELETE /api/v1/hosts/{id}`
- [x] Implement FQDN resolution on host add (resolve to IP at registration time)
- [x] Implement group CRUD routes: `GET/POST /api/v1/groups`, `GET/DELETE /api/v1/hosts/{id}/groups`
- [x] Implement host ↔ group and user ↔ group membership management
- [x] Implement RBAC scoping: operators can only see/manage hosts in their groups
- [x] Implement auto-discovery: `POST /api/v1/discovery/cidr` → worker scans CIDR, bounded concurrency (128), TCP+TLS probe (1.5s timeout), progress tracking, cancel action
- [x] Implement discovery results table and review flow
- [x] Implement host removal with audit logging
- [x] Frontend: Hosts page (filterable list by group, status, OS)
- [x] Frontend: Host Detail page (system info, packages, patches, jobs, maintenance window config)
- [x] Frontend: Groups page (manage groups, assign hosts and operators)
- [x] Frontend: Users page (local account management, MFA setup, group assignments)
- [x] Verify: add/remove hosts, group assignments, RBAC enforcement, CIDR scan with progress

### M4: Agent Communication Layer + Dashboard
**Goal:** mTLS client works, health/patch polling operational, dashboard shows fleet status.

- [x] Implement `pm-agent-client` — Rustls-based mTLS HTTP client with client certificate, TLS 1.3 only
- [x] Implement agent API calls: `GET /api/v1/health`, `GET /api/v1/system/info`, `GET /api/v1/packages`, `GET /api/v1/patches`
- [x] Implement worker health poller: 5-minute intervals, bounded concurrency (64 semaphore), update `host_health_data`
- [x] Implement worker patch data poller: 30-minute intervals, bounded concurrency, update `host_patch_data`
- [x] Implement on-demand refresh: `POST /api/v1/hosts/{id}/refresh` → `NOTIFY refresh_requested` → worker queries immediately
- [x] Implement host health status tracking: healthy/degraded/unreachable with timestamps
- [x] Implement dashboard API: `GET /api/v1/status/fleet` (authenticated, fleet aggregates)
- [x] Frontend: Dashboard page — compliance %, health summary, pending patches, upcoming windows, root CA download icon
- [x] Frontend: Real-time health status indicators (green/yellow/red) on host lists
- [x] Verify: polling works, dashboard shows live fleet data, on-demand refresh works, visual alerts for unhealthy agents

### M5: Patch Deployment & Job Management + Frontend Pages
**Goal:** Full patch lifecycle — queue, immediate, retry, rollback, job monitoring.

- [x] Implement job creation: `POST /api/v1/jobs` (queue for window or apply now)
- [x] Implement `patch_jobs` and `patch_job_hosts` row creation
- [x] Implement `NOTIFY job_enqueued` for immediate-apply wake
- [x] Implement worker job executor: call agent `POST /api/v1/patches/apply`, track async job IDs
- [x] Implement worker retry engine: exponential backoff (1min, 5min, 30min), 3 retries max
- [x] Implement patch job auto-retry within maintenance window (1 retry)
- [x] Implement batch partial failure handling: auto-retry once, then report
- [x] Implement rollback: `POST /api/v1/jobs/{id}/rollback` → worker calls agent rollback endpoint
- [x] Implement job status tracking: poll agent `GET /api/v1/jobs/{id}` for running jobs
- [x] Implement job listing/detail API: `GET /api/v1/jobs`, `GET /api/v1/jobs/{id}`
- [x] Frontend: Patch Deployment page (select hosts → review patches → queue or apply now)
- [x] Frontend: Jobs page (job list, per-host status, rollback action)
- [ ] Verify: queued job waits for window, immediate job runs now, retry logic works, rollback works, batch partial failures reported

### M6: Maintenance Windows & Scheduling + Frontend Page
**Goal:** Per-device recurring and one-time maintenance windows, auto-execution at window open.

- [x] Implement maintenance window CRUD: `GET/POST/PUT/DELETE /api/v1/hosts/{id}/maintenance-windows`
- [x] Implement recurring schedule logic: daily, weekly, monthly (cron-like evaluation)
- [x] Implement one-time window support
- [x] Implement worker job scheduler: detect window openings, dispatch queued jobs
- [x] Implement window-open event triggering job execution
- [x] Frontend: Maintenance Windows page (per-device schedule management)
- [x] Frontend: Maintenance window config on Host Detail page
- [ ] Verify: create recurring/one-time windows, queued jobs execute at window open, window expiration stops execution

### M7: WebSocket Relay (Real-Time Job Status)
**Goal:** Browser receives live job updates via WebSocket.

- [x] Implement WS ticket endpoint: `POST /api/v1/ws/ticket` (single-use, 60s expiry, JWT-authenticated)
- [x] Implement WebSocket relay: `WS /api/v1/ws/jobs?ticket=...` → authenticated browser connection
- [x] Implement agent WebSocket consumption: worker subscribes to agent `WS /api/v1/ws/jobs` for running jobs
- [x] Implement event multiplexing: agent WS events → PostgreSQL update → browser WS push
- [x] Frontend: WebSocket client hook with auto-reconnect and ticket refresh
- [x] Frontend: Live job progress updates on Jobs page
- [x] Verify: open job in browser, see real-time progress updates, WS ticket expires correctly

### M8: Internal CA + Certificate Management + Frontend Page
**Goal:** CA issues/renews certs, download links work.

- [ ] Implement `pm-ca` — CA initialization (root key + cert generation), stored at `/etc/patch-manager/ca/` with 0600 permissions
- [ ] Implement client certificate issuance for mTLS (per-host certs)
- [ ] Implement certificate renewal flow
- [ ] Implement certificate revocation (mark revoked in `certificates` table, re-issue replacement)
- [ ] Implement download endpoints: `GET /api/v1/ca/root.crt`, `GET /api/v1/hosts/{id}/client.crt`
- [ ] Implement Web UI TLS certificate: self-signed from internal CA (default) or operator-supplied cert/key
- [ ] Frontend: Certificates page (view/manage CA, issue/renew certs, view expiry)
- [ ] Frontend: Root CA download icon on Dashboard
- [ ] Frontend: Host-specific cert download icon on Host Detail page
- [ ] Verify: CA generates certs, downloads work, TLS cert strategy switchable

### M9: Reporting (CSV + PDF with Charts) + Frontend Page
**Goal:** All 4 report types exportable as CSV and PDF.

- [ ] Implement `pm-reports::csv` — CSV generation for all report types
- [ ] Implement `pm-reports::pdf` — PDF generation with `printpdf` + `plotters` charts
- [ ] Implement compliance report: % hosts fully patched by group/fleet, trend charts
- [ ] Implement patch history report: operations per host/group
- [ ] Implement vulnerability exposure report: hosts with pending CVEs
- [ ] Implement audit trail report: who did what when
- [ ] Implement report API: `GET /api/v1/reports/compliance`, `patch-history`, `vulnerability`, `audit` with `?format=csv|pdf`
- [ ] Frontend: Reports page (select type, filters, generate, download)
- [ ] Verify: all 4 reports generate as CSV and PDF, PDFs include charts

### M10: Settings Page (Azure SSO, SMTP, TLS, IP Whitelist) + Frontend Page
**Goal:** All runtime configuration manageable from the UI.

- [ ] Implement `system_config` table CRUD API
- [ ] Implement Azure SSO configuration: tenant ID, client ID/secret, redirect URI, scopes
- [ ] Implement "Test Connection" action for Azure SSO (round-trip against Azure AD, report success/failure without enabling)
- [ ] Implement SMTP configuration: host, port, auth mode, username/password, TLS mode, from-address
- [ ] Implement "Send Test Email" action for SMTP
- [ ] Implement polling interval tuning (health, patch) in Settings
- [ ] Implement Web UI TLS certificate strategy selection (internal CA vs. operator-supplied)
- [ ] Implement IP whitelist management in Settings
- [ ] Implement Azure SSO OAuth2/OIDC Authorization Code flow with PKCE
- [ ] Frontend: Settings page with all configuration sections and test actions
- [ ] Verify: Azure SSO test connection works, test email sends, TLS strategy switches, IP whitelist updates take effect

### M11: Email Notifications + Audit Logging Hardening
**Goal:** Optional email works, audit logs are tamper-evident.

- [ ] Implement email notifier in worker (Lettre crate, optional/disabled by default)
- [ ] Implement email templates: patch failure, job completion, maintenance window reminders
- [ ] Implement audit log hash chaining: `prev_hash` + `row_hash` on every insert
- [ ] Implement periodic audit integrity verification job
- [ ] Implement on-demand audit integrity verification from UI
- [ ] Implement audit log for all configuration changes (Azure SSO, SMTP, IP whitelist, TLS cert strategy)
- [ ] Implement audit log for certificate operations (issue, renew, download, revoke)
- [ ] Frontend: Email notification settings integration in Settings page
- [ ] Frontend: Audit integrity verification action in Reports/Users area
- [ ] Verify: email sends on failure, audit chain is intact, tampering detected by verification

### M12: Deployment Packaging, Backup/DR, Integration Testing
**Goal:** Production-ready deployment with documented runbooks.

- [ ] Create `docs/runbooks/restore.md` — backup/restore procedure
- [ ] Implement nightly `pg_dump` script to `/var/backups/patch-manager/`
- [ ] Implement CA material backup inclusion
- [ ] Implement `/etc/patch-manager/` config backup (excluding secrets unless encrypted destination)
- [ ] Create `scripts/setup.sh` — full host setup (install deps, create service user, set permissions, initialize DB)
- [ ] Finalize systemd unit files with proper dependencies, restart policies, logging
- [ ] End-to-end integration tests: full patch lifecycle across multiple agents
- [ ] Performance test: verify 500-host polling, dashboard load < 5s, CIDR scan < 10s for /22
- [ ] Security review: TLS 1.3 enforcement, IP whitelist, RBAC, audit chain integrity
- [ ] Compliance mapping verification: HIPAA and PCI-DSS controls documented and testable
- [ ] Verify: backup/restore works, RPO 24h / RTO 4h achievable, all NFRs met

---

## Dependency Graph

```
M1 (scaffolding)
 ├──> M2 (auth)
 │      ├──> M3 (hosts/groups)
 │      │      ├──> M4 (agent comm + dashboard)
 │      │      │      ├──> M5 (patch deployment + jobs)
 │      │      │      │      ├──> M6 (maintenance windows)
 │      │      │      │      │      └──> M7 (websocket relay)
 │      │      │      │      └──> M7 (websocket relay)
 │      │      │      └──> M8 (CA + certs)
 │      │      └──> M8 (CA + certs)
 │      └──> M10 (settings)
 ├──> M8 (CA + certs) [needed by M4 for mTLS]
 └──> M9 (reports)

M10 (settings) ──> M11 (email + audit hardening)
M11 ──> M12 (deployment + testing)
```

**Critical path:** M1 → M2 → M3 → M4 → M5 → M6 → M7 → M11 → M12

**Note:** M8 (CA) should be started early (after M1) since M4 (agent communication) requires mTLS client certs.

---

## Estimated Effort

| Milestone | Backend | Frontend | DB | Total |
|-----------|----------|----------|-----|-------|
| M1 | 3 days | 1 day | 1 day | 5 days |
| M2 | 4 days | 2 days | 0.5 day | 6.5 days |
| M3 | 3 days | 3 days | 0.5 day | 6.5 days |
| M4 | 3 days | 2 days | 0.5 day | 5.5 days |
| M5 | 4 days | 2 days | 0.5 day | 6.5 days |
| M6 | 2 days | 1.5 days | 0.5 day | 4 days |
| M7 | 2 days | 1.5 days | 0 | 3.5 days |
| M8 | 2 days | 1.5 days | 0 | 3.5 days |
| M9 | 3 days | 1.5 days | 0 | 4.5 days |
| M10 | 3 days | 2 days | 0.5 day | 5.5 days |
| M11 | 2 days | 1 day | 0.5 day | 3.5 days |
| M12 | 2 days | 0.5 days | 0.5 day | 3 days |
| **Total** | **33 days** | **19.5 days** | **5 days** | **~57.5 days** |

With a single developer: ~12 weeks. With parallel backend/frontend: ~7-8 weeks.

---

## Review Notes

- [ ] Kelly to review and approve this plan before implementation begins
- [ ] Confirm milestone ordering and priorities
- [ ] Confirm whether M8 (CA) should be pulled forward to support M4
- [ ] Confirm whether any milestones can be deferred to a later release
