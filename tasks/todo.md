# Health Check Configuration for Hosts — Feature Plan

## Overview
Each host can have 1-5 health checks. During maintenance windows, all checks must be healthy before patch execution. Health checks are also continuously polled for dashboard status.

## Design Decisions (confirmed with Kelly)
- Health check config lives in manager DB, manager controls everything
- Agent is just an action endpoint (no health check logic on agent)
- Admins and operators can manage (operators need matching group)
- Per-host 1:1 (not shareable templates)
- Both continuous polling AND must be healthy before patch execution
- Service health: query agent `GET /api/v1/system/services/{name}`, check `healthy` field
- HTTP health: manager makes direct HTTP request, substring match in response body
- Retry failed checks at 5-minute intervals until maintenance window closes
- 10-second check timeout; no response = failed
- Order doesn't matter
- Basic auth password: encrypted in DB with per-install app key
- Health check poll interval: 5 minutes
- Result retention: 4 days (time-based)

## linux_patch_api Agent Endpoints (Reference)

### GET /api/v1/system/services/{name}
Returns service status for health check Type 1 (service). Added in commit 8b6d9ed.

**Response:** `ApiResponse<ServiceStatusData>`
```json
{
  "success": true,
  "data": {
    "name": "nginx",
    "display_name": "A high performance web server",
    "active_state": "active",
    "sub_state": "running",
    "load_state": "loaded",
    "enabled_state": "enabled",
    "main_pid": 1234,
    "healthy": true
  }
}
```

**Health determination:** The agent `healthy` field is authoritative. Manager uses this boolean directly.

**Error responses:** 400 (invalid name), 404 (not found → unhealthy), 500 (error → unhealthy)

### GET /api/v1/health
Basic agent health. Returns `{"status": "healthy"}`. Used for connectivity checks, not host health checks.

---

## Phase 1: Database Schema

### New table: `host_health_checks`
```sql
CREATE TABLE host_health_checks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    check_type      VARCHAR(20) NOT NULL CHECK (check_type IN ('service', 'http')),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    -- Service check fields
    service_name    VARCHAR(200),
    -- HTTP check fields
    url             TEXT,
    expected_body   VARCHAR(500),
    ignore_cert_errors BOOLEAN DEFAULT true,
    basic_auth_user VARCHAR(100),
    basic_auth_pass_encrypted BYTEA,  -- AES-256-GCM encrypted with per-install key
    basic_auth_pass_nonce BYTEA,      -- nonce for AES-GCM
    -- Metadata
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_service_check CHECK (
        (check_type = 'service' AND service_name IS NOT NULL AND url IS NULL)
        OR
        (check_type = 'http' AND url IS NOT NULL AND expected_body IS NOT NULL AND service_name IS NULL)
    )
);

CREATE INDEX idx_health_checks_host ON host_health_checks (host_id);
```

### New table: `host_health_check_results`
```sql
CREATE TABLE host_health_check_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_id    UUID NOT NULL REFERENCES host_health_checks(id) ON DELETE CASCADE,
    healthy     BOOLEAN NOT NULL,
    detail      TEXT,
    latency_ms  INTEGER,
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_health_results_check ON host_health_check_results (check_id, checked_at DESC);
```

### Encryption key storage
- Per-install app key stored at `/etc/patch-manager/keys/health-check.key`
- 256-bit random key generated on first startup if not present
- File permissions: 0600, owned by patch-manager user
- Used for AES-256-GCM encryption of basic_auth_pass

- [ ] Create migration 007_health_checks.sql
- [ ] Add models to pm-core/src/models.rs
- [ ] Add encryption utility to pm-core
- [ ] Verify migration runs on dev LXC

---

## Phase 2: Backend API Routes

### Endpoints
- `GET    /api/v1/hosts/{id}/health-checks` — list health checks for host (RBAC scoped)
- `POST   /api/v1/hosts/{id}/health-checks` — create health check (max 5 per host)
- `PUT    /api/v1/hosts/{id}/health-checks/{check_id}` — update health check
- `DELETE /api/v1/hosts/{id}/health-checks/{check_id}` — delete health check
- `POST   /api/v1/hosts/{id}/health-checks/{check_id}/test` — run check immediately, return result

### Request/Response types
```rust
struct CreateHealthCheckRequest {
    name: String,
    check_type: String,  // "service" or "http"
    service_name: Option<String>,
    url: Option<String>,
    expected_body: Option<String>,
    ignore_cert_errors: Option<bool>,
    basic_auth_user: Option<String>,
    basic_auth_pass: Option<String>,  // plaintext in request, encrypted before storage
}

struct HealthCheck {
    id: Uuid,
    host_id: Uuid,
    name: String,
    check_type: String,
    enabled: bool,
    service_name: Option<String>,
    url: Option<String>,
    expected_body: Option<String>,
    ignore_cert_errors: bool,
    basic_auth_user: Option<String>,
    // basic_auth_pass NOT returned in responses
    last_result: Option<HealthCheckResult>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

struct HealthCheckResult {
    healthy: bool,
    detail: Option<String>,
    latency_ms: Option<i32>,
    checked_at: DateTime<Utc>,
}
```

- [ ] Add routes to pm-web/src/routes/ (new health_checks.rs)
- [ ] Add CRUD operations
- [ ] Add RBAC enforcement (admin all, operator matching group)
- [ ] Add max-5-per-host validation
- [ ] Add /test endpoint that runs check immediately
- [ ] Add audit logging for create/update/delete
- [ ] Add encryption/decryption for basic_auth_pass

---

## Phase 3: Worker Health Check Engine

### Continuous Polling
- New task in pm-worker: `health_check_poller`
- Polls all enabled health checks every 5 minutes
- For service checks: call agent `GET /api/v1/system/services/{name}` via mTLS, check `healthy` field
- For HTTP checks: make direct HTTP(S) request from manager, check status code + substring match
- Store results in `host_health_check_results`
- Prune results older than 4 days

### Pre-Patch Execution Gate
- When a patch job is about to execute on a host:
  1. Check if host has any enabled health checks
  2. If yes, verify all are currently healthy (from latest poll result)
  3. If any are unhealthy:
     - Wait and retry at 5-minute intervals
     - Continue until maintenance window closes
     - If window closes with failed checks, mark job host as failed with detail
  4. If all healthy, proceed with patch execution

### HTTP Check Implementation
- Use reqwest with:
  - 10-second timeout
  - Accept invalid certs (ignore_cert_errors)
  - Optional basic auth header (decrypt from DB)
  - Check response body contains expected_body substring
- Return healthy=true if match, false otherwise

- [ ] Add health_check_poller module to pm-worker
- [ ] Implement service check via AgentClient
- [ ] Implement HTTP check via reqwest
- [ ] Add pre-patch execution gate to job_executor
- [ ] Add retry loop with 5-minute intervals
- [ ] Add maintenance window expiry check
- [ ] Add health check config to WorkerConfig (poll interval)
- [ ] Add result pruning (4-day retention)

---

## Phase 4: Frontend UI

### Host Detail Page
- Add "Health Checks" section below host info
- List current health checks with status indicators
- Add/Edit/Delete health check dialogs
- "Test" button to run check immediately and show result
- Visual indicator: green check = healthy, red X = unhealthy, gray = unknown

### Hosts Page
- Add health check summary column or indicator
- Show aggregate status: all healthy / some unhealthy / no checks configured

### Deploy Page
- Show health check status in host selection table
- Warn if any selected hosts have unhealthy checks

### Job Detail
- Show health check gate status when job is waiting for healthy checks
- Display which checks are passing/failing

- [ ] Add HealthCheck types to frontend/src/types/index.ts
- [ ] Add health check API calls to frontend/src/api/client.ts
- [ ] Add Health Checks section to HostDetailPage.tsx
- [ ] Add health check status to HostsPage.tsx
- [ ] Add health check indicators to PatchDeploymentPage.tsx
- [ ] Add health check gate status to JobsPage.tsx detail view

---

## Phase 5: Integration & Testing
- [ ] Build and deploy to dev LXC
- [ ] Test service health check against dev LXC agent
- [ ] Test HTTP health check against internal services
- [ ] Test pre-patch gate: deploy with failing check, verify retry behavior
- [ ] Test maintenance window expiry with failing checks
- [ ] Test RBAC: operator can only manage checks in their group
- [ ] Test max 5 checks per host enforcement
- [ ] Test basic auth encryption/decryption
- [ ] Push to Gitea

---

## Resolved Items
- ~~Basic auth password storage~~ → Encrypted in DB with per-install app key (AES-256-GCM)
- ~~Health check poll interval~~ → 5 minutes
- ~~Result retention~~ → 4 days (time-based)
