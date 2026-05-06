# Target Host for Service Health Checks

## Overview
Add `target_host_id` field to service health checks, allowing a check configured on Host A to query a service on Host B's agent. Useful for redundant services running on multiple machines.

**Design:** `target_host_id` is nullable. When NULL (default), behavior unchanged — check queries its own host's agent. When set, the service check queries the target host's agent instead. Only applies to service checks; HTTP checks already specify a full URL.

## Implementation Checklist

### 1. Database Migration
- [ ] Create `migrations/011_health_check_target_host.sql`
- [ ] Add `target_host_id UUID REFERENCES hosts(id) ON DELETE SET NULL` column
- [ ] Add partial index on `target_host_id` where NOT NULL

### 2. Backend Models (`crates/pm-core/src/models.rs`)
- [ ] Add `target_host_id: Option<Uuid>` to `HealthCheck` struct
- [ ] Add `target_host_id: Option<Uuid>` to `CreateHealthCheckRequest`
- [ ] Add `target_host_id: Option<Uuid>` to `UpdateHealthCheckRequest`
- [ ] Add `target_host_id` to all HealthCheck SELECT queries

### 3. API Routes (`crates/pm-web/src/routes/health_checks.rs`)
- [ ] Create: add `target_host_id` to INSERT, validate target host exists + is healthy
- [ ] Update: add `target_host_id` to COALESCE UPDATE
- [ ] List/Get: add `target_host_id` to SELECT columns
- [ ] Test endpoint (`run_service_check`): when `target_host_id` is Some, query that host's IP/port
- [ ] Audit log: include `target_host_id` in audit JSON

### 4. Health Check Poller (`crates/pm-worker/src/health_check_poller.rs`)
- [ ] Add `target_host_id: Option<Uuid>` to `HealthCheckRow`
- [ ] Modify SQL: LEFT JOIN hosts th ON th.id = hc.target_host_id, use COALESCE(th.ip_address, h.ip_address) and COALESCE(th.agent_port, h.agent_port)
- [ ] Add `target_ip_address` and `target_agent_port` fields to HealthCheckRow
- [ ] `run_service_check`: use target host IP/port when available
- [ ] `check_host_health_checks`: no change needed (results count toward owning host)

### 5. Frontend Types (`frontend/src/types/index.ts`)
- [ ] Add `target_host_id?: string` to `HealthCheck`
- [ ] Add `target_host_id?: string` to `CreateHealthCheckRequest`
- [ ] Add `target_host_id?: string` to `UpdateHealthCheckRequest`

### 6. Frontend Form (`frontend/src/pages/HostDetailPage.tsx`)
- [ ] Add `target_host_id: string` to `HealthCheckFormValues`
- [ ] Add `target_host_id: ''` to `defaultHealthCheckForm`
- [ ] Add host selector dropdown in `HealthCheckFormDialog` (visible when check_type === 'service')
- [ ] Fetch hosts list for dropdown (use hostsApi.list or a dedicated endpoint)
- [ ] `handleHcCreateSubmit`: include `target_host_id: values.target_host_id || undefined`
- [ ] `handleHcEditClick`: map `check.target_host_id ?? ''` to form
- [ ] `handleHcEditSubmit`: include `target_host_id` in UpdateHealthCheckRequest
- [ ] Display target host in health checks table Target column

### 7. Build, Test, Deploy
- [ ] Run `cargo fmt --all` + `cargo clippy` + `cargo test`
- [ ] Run frontend build + ESLint + tsc
- [ ] Commit and push through CI pipeline
- [ ] Tag release, build .deb, deploy to dev

## Design Decisions
- `target_host_id` is nullable — NULL = check own host (backward compatible)
- FK with ON DELETE SET NULL — if target host deleted, revert to default
- Only applies to service checks (HTTP checks already have full URL)
- Health gate: results count toward the owning host, not the target host
- No RBAC required for target host — only requirement: target host exists in manager and is currently healthy
