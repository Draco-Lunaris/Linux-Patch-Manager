# SSO Implementation Fix Plan

## Issues Identified
1. **No SSO Login Button** — LoginPage.tsx missing "Sign in with Azure" button
2. **No SSO Callback Route** — App.tsx missing frontend route to handle SSO callback
3. **authStore No SSO Support** — authStore.ts has no method to store SSO tokens
4. **Backend Returns JSON Not Redirect** — azure_sso.rs callback returns JSON tokens instead of redirecting to frontend
5. **No SSO Session Cleanup** — sso_sessions DashMap has no expiry/cleanup task (memory leak)
6. **No JWT Signature Verification** — id_token decoded without verifying Azure AD signature

## Phases

### Phase 1: Backend SSO Fixes (Issues 4, 5) — COMPLETE ✅
- [x] 1a: Add SSO session cleanup task in main.rs (purge sessions older than 10 minutes)
- [x] 1b: Modify azure_sso.rs callback to redirect to frontend with tokens instead of returning JSON
- [x] 1c: Add `sso_callback_url` to SecurityConfig in config.rs with serde default
- [x] 1d: Update settings.rs to include sso_callback_url in settings response
- [x] 1e: Verify backend compiles with `cargo check`

### Phase 2: Frontend SSO Integration (Issues 1, 2, 3) — COMPLETE ✅
- [x] 2a: Add SSO callback page component (SsoCallbackPage.tsx)
- [x] 2b: Add SSO callback route to App.tsx (public route, no auth required)
- [x] 2c: Add "Sign in with Microsoft Azure" button to LoginPage.tsx
- [x] 2d: Add SSO-related types and API methods to frontend
- [x] 2e: Verify frontend builds with TypeScript compilation

### Phase 3: JWT Signature Verification (Issue 6) — COMPLETE ✅
- [x] 3a: Add JWKS client dependency to pm-web/Cargo.toml
- [x] 3b: Implement id_token signature verification in azure_sso.rs
- [x] 3c: Verify backend compiles with `cargo check`

### Phase 4: Integration Testing and Verification — COMPLETE ✅
- [x] 4a: Backend code review — all changes verified manually
- [x] 4b: Frontend TypeScript compilation — passes cleanly
- [x] 4c: SSO login flow reviewed end-to-end (backend redirect → frontend callback → auth store)
- [x] 4d: SSO session cleanup verified (10-minute expiry, 60-second purge interval)
- [x] 4e: Settings page SSO config unchanged (sso_callback_url added as read-only)
- [x] 4f: Lessons captured below

## Lessons Learned
- **SSO callback must redirect, not return JSON** — Browser OAuth2 flows require the backend to redirect to the frontend SPA, not return JSON tokens. The frontend must parse tokens from URL query parameters.
- **URLSearchParams.get() already decodes** — Don't double-decode with decodeURIComponent() when using URLSearchParams.
- **JWKS caching prevents rate-limiting** — Azure AD JWKS endpoint should be cached with TTL (1 hour) to avoid fetching on every SSO login.
- **tokio::sync::Mutex over std::sync::Mutex** — Axum handlers must be Send; std::sync::MutexGuard is not Send across await points.
- **DashMap session cleanup** — In-memory session stores (DashMap) need periodic cleanup tasks to prevent memory leaks. Pattern: tokio::spawn with interval + retain with time-based cutoff.

# Host Self-Enrollment Implementation Plan

## Phases

### Phase 1: Database & Core Models
- [x] 1a: Create SQL migration for `enrollment_requests` table
- [x] 1b: Define Rust data models for `EnrollmentRequest` in `pm-core`
- [x] 1c: Add DB interaction methods (insert, list, delete) in `pm-core`

### Phase 2: Client-Facing API (pm-web)
- [ ] 2a: Implement `POST /api/v1/enroll` to accept payloads and generate `polling_token`
- [ ] 2b: Implement `GET /api/v1/enroll/status/{token}` to return pending/approved (PKI) statuses
- [ ] 2c: Implement IP-based rate limiting for the `/enroll` endpoint

### Phase 3: Admin-Facing API (pm-web)
- [x] 3a: Implement `GET /api/v1/admin/enrollments` to list pending queue
- [x] 3b: Implement `POST /api/v1/admin/enrollments/{id}/approve` (generate PKI via `pm-ca`, migrate to `hosts` table)
- [x] 3c: Implement `DELETE /api/v1/admin/enrollments/{id}/deny` to purge request

### Phase 4: Background Workers (pm-worker)
- [x] 4a: Create a scheduled task to purge `enrollment_requests` older than 24 hours

### Phase 5: Frontend UI (pm-web/React)
- [x] 5a: Add enrollment API methods and types to frontend
- [x] 5b: Update `Hosts` view to include "Pending Enrollments" filter and visual badge
- [x] 5c: Render pending hosts in the table with highlight styling
- [x] 5d: Add Approve/Deny action buttons to pending host rows
- [x] 5e: Implement "merge/overwrite" interactive modal for `fqdn`/`ip_address` collisions on approval
