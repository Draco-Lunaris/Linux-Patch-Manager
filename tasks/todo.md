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

---

# WS Origin Allowlist — Implementation Plan (Issue #10)

Spec: `tasks/ws-origin-check-spec.md` (v0.1.0, awaiting sign-off)

## Issues Identified
1. **No Origin check on WS upgrade** — `crates/pm-web/src/routes/ws.rs` `ws_handler` does
   not inspect the `Origin` header, leaving the `/api/v1/ws/jobs` endpoint exposed to
   Cross-Site WebSocket Hijacking (CSWSH) if a ticket ever leaks via logs / `Referer` /
   browser history / support bundles.
2. **No `allowed_origins` config field** — `SecurityConfig` has no way to express the
   allowlist; defaults need to be derived from `sso_callback_url` to stay secure out
   of the box.
3. **No integration tests for ws.rs** — there is no `crates/pm-web/tests/` directory
   today, so the new behavior would land without automated coverage.

## Phases

### Phase 1: Config schema (Issue 2)
- [x] 1a: Add `allowed_origins: Vec<String>` to `SecurityConfig` in `crates/pm-core/src/config.rs`
- [x] 1b: Implement `default_allowed_origins()` that parses `sso_callback_url` to `scheme://host[:port]`
- [x] 1c: Emit `tracing::warn!` at startup if the derived allowlist ends up empty
- [x] 1d: Update `Default for AppConfig` to include the new field
- [x] 1e: Update `config/config.example.toml` with documented `allowed_origins` key

### Phase 2: Handler change (Issue 1)
- [x] 2a: Add `HeaderMap` extractor to `ws_handler`
- [x] 2b: Implement hand-rolled `Origin` parser (scheme, host, port) with default-port normalization
- [x] 2c: Implement allowlist match (exact, case-insensitive host, case-sensitive scheme/port)
- [x] 2d: Reject missing / malformed / non-allowlisted `Origin` with `403 forbidden_origin` *before* ticket validation
- [x] 2e: Augment the success `tracing::info!` with `origin`; add `tracing::warn!` on rejection (never log the ticket)
- [x] 2f: Verify `cargo check -p pm-web` and `cargo clippy --all-targets` pass

### Phase 3: Tests (Issue 3)
- [x] 3a: Add `crates/pm-web/tests/` and a `build_test_app` harness (no DB, minimal `AppState`)
- [x] 3b: Add `ws_rejects_missing_origin` test
- [x] 3c: Add `ws_rejects_disallowed_origin` test
- [x] 3d: Add `ws_rejects_malformed_origin` test
- [x] 3e: Add `ws_allows_listed_origin_with_valid_ticket` test (asserts ticket is consumed)
- [x] 3f: Add `ws_default_origin_derived_from_sso_callback_url` config-derivation test
- [x] 3g: Verify `cargo test -p pm-web` passes

### Phase 4: Documentation
- [x] 4a: Update `docs/security-review.md` with a new control row for the WS Origin allowlist
- [x] 4b: (Optional, per Kelly) bump `SPEC.md` to 0.0.3 with a sentence in the Security section

### Phase 5: Review
- [x] 5a: Self-review against the 10-point acceptance criteria in the spec
- [x] 5b: Commit on a feature branch (`issue/10-ws-origin-check`) per git-workflow skill
- [x] 5c: Lessons captured below

## Lessons Learned (this issue)
_(filled in at completion)_

- **SSO callback must redirect, not return JSON** — Browser OAuth2 flows require the backend to redirect to the frontend SPA, not return JSON tokens. The frontend must parse tokens from URL query parameters.
- **URLSearchParams.get() already decodes** — Don't double-decode with decodeURIComponent() when using URLSearchParams.
- **JWKS caching prevents rate-limiting** — Azure AD JWKS endpoint should be cached with TTL (1 hour) to avoid fetching on every SSO login.
- **tokio::sync::Mutex over std::sync::Mutex** — Axum handlers must be Send; std::sync::MutexGuard is not Send across await points.
- **DashMap session cleanup** — In-memory session stores (DashMap) need periodic cleanup tasks to prevent memory leaks. Pattern: tokio::spawn with interval + retain with time-based cutoff.

# IP Allowlist Hardening — Implementation Plan (Issue #3)

Spec: `tasks/ip-allowlist-spec.md` (v0.1.0, awaiting sign-off)

## Issues Identified
1. **Allowlist bypass via missing XFF** — `extract_remote_ip` returns `None` when
   the header is absent, and the middleware's `if let Some(ip)` block has no
   `else` branch, so a request without `X-Forwarded-For` skips the check.
2. **Allowlist spoofing via XFF** — `extract_remote_ip` reads the header
   unconditionally; any client can claim to be from a whitelisted IP.
3. **No trusted-proxy concept** — there is no config field to declare which
   intermediate proxies are allowed to set `X-Forwarded-For`.
4. **No `ConnectInfo<SocketAddr>` wiring** — the axum listeners in
   `pm-web/src/main.rs` do not use `into_make_service_with_connect_info`, so
   the middleware cannot access the real peer address.

## Phases

### Phase 1: Resolver helper in pm-auth
- [ ] 1a: Add `fn resolve_client_ip(headers, peer, trusted_proxies) -> Option<IpAddr>`
- [ ] 1b: Add 12 unit tests in `crates/pm-auth/src/rbac.rs` (cfg(test)) covering
      the resolution matrix (peer-only, XFF trusted/untrusted, multi-hop,
      IPv6, malformed, missing peer)
- [ ] 1c: Run `cargo test -p pm-auth` and confirm green

### Phase 2: AuthConfig + SecurityConfig schema
- [ ] 2a: Add `trusted_proxies: Arc<RwLock<Vec<IpNet>>>` to `AuthConfig`
- [ ] 2b: Add `trusted_proxies: Vec<String>` to `SecurityConfig` in `crates/pm-core/src/config.rs`
- [ ] 2c: Update `Default for AppConfig` to include `trusted_proxies: vec![]`
- [ ] 2d: Add `update_trusted_proxies` setter on `AuthConfig` (symmetric to
      `update_ip_whitelist`)
- [ ] 2e: Update `config/config.example.toml` with a documented `trusted_proxies`
      entry and a reverse-proxy runbook comment block
- [ ] 2f: Plumb `trusted_proxies` from `SecurityConfig` into `AuthConfig::new`
      in `pm-web/src/main.rs`
- [ ] 2g: Run `cargo check` and `cargo clippy --all-targets`

### Phase 3: Middleware change
- [ ] 3a: Update `require_auth` to extract `ConnectInfo<SocketAddr>` from
      request extensions and call `resolve_client_ip`
- [ ] 3b: Add fail-closed path: non-empty allowlist + unresolvable IP →
      `403 forbidden_ip`
- [ ] 3c: Replace `forbidden("Access denied")` with the new error code in IP-deny path
- [ ] 3d: Add `tracing::warn!` with `client_ip`, `peer`, `xff_present`, `reason`
- [ ] 3e: Remove the old `extract_remote_ip` (header-only) function
- [ ] 3f: Run `cargo check` and `cargo clippy --all-targets`

### Phase 4: pm-web listener wiring
- [ ] 4a: Switch both TCP and TLS axum listeners in `pm-web/src/main.rs` to
      `into_make_service_with_connect_info::<SocketAddr>()`
- [ ] 4b: Run `cargo check -p pm-web`

### Phase 5: Middleware integration tests
- [ ] 5a: Add `TestApp` harness in `crates/pm-auth/src/rbac.rs` cfg(test)
      (no DB, single-route router, `tower::ServiceExt`-style call)
- [ ] 5b: Add 8 middleware integration tests per spec section 6.1
      (allow empty, deny non-empty, allow in list, fail-closed no peer,
      spoofed XFF ignored, trusted proxy honors XFF, bad XFF fallback,
      no-JWT on deny)
- [ ] 5c: Run `cargo test -p pm-auth` and confirm green

### Phase 6: Documentation
- [ ] 6a: Update `docs/security-review.md` — update existing IP-allowlist row
      and reference new code path + `trusted_proxies` field
- [ ] 6b: Update `SPEC.md` Security section (one paragraph)
- [ ] 6c: Add a "Reverse proxy deployment" runbook under `docs/runbooks/`
      (optional, per Kelly)

### Phase 7: Review & commit
- [ ] 7a: Self-review against the 8 acceptance criteria in the spec
- [ ] 7b: Run `bash /a0/usr/skills/git-workflow/scripts/validate-push.sh`
- [ ] 7c: Commit on `fix/3-ip-allowlist-bypass` (per git-workflow skill)
- [ ] 7d: Push to `github/fix/3-ip-allowlist-bypass` and open PR against `master`
- [ ] 7e: Comment on issue #3 linking the PR; close issue on merge
- [ ] 7f: Capture lessons in this file

## Lessons Learned (this issue)
_(filled in at completion)_

---

# Host Self-Enrollment Implementation Plan

## Phases

### Phase 1: Database & Core Models
- [x] 1a: Create SQL migration for `enrollment_requests` table
- [x] 1b: Define Rust data models for `EnrollmentRequest` in `pm-core`
- [x] 1c: Add DB interaction methods (insert, list, delete) in `pm-core`

### Phase 2: Client-Facing API (pm-web)
- [x] 2a: Implement `POST /api/v1/enroll` to accept payloads and generate `polling_token`
- [x] 2b: Implement `GET /api/v1/enroll/status/{token}` to return pending/approved (PKI) statuses
- [x] 2c: Implement IP-based rate limiting for the `/enroll` endpoint

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
