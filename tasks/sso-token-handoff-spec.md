# SSO Token Handoff — Specification

**Issue:** [#4](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/4)
**Component:** `crates/pm-web/src/routes/sso.rs`, `frontend/src/pages/SsoCallbackPage.tsx`, `frontend/src/store/authStore.ts`
**Spec version:** 0.1.0 (draft)
**Status:** Awaiting Kelly sign-off

---

## 1. Goal

Stop embedding JWT access tokens, refresh tokens, and user objects in the
SSO callback redirect URL. Today, after a successful OIDC login, the
backend 302-redirects the browser to the SPA with the tokens in the
query string:

```
https://app.example.com/auth/sso/callback
  ?access_token=<jwt>
  &refresh_token=<raw>
  &token_type=Bearer
  &expires_in=900
  &user=<urlencoded-json>
```

Tokens in URLs are written to browser history, intermediate proxy and
load-balancer access logs, and may leak via the `Referer` header when
the landing page loads third-party resources. The refresh token is
the most sensitive value (long-lived, rotating) and gets the worst
exposure.

Replace the URL-embedded tokens with a **single-use, short-lived
handoff code** that the SPA exchanges for tokens via a server-to-server
POST. The URL then contains only the code, which expires in 60 seconds
and is invalidated on first use.

## 2. Non-Goals

- Changing the OIDC flow itself (Authorization Code + PKCE stays the same).
- Changing the MFA verification path that runs after the OIDC callback.
- Touching the WS ticket pattern (issue #10) — this spec is a *new*
  in-memory store for SSO handoff codes, mirroring but separate from
  `ws_tickets: Arc<DashMap<String, WsTicket>>`.
- Adding cookie-based or `form_post` delivery. The handoff code
  approach was selected over those (Kelly sign-off Q1).
- Long-lived SSO sessions. The handoff code is single-use; subsequent
  SSO logins re-issue a new code.

## 3. Design Decisions (Kelly sign-off, 2026-06-02)

| # | Question | Resolution |
|---|----------|------------|
| Q1 | Approach selection | **Handoff code** (option C in issue #4). Mirrors the existing WS-ticket pattern. URL contains only a single-use, 60s `handoff_code`. SPA POSTs to `/api/v1/auth/sso/handoff` and gets tokens in the JSON response. |
| Q2 | Cookie attributes | **N/A** — handoff code approach uses no cookies. |
| Q3 | Rollout strategy | **Hard cutover** — remove the old query-string parsing in the same PR. No dual-read window. (Justification: security-critical fix, deploy window is short, no in-flight SSO logins survive a rolling restart because the auth state is in the user's browser, not on the server.) |
| Q4 | `Secure` cookie flag | **N/A** — handoff code approach uses no cookies. Kelly's answer ("unconditionally secure") is noted for future cookie work but does not apply here. |

## 4. Design

### 4.1 Backend: SSO callback (`crates/pm-web/src/routes/sso.rs`)

The `sso_callback` handler currently constructs a redirect URL with all
token values. Replace this with a handoff code generation step:

1. After the access/refresh tokens and `user_json` are computed (the
   existing logic through `sso_callback` is unchanged up to the
   redirect construction), generate a cryptographically random
   `handoff_code` (32 bytes, base64url-encoded, ~43 chars).
2. Store the handoff payload in a new in-memory map:
   ```rust
   pub struct SsoHandoff {
       pub access_token: String,
       pub raw_refresh: String,
       pub user_json: Value,
       pub access_ttl: u64,
       pub expires_at: Instant, // now + 60s
   }
   pub sso_handoffs: Arc<DashMap<String, SsoHandoff>>,
   ```
   Mirrors the `WsTicket` struct (single-use, in-memory, TTL enforced
   on read). The map is added to `AppState` alongside `ws_tickets`.
3. Build the redirect URL with ONLY the handoff code:
   ```rust
   let redirect_url = format!("{}?handoff={}", callback_url, handoff_code);
   Ok(Redirect::to(&redirect_url))
   ```
4. Log the handoff creation (without the code value itself) for audit:
   ```rust
   tracing::info!(user_id = %user.id, auth_provider, "SSO handoff issued");
   ```

### 4.2 Backend: Handoff exchange endpoint

New handler `POST /api/v1/auth/sso/handoff`:

- Request body: `{ "handoff_code": "<code>" }`
- Behavior:
  1. Look up `handoff_code` in `sso_handoffs` (DashMap read lock).
  2. If not found → `400 invalid_handoff`.
  3. If found but `expires_at < Instant::now()` → remove the entry and
     return `400 invalid_handoff` (the cleanup-on-expiry also prevents
     memory bloat from expired-but-unconsumed codes).
  4. **Remove the entry atomically** (DashMap `remove` is atomic) —
     this is the single-use guarantee. Even if two requests race with
     the same code, only one wins.
  5. Return the payload as JSON:
     ```json
     {
       "access_token": "<jwt>",
       "refresh_token": "<raw>",
       "token_type": "Bearer",
       "expires_in": 900,
       "user": { "id": "...", "username": "...", ... }
     }
     ```
- Log:
  - On success: `tracing::info!(user_id = %payload.user.id, "SSO handoff exchanged")`
  - On failure: `tracing::warn!(reason = %reason, "SSO handoff exchange failed")`
  - **Never log the handoff code value itself** (it's a bearer secret
    with 60s window).

### 4.3 Backend: Cleanup task

Add a `tokio::spawn` cleanup task in `main.rs` (mirroring the existing
WS-ticket cleanup if present, or the SSO-session cleanup that already
runs per the codebase). Every 60 seconds, walk `sso_handoffs` and
remove entries with `expires_at < Instant::now()`. Bounded memory
growth even if the SPA never POSTs back.

### 4.4 Backend: Route registration

In `pm-web/src/main.rs`, add the new route to the public router
(alongside `/api/v1/ws/ticket`, which is also public — no JWT
required because the handoff code IS the credential):

```rust
.route("/api/v1/auth/sso/handoff", post(sso_handoff_exchange))
```

### 4.5 Frontend: `SsoCallbackPage.tsx`

Replace the URL-param parsing with a POST to the handoff endpoint:

```typescript
useEffect(() => {
  const params = new URLSearchParams(window.location.search)
  const errorCode = params.get('error')
  if (errorCode) {
    // ... existing error handling unchanged ...
    return
  }

  const handoffCode = params.get('handoff')
  if (!handoffCode) {
    setError('Missing handoff code. Please try logging in again.')
    setProcessing(false)
    return
  }

  // Exchange handoff code for tokens
  fetch('/api/v1/auth/sso/handoff', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ handoff_code: handoffCode }),
  })
    .then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)))
    .then(data => {
      setTokens(data.access_token, data.refresh_token)
      setUser(buildUser(data.user))
      // Clear the handoff code from the URL to prevent bookmarking/sharing
      window.history.replaceState({}, '', '/auth/sso/callback')
      navigate('/dashboard', { replace: true })
    })
    .catch(err => {
      setError(err?.error?.message || 'Failed to complete sign-in. Please try again.')
      setProcessing(false)
    })
}, [setTokens, setUser, navigate])
```

The `buildUser` helper mirrors the existing field-mapping logic
(lines 54–67 of the current file).

### 4.6 Frontend: `authStore.ts`

**No change required.** The existing `setTokens(access, refresh)` and
`setUser(user)` API is what the new code calls. The `partialize`
config (line 74) already correctly persists only `refreshToken` and
`user` — not `accessToken` — so the in-memory access token is never
written to localStorage. This is the correct security posture and
should be preserved.

## 5. Acceptance Criteria

- [ ] SSO callback no longer places `access_token`, `refresh_token`,
      `token_type`, `expires_in`, or `user` in the redirect URL.
      The URL contains only `handoff=<code>` (plus the error params on
      failure, which are unchanged).
- [ ] The handoff code is at least 128 bits of entropy (32 bytes,
      base64url-encoded) and is generated with a CSPRNG.
- [ ] The handoff code is single-use: a second exchange attempt with
      the same code returns `400 invalid_handoff` and does NOT return
      the tokens again.
- [ ] The handoff code expires after 60 seconds. An exchange attempt
      with an expired code returns `400 invalid_handoff` and the
      entry is removed from the in-memory map.
- [ ] The SPA successfully completes login: POST to the handoff
      endpoint receives the tokens, calls `setTokens` and `setUser`,
      and navigates to `/dashboard`.
- [ ] `authStore.ts` is unchanged (its existing `partialize` already
      prevents access-token persistence; the handoff code approach
      doesn't change that contract).
- [ ] `cargo check` and `cargo clippy --all-targets` pass.
- [ ] `cargo test -p pm-web` passes with new tests for the handoff
      endpoint (create, exchange success, exchange duplicate=400,
      exchange expired=400, exchange unknown=400).
- [ ] `frontend` builds cleanly (`npm run build` in `frontend/`).
- [ ] No access or refresh token values appear in any URL or query
      string in the SSO flow. Manual verification: complete a login
      and grep the server access log for the callback URL — only the
      handoff code should be present.
- [ ] `docs/security-review.md` §2.5 (Azure SSO) is updated to
      document the handoff code control.

## 6. Test Plan

### 6.1 Backend unit/integration tests (`crates/pm-web/src/routes/sso.rs`)

Using a small `TestApp` harness mirroring the WS-ticket test pattern
(no real HTTP listener, no DB beyond the connection that's already
mocked in the existing tests):

1. `handoff_exchange_success` — create a handoff, POST to the
   exchange endpoint, expect 200 with the access/refresh/user fields.
2. `handoff_exchange_single_use` — exchange once (success), exchange
   the same code again (expect 400 `invalid_handoff`).
3. `handoff_exchange_unknown_code` — POST with a code that was never
   issued (expect 400 `invalid_handoff`).
4. `handoff_exchange_expired_code` — create a handoff with
   `expires_at = past`, exchange (expect 400 `invalid_handoff` AND
   the entry is removed from the map).
5. `handoff_exchange_race` — two concurrent POSTs with the same code
   (using `tokio::join!`); exactly one succeeds, the other gets 400.
6. `handoff_exchange_malformed_body` — POST with invalid JSON or
   missing `handoff_code` field (expect 400 `invalid_handoff`).
7. `callback_redirect_contains_only_handoff` — invoke `sso_callback`
   through a mock OIDC config and assert the resulting redirect URL
   contains only `handoff=<code>` and NO `access_token` /
   `refresh_token` / `user` query params.

### 6.2 Backend cleanup test

8. `handoff_cleanup_removes_expired` — create 3 handoffs with
   varying `expires_at`, run one tick of the cleanup task, assert
   only the non-expired ones remain.

### 6.3 Frontend tests (`frontend/src/pages/SsoCallbackPage.tsx`)

Add a Vitest + React Testing Library test suite (the frontend already
uses Vitest — see `frontend/package.json` and `frontend/vite.config.ts`):

9. `renders_processing_state_initially` — on mount with a handoff
   code, shows the spinner and "Completing sign-in…".
10. `calls_handoff_endpoint_on_mount` — mocks `fetch` and asserts the
    POST goes to `/api/v1/auth/sso/handoff` with `{ handoff_code: <code> }`.
11. `stores_tokens_and_user_on_success` — mocks a successful response,
    asserts `setTokens` and `setUser` are called with the response
    payload, and the SPA navigates to `/dashboard`.
12. `shows_error_on_handoff_failure` — mocks a 400 response, asserts
    the error message is rendered and the spinner stops.
13. `shows_error_when_handoff_code_missing` — invokes the effect with
    no handoff code, asserts the "Missing handoff code" error is
    shown.
14. `clears_handoff_code_from_url_after_success` — asserts
    `window.history.replaceState` is called to remove the `?handoff=`
    param from the URL after a successful exchange.

## 7. Risk Analysis

- **Risk: regression in the SSO login flow.** Mitigation: the test
  plan covers the callback redirect shape, the exchange endpoint
  behavior (success, single-use, expiry, race), and the frontend
  effect. Manual end-to-end test (completing a real Azure AD login)
  is required before merge — the new `scripts/integration-test.sh`
  should be extended or a new `scripts/integration-test-sso.sh`
  added to exercise the full flow against a mock OIDC provider.
- **Risk: in-flight SSO logins during deploy break.** Per Kelly
  sign-off Q3, we accept hard cutover. The mitigation: the 60s
  handoff TTL means any in-flight redirect that arrives after the
  server restart has a 60s window to complete. If the new code is
  deployed and the old handoffs are lost, the user is sent back to
  `/auth/sso/callback?handoff=<old-code>` which the new code rejects
  with `400 invalid_handoff`, and the SPA shows "Please try logging
  in again." Worst case: a 30-second re-login. Acceptable for a
  security-critical fix.
- **Risk: handoff code leaked via browser history or `Referer`.**
  The code is single-use and 60s TTL, so the blast radius is small
  even if logged. The SPA calls `history.replaceState` after a
  successful exchange to remove the code from the address bar (and
  the underlying history entry). The 60s window limits exposure to
  `Referer` leakage on subsequent navigations from the callback
  page.
- **Risk: memory growth from unconsumed handoffs.** Mitigation: the
  cleanup task runs every 60s and removes expired entries. Worst
  case memory usage is `O(active_logins)` — typically single digits.
- **Risk: race condition in the single-use guarantee.** Mitigation:
  `DashMap::remove` is atomic, so only one of two concurrent
  exchange attempts can succeed. Verified by the
  `handoff_exchange_race` test.

## 8. Documentation Updates

- `docs/security-review.md` §2.5 (Azure SSO): add a new row
  documenting the handoff code control and explicitly state that no
  tokens appear in any URL.
- `frontend/src/pages/SsoCallbackPage.tsx`: update the doc-comment to
  describe the POST-and-exchange flow instead of the URL-param parse.
- `docs/REST_API.md`: document the new `POST /api/v1/auth/sso/handoff`
  endpoint.

## 9. Out of Scope / Follow-ups

- Cookie-based SSO session (a future enhancement that would let the
  SPA refresh state without a new OIDC flow on every page load).
- `form_post` response mode (a future enhancement if browsers
  standardize it more widely).
- Rate limiting on the handoff endpoint (out of scope here; the
  existing governor-based rate limits on `/auth/*` may already cover
  this — verify during implementation).
- Moving the in-memory `sso_handoffs` to Redis (out of scope; the
  single-instance design constraint in `SPEC.md` is fine for this
  control).
