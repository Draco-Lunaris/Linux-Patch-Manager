# WS Origin Allowlist — Specification

**Issue:** [#10](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/10)
**Component:** `crates/pm-web/src/routes/ws.rs`
**Spec version:** 0.1.0 (draft)
**Status:** Awaiting Kelly sign-off

---

## 1. Goal

Harden the browser-facing WebSocket upgrade endpoint (`GET /api/v1/ws/jobs`) against
Cross-Site WebSocket Hijacking (CSWSH) by validating the `Origin` header against a
configured allowlist. The existing single-use, 60-second ticket mechanism is retained
as the first credential factor; the Origin check is the second factor.

## 2. Non-Goals

- Replacing or weakening the ticket mechanism.
- Binding the ticket to a specific WebSocket connection at issuance time (separate,
larger change).
- Origin/CORS checks on the JWT-authenticated ticket-issuance endpoint
(`POST /api/v1/ws/ticket`) — it is already protected by JWT + RBAC middleware and is
not a browser-only entry point.
- Changes to `pm-worker/ws_relay.rs` — that module is an outbound mTLS WS *client* to
agents, not a server, and is not reachable from a browser.

## 3. Design

### 3.1 Handler change (`crates/pm-web/src/routes/ws.rs`)

The `ws_handler` function (lines 96–137) gains a new `HeaderMap` extractor and
performs an Origin allowlist check **before** ticket validation.

Order of operations in the new handler:

1. Extract `HeaderMap` (new).
2. Read `Origin` header. If absent → reject `403 forbidden_origin` (`"Origin header
   required"`).
3. Normalize and compare against the configured allowlist. If not matched → reject
   `403 forbidden_origin` (`"Origin not allowed"`).
4. Existing ticket validation (lines 101–127) runs unchanged.
5. Existing upgrade (line 136) runs unchanged.

Rationale for Origin-first ordering: a CSWSH probe from a malicious page will not
have a valid ticket. If we validated the ticket first and then checked Origin, an
attacker who has obtained a leaked ticket (from logs, `Referer`, history, support
bundle) could mount a denial-of-service against the legitimate user by burning their
tickets with `403` responses. Origin-first means rejected cross-origin attempts do
not consume the user's ticket.

### 3.2 Origin parsing and comparison

- Read the raw `Origin` header value as a string.
- Strip any trailing `/`.
- Use a hand-rolled parser (no new dependency) to extract `scheme`, `host`, and
  optional `port`:
  - `scheme` must be `http` or `https` (lowercased).
  - `host` must be non-empty and contain no whitespace.
  - `port`, if present, must parse as `u16`.
- Apply default-port normalization: `https` implies port `443`; `http` implies port
  `80`. If the explicit port equals the default for the scheme, drop it from the
  comparison. This matches browser behavior (browsers do not include default ports
  in `Origin`).
- Case-insensitive host comparison; case-sensitive scheme and port.
- Match each configured allowlist entry against the parsed Origin. **Exact match
  only** — no subdomain wildcards, no regex, no path.
- If the `Origin` header is malformed (does not parse) → reject
  `403 forbidden_origin` (`"Malformed Origin header"`).

### 3.3 Config schema (`crates/pm-core/src/config.rs`)

Add a new field to `SecurityConfig`:

```rust
/// Allowlist of browser `Origin` values permitted to open the
/// `/api/v1/ws/jobs` WebSocket. Entries are exact `scheme://host[:port]`
/// strings. If empty, the server derives the default from `sso_callback_url`.
#[serde(default = "default_allowed_origins")]
pub allowed_origins: Vec<String>,
```

Default value (`default_allowed_origins`): a single-element vector containing the
`scheme://host[:port]` form of `sso_callback_url` parsed at config-load time. This
keeps the default config secure out of the box — a fresh install will only accept
WS upgrades from the same origin the SSO callback redirects to.

If `sso_callback_url` cannot be parsed (e.g., a custom dev value), fall back to
`vec![]` and emit a `tracing::warn!` at startup. An empty allowlist with no
parseable default would make the WS endpoint reject all upgrades; this is the safe
direction (fail-closed), but the warning makes it loud.

Add a corresponding `ConfigError` if `allowed_origins` is manually set to an empty
vector and `sso_callback_url` is also unparseable, since that combination produces a
non-functional WS endpoint. The user must explicitly opt in to "no origins allowed"
by providing a list.

### 3.4 Logging

- On allowed upgrade: existing `tracing::info!` continues (lines 129–133), augmented
  with `origin = %origin_str` for audit context.
- On rejected upgrade: new `tracing::warn!` with `origin = %origin_str` and
  `reason = %reason`. **Never log the ticket value**.

### 3.5 Response shape

Reuse the existing `err` helper (lines 48–58):

```json
{ "error": { "code": "forbidden_origin", "message": "…" } }
```

Status: `403 Forbidden` for all Origin rejections. Do not differentiate between
"missing", "malformed", and "not in allowlist" in the response — they all map to the
same code, and the specific reason is logged server-side only.

## 4. Acceptance Criteria

- [ ] A WS upgrade request with a missing `Origin` header is rejected with `403`
      and code `forbidden_origin`. The ticket is **not** consumed.
- [ ] A WS upgrade request with a malformed `Origin` header is rejected with `403`
      and code `forbidden_origin`. The ticket is **not** consumed.
- [ ] A WS upgrade request with an `Origin` not in the allowlist is rejected with
      `403` and code `forbidden_origin`. The ticket is **not** consumed.
- [ ] A WS upgrade request with an allowlisted `Origin` and a valid, unconsumed
      ticket succeeds (101 Switching Protocols / upgrade accepted) and the ticket is
      consumed atomically (existing behavior preserved).
- [ ] A WS upgrade request with an allowlisted `Origin` and an invalid/expired/
      already-used ticket is rejected with the existing `401 invalid_ticket` /
      `401 ticket_expired` (existing behavior preserved).
- [ ] The allowlist is configurable via `security.allowed_origins` in
      `config/config.example.toml` and is documented in that file.
- [ ] When `allowed_origins` is not set, the default is derived from
      `sso_callback_url` and the service starts cleanly.
- [ ] `cargo check` and `cargo clippy --all-targets` pass.
- [ ] `cargo test -p pm-web` passes with the new integration tests added.
- [ ] `docs/security-review.md` documents the new control with an evidence row
      pointing to `crates/pm-web/src/routes/ws.rs`.

## 5. Test Plan

Unit tests in `crates/pm-web/src/routes/ws.rs` (cfg(test) module) — 33 tests
covering the security-critical logic. The end-to-end wiring (HeaderMap
extractor, axum handler, response shape) is verified by `cargo check`,
`cargo clippy --all-targets`, and the manual `scripts/integration-test.sh`
end-to-end check.

**Why unit tests instead of `tests/ws_origin.rs` integration tests:** the
handler is wired to `State<AppState>`, and `AppState` contains a
`sqlx::PgPool` and a `pm_ca::CertAuthority` that cannot be cheaply
constructed in a test (the CA requires a real Postgres connection and
on-disk key material, both unavailable in `cargo test`). Refactoring
`ws_handler` to take a smaller state struct is out of scope for this
hardening change.

### 5.1 pm-core unit tests (`crates/pm-core/src/config.rs`, 7 tests)

`derive_allowed_origins` — the sso_callback_url → allowlist derivation:

1. `derive_strips_default_https_port` — `https://x:443/...` → `https://x`
2. `derive_keeps_non_default_port` — `https://x:8443/...` → `https://x:8443`
3. `derive_strips_default_http_port` — `http://x:80/x` → `http://x`
4. `derive_handles_trailing_slash` — `https://x/` → `https://x`
5. `derive_handles_no_path` — `https://x` → `https://x`
6. `derive_returns_empty_for_garbage` — rejects "not a url", "", "ftp://x"
7. `derive_lowercases_scheme` — `HTTPS://...` → `https://...`

### 5.2 pm-web unit tests (`crates/pm-web/src/routes/ws.rs`, 33 tests)

`parse_origin_header` (14 tests): basic, with-port, scheme/host lowercasing,
path/query/fragment ignored, trailing-slash stripped, empty/whitespace
rejected, unsupported schemes rejected, empty host rejected, host with
whitespace rejected, malformed port rejected, IPv6 literal rejected, no
scheme separator rejected.

`Origin::canonical` (3 tests): default-port normalization in both directions
(http:80, https:443), non-default port kept.

`is_origin_allowed` (11 tests): exact match, default-port normalization in
both directions, case-insensitive host, different host rejected, different
scheme rejected, different port rejected, empty allowlist rejected,
unparseable allowlist entry rejected, multi-entry allowlist.

`check_origin` (7 tests): missing header, malformed header, disallowed
origin, empty allowlist, allowed origin, default-port normalization allowed,
case-insensitive host allowed. This function returns the `(StatusCode, Json)`
error tuple used by the handler, so these tests cover the response shape.

## 6. Risk Analysis

- **Risk: a config that breaks the WS endpoint in production.** Mitigation: default
  is derived from `sso_callback_url` (already required for SSO to function), and
  startup logs a warning if the allowlist ends up empty.
- **Risk: legitimate cross-origin frontend (e.g., SPA on `app.foo.com` talking to
  API on `api.foo.com`).** Out of scope for this fix — the WS endpoint is on the
  same origin as the SPA. If a future deployment splits them, the operator adds
  the API origin to `allowed_origins`. Documented in `config/config.example.toml`.
- **Risk: a non-browser caller (CLI, integration test) cannot connect.** Such
  callers should use the REST API for state mutations; the WS is documented as the
  browser job-stream channel. If a non-browser WS client is needed, document it in
  `docs/REST_API.md` and tell the operator to add its origin.
- **Risk: false sense of security.** The Origin check is defense-in-depth, not a
  replacement for the ticket. Documented as such in the security review update.

## 7. Files Touched

- `crates/pm-web/src/routes/ws.rs` — handler change.
- `crates/pm-core/src/config.rs` — new field + default.
- `config/config.example.toml` — new field documented.
- `crates/pm-web/tests/ws_origin.rs` — new integration tests (and harness).
- `docs/security-review.md` — control documentation row.
- `tasks/todo.md` — plan section (added by the orchestrator).

## 8. Out of Scope (Future Work)

- Bind ticket issuance to the WS upgrade in a single round-trip (eliminates
  query-string ticket leakage from logs/history).
- Per-message MAC on WS frames (defense against in-process tampering).
- Rate limiting on the WS endpoint itself.
