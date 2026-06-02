# IP Allowlist Hardening — Specification

**Issue:** [#3](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/3)
**Component:** `crates/pm-auth/src/rbac.rs`, `crates/pm-core/src/config.rs`
**Spec version:** 0.1.0 (draft)
**Status:** Awaiting Kelly sign-off

---

## 1. Goal

Harden the IP allowlist enforced in the `require_auth` middleware so that:

1. It cannot be bypassed by omitting the `X-Forwarded-For` header.
2. It cannot be spoofed by setting `X-Forwarded-For` to an allowlisted value from
   a client that directly reaches the service.
3. When a non-empty allowlist is configured and no trustworthy client IP can be
   determined, the request is **denied** (fail-closed).

Today the allowlist is a documented production access control (see
`config/config.example.toml` `[security] ip_whitelist`) but, as filed in issue #3,
can be trivially defeated.

## 2. Non-Goals

- Replacing or weakening JWT auth. The allowlist is a defense-in-depth layer; JWT
  validation continues to run.
- Adding rate-limiting behavior (governor's `SmartIpKeyExtractor` is used for rate
  limiting and is out of scope to change here).
- Changes to `pm-worker` or `pm-agent-client` IP handling. This issue is scoped to
  the web/API edge.
- IPv6-specific quirks beyond what `ipnet` already supports. `is_ip_allowed`
  already handles IPv4 and IPv6 CIDRs via `IpNet`.

## 3. Design Decisions (Kelly sign-off, 2026-06-02)

| # | Decision | Resolution |
|---|----------|------------|
| Q1 | Trusted-proxy handling | **Strict (no proxies trusted by default).** Add a new `trusted_proxies: Vec<IpNet>` config field. When the field is **empty** (the default), the allowlist check uses the socket peer IP only and ignores `X-Forwarded-For` entirely. When the field is **non-empty** and the immediate peer is in the list, `X-Forwarded-For` may be honored; otherwise the socket peer IP is used. |
| Q2 | Reuse `SmartIpKeyExtractor` | **Reuse the pattern.** Extract a small, well-tested resolver helper (named `resolve_client_ip`) into `pm-auth` that mirrors `SmartIpKeyExtractor`'s "trust XFF only when peer is in trusted list, else peer IP" semantics, so the IP-allowlist check and the rate-limiter use the same resolution rule. We do not introduce a `pm-web → pm-auth` cycle; the resolver lives in `pm-auth` and is consumed by the middleware directly. (`pm-web` continues to use the governor extractor for its own rate-limiting layer.) |
| Q3 | Fail-closed on unresolvable IP | **Deny.** When the allowlist is non-empty and `resolve_client_ip` cannot determine a client IP (no `ConnectInfo<SocketAddr>`, peer address missing), the request is rejected with `403 forbidden_ip` and a `tracing::warn!` is emitted. |
| Q4 | Backward compat for empty allowlist | **Preserve `ip_whitelist = []` → allow all.** This keeps dev installs and unconfigured deployments working without code changes. Production deployments that set a non-empty list get the hardened behavior automatically. |

## 4. Design

### 4.1 Resolver helper (`crates/pm-auth/src/rbac.rs`)

New function:

```rust
/// Determine the client IP used for IP-allowlist enforcement.
///
/// Resolution rules:
/// 1. Start with the socket peer IP (`SocketAddr::ip()`).
/// 2. If `trusted_proxies` is non-empty **and** the socket peer is in
///    `trusted_proxies`, parse the leftmost entry of the `X-Forwarded-For`
///    header and use it (the immediate untrusted hop).
/// 3. If parsing `X-Forwarded-For` fails or the header is missing, fall back
///    to the socket peer IP.
/// 4. If the socket peer is unknown (no `ConnectInfo<SocketAddr>` is
///    available on the request), return `None` so the caller can apply
///    fail-closed logic when the allowlist is non-empty.
fn resolve_client_ip(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr>
```

The function is pure, easy to unit test, and has no I/O. Logging is performed by
the caller (middleware) so test assertions can be made on behavior without
capturing tracing output.

### 4.2 Middleware change (`crates/pm-auth/src/rbac.rs`)

`require_auth` is changed to:

1. Extract the peer address from request extensions
   (`req.extensions().get::<ConnectInfo<SocketAddr>>()`).
2. Compute the resolved client IP via `resolve_client_ip`.
3. If `auth_config.ip_whitelist` is non-empty **and** no client IP could be
   resolved, return `403 forbidden_ip` (`"Client IP could not be determined"`)
   with a `tracing::warn!`.
4. If a client IP was resolved and the allowlist rejects it, return
   `403 forbidden_ip` (`"Access denied"`) with a `tracing::warn!` (existing
   message preserved for log continuity).
5. Otherwise continue to JWT validation (unchanged).

`axum::extract::ConnectInfo<SocketAddr>` is added as a request extension by the
axum server in `pm-web/src/main.rs` (one new line in the TCP/TLS listener
configuration; this is a required companion change to the middleware).

The old `extract_remote_ip` (header-only) is removed; the function is
superseded by `resolve_client_ip` and is not exported.

### 4.3 Config schema (`crates/pm-core/src/config.rs`)

Add a field to `SecurityConfig`:

```rust
/// IP addresses (CIDR or single IP) of trusted reverse proxies. When the
/// immediate TCP peer is in this list, `X-Forwarded-For` is honored; otherwise
/// the socket peer IP is used. Default: empty (do not trust `X-Forwarded-For`).
#[serde(default)]
pub trusted_proxies: Vec<String>,
```

The field parses to `Vec<IpNet>` at config-load time and is plumbed into
`AuthConfig::new` as a new `trusted_proxies: Arc<RwLock<Vec<IpNet>>>`
parameter (mirroring the existing `ip_whitelist` runtime-update pattern; an
`update_trusted_proxies` setter is added for symmetry, though no endpoint
needs it for this issue).

`Default for AppConfig` is updated to set `trusted_proxies: vec![]`.
`config/config.example.toml` gets a documented `trusted_proxies = []` entry
with a comment block explaining when to set it.

### 4.4 `pm-web` wiring (`crates/pm-web/src/main.rs`)

The axum listener is changed to use `into_make_service_with_connect_info::<SocketAddr>()`
so that `ConnectInfo<SocketAddr>` is available to extractors and middleware.
This is the documented axum pattern and is a one-line change per listener
(there are currently two listeners in `main.rs`: a TCP one for dev and a
TLS one for prod; both need the connect-info wrapper).

### 4.5 Response shape

Reuse the existing `forbidden` helper. Error code: `forbidden_ip` (new). Body:

```json
{ "error": { "code": "forbidden_ip", "message": "…" } }
```

Status: `403 Forbidden` for all IP rejections. Do not differentiate between
"unresolvable" and "not in allowlist" in the response; the specific reason is
logged server-side only.

### 4.6 Logging

- On allow (allowlist empty or IP matched): no new log line (existing flow
  continues silently).
- On deny (allowlist non-empty and IP not allowed, or IP unresolvable): new
  `tracing::warn!` with `client_ip = %ip_opt`, `peer = %peer_opt`,
  `xff_present = bool`, `reason = %reason`.

The existing `tracing::warn!` for blocked requests is preserved in shape so
log-greppers continue to work.

## 5. Acceptance Criteria

- [ ] A request with a non-empty allowlist and no `X-Forwarded-For` header is
      evaluated against the socket peer IP.
- [ ] A request with a non-empty allowlist and a spoofed `X-Forwarded-For`
      (set by a client that is **not** in `trusted_proxies`) is evaluated
      against the socket peer IP; the spoofed value is ignored.
- [ ] A request with a non-empty allowlist, an empty `trusted_proxies`, and
      no resolvable peer IP is rejected with `403 forbidden_ip`.
- [ ] A request with a non-empty allowlist and a valid `X-Forwarded-For` from
      a peer in `trusted_proxies` is evaluated against the leftmost untrusted
      hop.
- [ ] A request with an empty allowlist is allowed regardless of IP
      resolution (preserved behavior for dev installs).
- [ ] `cargo check` and `cargo clippy --all-targets` pass.
- [ ] `cargo test -p pm-auth` passes with new unit tests for `resolve_client_ip`
      and the middleware allow/deny matrix.
- [ ] `docs/security-review.md` documents the hardened control with a new row
      in the controls table referencing `crates/pm-auth/src/rbac.rs`.

## 6. Test Plan

### 6.1 Unit tests in `crates/pm-auth/src/rbac.rs` (cfg(test) module)

`resolve_client_ip` (12 tests):

1. `peer_only_no_xff` — no XFF, trusted_proxies empty → returns peer.
2. `peer_only_xff_untrusted` — XFF set, peer not in trusted_proxies, trusted_proxies
   non-empty → returns peer (XFF ignored).
3. `peer_only_trusted_proxies_empty_xff_present` — XFF set, trusted_proxies
   empty → returns peer (XFF ignored). [strict default]
4. `xff_trusted_peer_in_list` — XFF set, peer in trusted_proxies → returns
   parsed leftmost XFF entry.
5. `xff_trusted_peer_in_list_malformed_xff` — XFF unparseable, peer in
   trusted_proxies → falls back to peer.
6. `xff_trusted_peer_in_list_empty_xff` — XFF is empty string, peer in
   trusted_proxies → falls back to peer.
7. `xff_trusted_peer_in_list_multi_hop` — "1.2.3.4, 5.6.7.8" with peer in
   trusted_proxies → returns 1.2.3.4 (leftmost).
8. `no_peer_no_xff` — peer None, no XFF → returns None.
9. `no_peer_xff_untrusted` — peer None, XFF set, trusted_proxies empty →
   returns None (caller fails closed).
10. `xff_trusted_whitespace` — XFF `"  1.2.3.4"`, peer in trusted_proxies →
    returns 1.2.3.4 (trim).
11. `trusted_proxies_ipv6` — peer in IPv6 trusted list, IPv6 XFF → returns XFF.
12. `peer_ipv4_xff_ipv6_mismatch_trusted` — peer in trusted list, XFF is IPv6
    → returns parsed IPv6 (mixed family is fine).

`AuthConfig` integration with middleware (8 tests, using a small `TestApp`
harness with a `tower::ServiceExt`-style call into a single-route router —
no DB, no real HTTP listener):

13. `middleware_allows_when_whitelist_empty` — empty list + any IP → 200/ok.
14. `middleware_denies_when_whitelist_non_empty_and_ip_not_in_list` —
    non-empty list + peer outside → 403 `forbidden_ip`.
15. `middleware_allows_when_ip_in_list` — non-empty list + peer inside → 200.
16. `middleware_denies_when_no_peer_resolvable_and_whitelist_non_empty` —
    non-empty list + missing `ConnectInfo` → 403 `forbidden_ip`.
17. `middleware_spoofed_xff_ignored_when_peer_untrusted` — non-empty list +
    peer outside list + XFF inside list → 403 `forbidden_ip`.
18. `middleware_trusted_proxy_honors_xff` — non-empty list + peer in
    `trusted_proxies` + XFF inside list → 200.
19. `middleware_trusted_proxy_falls_back_to_peer_on_bad_xff` — peer in
    `trusted_proxies` + unparseable XFF + peer outside list → 403
    `forbidden_ip`.
20. `middleware_no_jwt_when_ip_blocked` — blocked request never reaches
    JWT validation (no `validate_access_token` call on deny path; covered by
    passing an obviously invalid token and asserting 403 not 401).

### 6.2 Test harness

A small `TestApp` helper builds a one-route `axum::Router` with a stub
handler that returns `200 OK` and a `require_auth` middleware. The harness
provides:

- A configurable `AuthConfig` (whitelist, trusted_proxies).
- A way to attach `ConnectInfo<SocketAddr>` (via a request-extension
  pre-set in the test).
- A way to add/omit the `Authorization: Bearer` header (for the
  `middleware_no_jwt_when_ip_blocked` test).

No real TCP listener, no DB, no async runtime beyond `#[tokio::test]`.

## 7. Risk Analysis

- **Risk: breaking change for deployments behind a reverse proxy that did not
  configure `trusted_proxies`.** Today, `X-Forwarded-For` from any caller is
  trusted (or, with the new code, ignored). After this change, such deployments
  will see the allowlist evaluate against the **proxy's** IP, which may not be
  in the allowlist and will cause 403s.
  - **Mitigation:** Document `trusted_proxies` prominently in
    `config/config.example.toml` with a clear warning. The default empty list
    is fail-closed (403), not fail-open, so misconfigured deployments will
    notice immediately rather than silently allowing traffic.
  - **Operational runbook:** add a "reverse proxy" section to the install
    docs describing the required config change.

- **Risk: dev installs behind a corporate proxy that injects XFF.** Same as
  above; documented in the example config and the runbook.

- **Risk: missing `ConnectInfo<SocketAddr>` in some test or alternate
  listener.** The middleware handles this gracefully (returns `None` from
  `resolve_client_ip` → fail-closed when allowlist non-empty → 403). The
  unit test matrix covers this path explicitly.

- **Risk: regression in JWT auth path.** The deny path short-circuits before
  JWT validation (test 20). The allow path is unchanged.

- **Risk: governor rate-limiter inconsistency.** `pm-web`'s rate-limiter
  uses `SmartIpKeyExtractor` from the `governor` crate, which has its own
  resolution semantics (governor's defaults). If Kelly wants the rate
  limiter to share `resolve_client_ip`, that's a follow-up issue and is
  called out in the lessons file as a known consistency gap.

## 8. Documentation Updates

- `config/config.example.toml`: new `trusted_proxies = []` entry with
  multi-line comment block.
- `docs/security-review.md`: new row in the controls table; update the
  existing IP-allowlist row to point to the new code path and the new
  `trusted_proxies` field.
- `docs/runbooks/`: (optional, per Kelly) add a short "Reverse proxy
  deployment" runbook.
- `SPEC.md`: (optional, per Kelly) one-paragraph update in the Security
  section.

## 9. Out of Scope / Follow-ups

- Sharing `resolve_client_ip` with the governor rate-limiter in `pm-web`
  (consistency improvement, separate change).
- mTLS client-cert CN/SAN allowlist (defense-in-depth beyond IP).
- Per-route IP allowlist (different routes, different lists). Current
  allowlist is global.
