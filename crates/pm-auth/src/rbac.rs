//! Role-Based Access Control (RBAC) middleware for Axum.
//!
//! Provides:
//! - JWT extraction and validation from `Authorization: Bearer <token>` header
//! - Role enforcement (`admin`, `operator`)
//! - Group-scoped access (enforced at the handler level using `AuthUser` extension)
//! - IP whitelist enforcement

use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use ipnet::IpNet;
use parking_lot::RwLock;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use crate::jwt::{validate_access_token, AccessClaims, JwtError};

/// User identity extracted from a validated JWT, inserted as a request extension.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub username: String,
    pub role: UserRole,
    pub claims: AccessClaims,
}

/// Application roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRole {
    Admin,
    Operator,
    Reporter,
}

impl UserRole {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "reporter" => Some(Self::Reporter),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Reporter => "reporter",
        }
    }

    /// Admin can do everything; operator has limited scope.
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }

    /// Admin and Operator can write; Reporter is read-only.
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }
}

/// Shared auth configuration injected via Axum state.
#[derive(Clone)]
pub struct AuthConfig {
    /// Ed25519 public key PEM for JWT verification.
    pub verify_key_pem: String,
    /// IP whitelist (empty = allow all). RwLock for runtime updates.
    pub ip_whitelist: Arc<RwLock<Vec<IpNet>>>,
    /// Trusted reverse-proxy CIDRs (empty = do not trust `X-Forwarded-For`).
    /// RwLock for runtime updates (symmetric to `ip_whitelist`).
    pub trusted_proxies: Arc<RwLock<Vec<IpNet>>>,
}

impl AuthConfig {
    pub fn new(
        verify_key_pem: String,
        ip_whitelist_cidrs: &[String],
        trusted_proxy_cidrs: &[String],
    ) -> Self {
        let ip_whitelist = ip_whitelist_cidrs
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();
        let trusted_proxies = trusted_proxy_cidrs
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();

        Self {
            verify_key_pem,
            ip_whitelist: Arc::new(RwLock::new(ip_whitelist)),
            trusted_proxies: Arc::new(RwLock::new(trusted_proxies)),
        }
    }

    /// Check if an IP address is allowed by the whitelist.
    /// If the whitelist is empty, all IPs are allowed.
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        let whitelist = self.ip_whitelist.read();
        if whitelist.is_empty() {
            return true;
        }
        whitelist.iter().any(|net| net.contains(ip))
    }

    /// Update the IP whitelist at runtime without restart.
    pub fn update_ip_whitelist(&self, entries: Vec<String>) {
        let nets: Vec<IpNet> = entries
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();
        let count = nets.len();
        *self.ip_whitelist.write() = nets;
        tracing::info!(count, "IP whitelist updated at runtime");
    }

    /// Update the trusted-proxy list at runtime without restart.
    /// Empty list = strict mode (ignore `X-Forwarded-For`).
    pub fn update_trusted_proxies(&self, entries: Vec<String>) {
        let nets: Vec<IpNet> = entries
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();
        let count = nets.len();
        *self.trusted_proxies.write() = nets;
        tracing::info!(count, "Trusted proxies updated at runtime");
    }
}

/// Extract `Authorization: Bearer <token>` from request headers.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// Determine the client IP used for IP-allowlist enforcement.
///
/// Resolution rules (per `tasks/ip-allowlist-spec.md` §4.1):
/// 1. Start with the socket peer IP.
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
) -> Option<IpAddr> {
    let peer_ip = peer?;

    if !trusted_proxies.is_empty() && trusted_proxies.iter().any(|net| net.contains(&peer_ip)) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(ip) = xff
                .split(',')
                .next()
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
            {
                return Some(ip);
            }
        }
    }

    Some(peer_ip)
}

/// Unauthorized JSON response helper.
fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": { "code": "unauthorized", "message": message } })),
    )
        .into_response()
}

/// Forbidden JSON response helper.
fn forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": { "code": "forbidden", "message": message } })),
    )
        .into_response()
}

/// Forbidden-by-IP response helper. Distinct error code (`forbidden_ip`) so
/// callers can distinguish an IP-allowlist rejection from a role-based
/// rejection. Used by `require_auth` after the IP-resolution failure or
/// allowlist miss per `tasks/ip-allowlist-spec.md` §4.2.
fn forbidden_ip(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": { "code": "forbidden_ip", "message": message } })),
    )
        .into_response()
}

/// Middleware: authenticate any valid JWT (admin or operator).
///
/// Inserts `AuthUser` into request extensions on success.
/// Rejects with 401 if token is missing/invalid, 403 if IP is blocked.
pub async fn require_auth(auth_config: Arc<AuthConfig>, mut req: Request, next: Next) -> Response {
    // IP whitelist check. Only enforced when the configured allowlist is
    // non-empty (Q4 sign-off: empty list = allow all, preserved for dev
    // installs). When enforced, the resolved client IP comes from
    // `resolve_client_ip`, which uses the socket peer IP by default and
    // honors `X-Forwarded-For` only when the immediate peer is in
    // `trusted_proxies` (Q1 sign-off: strict default, Q2 sign-off: same
    // resolution pattern as the rate-limiter). Fail-closed when the IP
    // cannot be determined (Q3 sign-off).
    //
    // See `tasks/ip-allowlist-spec.md` §4.2 for the full design.
    if !auth_config.ip_whitelist.read().is_empty() {
        let headers = req.headers().clone();
        let peer: Option<IpAddr> = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        let xff_present = headers.contains_key("x-forwarded-for");
        let trusted: Vec<IpNet> = auth_config.trusted_proxies.read().clone();
        let resolved = resolve_client_ip(&headers, peer, &trusted);

        match resolved {
            None => {
                tracing::warn!(
                    peer = ?peer,
                    xff_present,
                    reason = "unresolvable_client_ip",
                    "Request denied by IP whitelist (fail-closed: no ConnectInfo<SocketAddr>)"
                );
                return forbidden_ip("Client IP could not be determined");
            },
            Some(ip) => {
                if !auth_config.is_ip_allowed(&ip) {
                    tracing::warn!(
                        client_ip = %ip,
                        peer = ?peer,
                        xff_present,
                        reason = "ip_not_in_allowlist",
                        "Request blocked by IP whitelist"
                    );
                    return forbidden_ip("Access denied");
                }
            },
        }
    }

    // Extract and validate JWT
    let token = match extract_bearer_token(req.headers()) {
        Some(t) => t,
        None => return unauthorized("Missing authorization token"),
    };

    let claims = match validate_access_token(token, &auth_config.verify_key_pem) {
        Ok(c) => c,
        Err(JwtError::Expired) => return unauthorized("Token expired"),
        Err(e) => {
            tracing::debug!(error = %e, "JWT validation failed");
            return unauthorized("Invalid token");
        },
    };

    let role = match UserRole::from_str(&claims.role) {
        Some(r) => r,
        None => return unauthorized("Invalid role in token"),
    };

    let user_id = match claims.user_id() {
        Ok(id) => id,
        Err(_) => return unauthorized("Invalid user ID in token"),
    };

    let auth_user = AuthUser {
        user_id,
        username: claims.username.clone(),
        role,
        claims,
    };

    req.extensions_mut().insert(auth_user);
    next.run(req).await
}

/// Middleware: require the `admin` role.
/// Must be chained AFTER `require_auth` (which inserts `AuthUser`).
pub async fn require_admin(req: Request, next: Next) -> Response {
    let auth_user = match req.extensions().get::<AuthUser>().cloned() {
        Some(u) => u,
        None => return unauthorized("Authentication required"),
    };

    if !auth_user.role.is_admin() {
        return forbidden("Admin role required");
    }

    next.run(req).await
}

/// Axum extractor: pulls `AuthUser` from request extensions.
impl<S> axum::extract::FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or_else(|| unauthorized("Authentication required"))
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the IP-allowlist resolver helper.
    //!
    //! Covers the matrix in `tasks/ip-allowlist-spec.md` §6.1
    //! (12 cases for `resolve_client_ip`).

    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("test fixture: parse IP")
    }

    fn net(s: &str) -> IpNet {
        IpNet::from_str(s).expect("test fixture: parse CIDR")
    }

    fn hdr() -> HeaderMap {
        HeaderMap::new()
    }

    fn hdr_with_xff(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            xff.parse().expect("test fixture: xff header"),
        );
        h
    }

    // 1. peer_only_no_xff — no XFF, trusted_proxies empty → returns peer
    #[test]
    fn peer_only_no_xff() {
        let result = resolve_client_ip(&hdr(), Some(ip("203.0.113.10")), &[]);
        assert_eq!(result, Some(ip("203.0.113.10")));
    }

    // 2. peer_only_xff_untrusted — XFF set, peer not in trusted_proxies,
    //    trusted_proxies non-empty → returns peer (XFF ignored)
    #[test]
    fn peer_only_xff_untrusted() {
        let headers = hdr_with_xff("198.51.100.5");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("203.0.113.10")), &trusted);
        assert_eq!(result, Some(ip("203.0.113.10")));
    }

    // 3. peer_only_trusted_proxies_empty_xff_present — XFF set,
    //    trusted_proxies empty → returns peer (strict default)
    #[test]
    fn peer_only_trusted_proxies_empty_xff_present() {
        let headers = hdr_with_xff("198.51.100.5");
        let result = resolve_client_ip(&headers, Some(ip("203.0.113.10")), &[]);
        assert_eq!(result, Some(ip("203.0.113.10")));
    }

    // 4. xff_trusted_peer_in_list — XFF set, peer in trusted_proxies
    //    → returns parsed leftmost XFF entry
    #[test]
    fn xff_trusted_peer_in_list() {
        let headers = hdr_with_xff("198.51.100.5");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("198.51.100.5")));
    }

    // 5. xff_trusted_peer_in_list_malformed_xff — XFF unparseable,
    //    peer in trusted_proxies → falls back to peer
    #[test]
    fn xff_trusted_peer_in_list_malformed_xff() {
        let headers = hdr_with_xff("not-an-ip");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("10.0.0.5")));
    }

    // 6. xff_trusted_peer_in_list_empty_xff — XFF empty string,
    //    peer in trusted_proxies → falls back to peer
    #[test]
    fn xff_trusted_peer_in_list_empty_xff() {
        let headers = hdr_with_xff("");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("10.0.0.5")));
    }

    // 7. xff_trusted_peer_in_list_multi_hop — "1.2.3.4, 5.6.7.8"
    //    with peer in trusted_proxies → returns 1.2.3.4 (leftmost)
    #[test]
    fn xff_trusted_peer_in_list_multi_hop() {
        let headers = hdr_with_xff("1.2.3.4, 5.6.7.8");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("1.2.3.4")));
    }

    // 8. no_peer_no_xff — peer None, no XFF → returns None
    #[test]
    fn no_peer_no_xff() {
        let result = resolve_client_ip(&hdr(), None, &[net("10.0.0.0/8")]);
        assert_eq!(result, None);
    }

    // 9. no_peer_xff_untrusted — peer None, XFF set, trusted_proxies empty
    //    → returns None (caller fails closed)
    #[test]
    fn no_peer_xff_untrusted() {
        let headers = hdr_with_xff("198.51.100.5");
        let result = resolve_client_ip(&headers, None, &[]);
        assert_eq!(result, None);
    }

    // 10. xff_trusted_whitespace — XFF "  1.2.3.4", peer in trusted_proxies
    //     → returns 1.2.3.4 (trim)
    #[test]
    fn xff_trusted_whitespace() {
        let headers = hdr_with_xff("  198.51.100.5");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("198.51.100.5")));
    }

    // 11. trusted_proxies_ipv6 — peer in IPv6 trusted list, IPv6 XFF
    //     → returns XFF
    #[test]
    fn trusted_proxies_ipv6() {
        let headers = hdr_with_xff("2001:db8::1");
        let trusted = vec![net("::1/128"), net("2001:db8::/32")];
        let result = resolve_client_ip(&headers, Some(ip("2001:db8::ffff")), &trusted);
        assert_eq!(result, Some(ip("2001:db8::1")));
    }

    // 12. peer_ipv4_xff_ipv6_mismatch_trusted — peer in trusted list,
    //     XFF is IPv6 → returns parsed IPv6 (mixed family is fine)
    #[test]
    fn peer_ipv4_xff_ipv6_mismatch_trusted() {
        let headers = hdr_with_xff("2001:db8::dead");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("2001:db8::dead")));
    }
}

#[cfg(test)]
mod middleware_tests {
    //! End-to-end tests for the `require_auth` middleware IP-allowlist path.
    //!
    //! Uses a tiny in-process `axum::Router` with the middleware attached and
    //! `tower::ServiceExt::oneshot` to send synthetic requests. No DB, no real
    //! TCP listener.
    //!
    //! Mirrors the production wiring pattern in `pm-web/src/main.rs` (a
    //! `from_fn` closure that captures the `AuthConfig` and forwards to
    //! `require_auth`).
    //!
    //! For tests where the spec expects `200` (allowlist passed), we assert
    //! `401` instead — the JWT will fail validation against the empty verify
    //! key, which **proves the IP check did not short-circuit** (a 403 here
    //! would mean the IP check rejected the request).
    //!
    //! Per `tasks/ip-allowlist-spec.md` §6.1 tests 13–20.

    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    /// Stub handler that returns 200 OK if the middleware let the request
    /// through. JWT validation will fail in these tests, so the handler is
    /// only reached in the "IP check passed but JWT failed" scenarios we
    /// assert as `401`.
    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn build_test_app(auth_config: Arc<AuthConfig>) -> Router {
        Router::new()
            .route("/test", get(ok_handler))
            .layer(from_fn(move |req, next| {
                let cfg = auth_config.clone();
                async move { require_auth(cfg, req, next).await }
            }))
    }

    /// Build a request with the given extensions, headers, and an
    /// `Authorization: Bearer` token (which will fail JWT validation since
    /// the test `AuthConfig` has an empty verify key). Tests assert on the
    /// status code only — the body content is irrelevant.
    fn build_request(peer: Option<SocketAddr>, xff: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer test-token-invalid");
        if let Some(x) = xff {
            builder = builder.header("x-forwarded-for", x);
        }
        let mut req = builder.body(Body::empty()).expect("build request");
        if let Some(p) = peer {
            req.extensions_mut().insert(ConnectInfo(p));
        }
        req
    }

    fn peer_v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::from(([a, b, c, d], 1234))
    }

    // 13. middleware_allows_when_whitelist_empty — empty list + any IP
    //     → IP check skipped, request continues to JWT (which fails → 401).
    #[tokio::test]
    async fn middleware_allows_when_whitelist_empty() {
        let cfg = Arc::new(AuthConfig::new(String::new(), &[], &[]));
        let app = build_test_app(cfg);
        let req = build_request(Some(peer_v4(203, 0, 113, 10)), Some("10.0.0.5"));
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 14. middleware_denies_when_whitelist_non_empty_and_ip_not_in_list
    //     — non-empty list + peer outside → 403 forbidden_ip.
    #[tokio::test]
    async fn middleware_denies_when_whitelist_non_empty_and_ip_not_in_list() {
        let cfg = Arc::new(AuthConfig::new(
            String::new(),
            &["10.0.0.0/8".to_string()],
            &[],
        ));
        let app = build_test_app(cfg);
        let req = build_request(Some(peer_v4(203, 0, 113, 10)), None);
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 15. middleware_allows_when_ip_in_list — non-empty list + peer inside
    //     → 401 (JWT fails, IP check passed).
    #[tokio::test]
    async fn middleware_allows_when_ip_in_list() {
        let cfg = Arc::new(AuthConfig::new(
            String::new(),
            &["10.0.0.0/8".to_string()],
            &[],
        ));
        let app = build_test_app(cfg);
        let req = build_request(Some(peer_v4(10, 0, 0, 5)), None);
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 16. middleware_denies_when_no_peer_resolvable_and_whitelist_non_empty
    //     — non-empty list + missing ConnectInfo → 403 forbidden_ip (fail-closed).
    #[tokio::test]
    async fn middleware_denies_when_no_peer_resolvable_and_whitelist_non_empty() {
        let cfg = Arc::new(AuthConfig::new(
            String::new(),
            &["10.0.0.0/8".to_string()],
            &[],
        ));
        let app = build_test_app(cfg);
        let req = build_request(None, None); // no ConnectInfo
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 17. middleware_spoofed_xff_ignored_when_peer_untrusted
    //     — non-empty list + peer outside + XFF inside list → 403 forbidden_ip.
    #[tokio::test]
    async fn middleware_spoofed_xff_ignored_when_peer_untrusted() {
        let cfg = Arc::new(AuthConfig::new(
            String::new(),
            &["10.0.0.0/8".to_string()],
            &[],
        ));
        let app = build_test_app(cfg);
        // Peer is 203.0.113.10 (not in 10.0.0.0/8). XFF claims 10.0.0.5 but
        // trusted_proxies is empty, so XFF is ignored and peer is checked → 403.
        let req = build_request(Some(peer_v4(203, 0, 113, 10)), Some("10.0.0.5"));
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 18. middleware_trusted_proxy_honors_xff — peer in trusted_proxies +
    //     XFF inside allowlist → 401 (IP check passed, JWT fails).
    #[tokio::test]
    async fn middleware_trusted_proxy_honors_xff() {
        let cfg = Arc::new(AuthConfig::new(
            String::new(),
            &["10.0.0.0/8".to_string()],
            &["203.0.113.0/24".to_string()],
        ));
        let app = build_test_app(cfg);
        // Peer 203.0.113.10 is in trusted_proxies, so XFF "10.0.0.5" is used
        // and that IP is in the allowlist → IP check passes → JWT fails → 401.
        let req = build_request(Some(peer_v4(203, 0, 113, 10)), Some("10.0.0.5"));
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 19. middleware_trusted_proxy_falls_back_to_peer_on_bad_xff
    //     — peer in trusted_proxies + unparseable XFF + peer outside list → 403.
    #[tokio::test]
    async fn middleware_trusted_proxy_falls_back_to_peer_on_bad_xff() {
        let cfg = Arc::new(AuthConfig::new(
            String::new(),
            &["10.0.0.0/8".to_string()],
            &["203.0.113.0/24".to_string()],
        ));
        let app = build_test_app(cfg);
        // Peer 203.0.113.10 is in trusted_proxies. XFF is unparseable, so
        // resolver falls back to peer (203.0.113.10) which is NOT in
        // allowlist (10.0.0.0/8) → 403.
        let req = build_request(Some(peer_v4(203, 0, 113, 10)), Some("not-an-ip"));
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 20. middleware_no_jwt_when_ip_blocked — blocked request never reaches
    //     JWT validation. With an invalid token AND a denied IP, response is
    //     403 (forbidden_ip) NOT 401 (which would indicate JWT was reached).
    #[tokio::test]
    async fn middleware_no_jwt_when_ip_blocked() {
        let cfg = Arc::new(AuthConfig::new(
            String::new(),
            &["10.0.0.0/8".to_string()],
            &[],
        ));
        let app = build_test_app(cfg);
        // Peer 203.0.113.10 is outside allowlist, token is invalid.
        // If the IP check ran first, response is 403. If JWT ran first, 401.
        // We assert 403, proving the IP check short-circuited.
        let req = build_request(Some(peer_v4(203, 0, 113, 10)), None);
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
