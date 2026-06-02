//! WebSocket relay routes — M7
//!
//! POST /api/v1/ws/ticket  — create a single-use WS auth ticket (JWT-protected)
//! GET  /api/v1/ws/jobs    — browser WebSocket endpoint (ticket-authenticated)

use axum::{
    extract::ws::{Message, WebSocket},
    extract::{Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{Json, Response},
    routing::{get, post},
    Router,
};
use chrono::{Duration, Utc};
use pm_auth::rbac::AuthUser;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::postgres::PgListener;
use ulid::Ulid;
use uuid::Uuid;

use crate::AppState;

// ── WsTicket ──────────────────────────────────────────────────────────────────

/// Single-use WebSocket authentication ticket stored in-memory.
#[derive(Debug, Clone)]
pub struct WsTicket {
    pub user_id: Uuid,
    pub role: String,
    pub expires_at: chrono::DateTime<Utc>,
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Router for ticket-issuance endpoint (JWT-protected, merged into protected_api).
pub fn ticket_router() -> Router<AppState> {
    Router::new().route("/ws/ticket", post(create_ticket_handler))
}

/// Router for the WebSocket endpoint (ticket-authenticated, NO JWT middleware).
pub fn ws_router() -> Router<AppState> {
    Router::new().route("/api/v1/ws/jobs", get(ws_handler))
}

// ── Error helper ─────────────────────────────────────────────────────────────

#[inline]
fn err(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
}

// ── Origin parsing & allowlist matching ───────────────────────────────────────

/// Parsed browser `Origin` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    /// `None` means "use scheme default" (80 for http, 443 for https).
    port: Option<u16>,
}

impl Origin {
    /// Render back to canonical `scheme://host[:port]` form with default
    /// ports normalized away (so `https://x:443` becomes `https://x`).
    fn canonical(&self) -> String {
        let default_port: Option<u16> = match self.scheme.as_str() {
            "https" => Some(443),
            "http" => Some(80),
            _ => None,
        };
        match (self.port, default_port) {
            (Some(p), Some(d)) if p == d => format!("{}://{}", self.scheme, self.host),
            (Some(p), _) => format!("{}://{}:{}", self.scheme, self.host, p),
            (None, _) => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Parse a raw `Origin` header value. Returns `None` for missing scheme,
/// unsupported schemes (only `http`/`https`), empty host, or whitespace in
/// the host. IPv6 literal hosts are explicitly rejected to keep the parser
/// simple — WebSocket connections from IPv6 browser origins are not a
/// realistic deployment for this product.
fn parse_origin_header(value: &str) -> Option<Origin> {
    let s = value.trim().trim_end_matches('/');
    if s.is_empty() {
        return None;
    }
    let (scheme, rest) = s.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    // Authority is everything up to the first `/`, `?`, or `#`.
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }
    // Treat the LAST `:` as the port separator. IPv6 literal hosts (e.g.
    // `[::1]`) contain a `:` inside the brackets; reject those.
    let (host, port_str) = match authority.rsplit_once(':') {
        Some((h, _)) if h.contains(':') => return None,
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let host = host.trim();
    if host.is_empty() || host.contains(char::is_whitespace) || host.contains(':') {
        return None;
    }
    let port = match port_str {
        Some(p) => match p.parse::<u16>() {
            Ok(n) => Some(n),
            Err(_) => return None,
        },
        None => None,
    };
    Some(Origin {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// Match a parsed `Origin` against an allowlist. Each allowlist entry is
/// itself parsed with [`parse_origin_header`] and compared by its canonical
/// string form, so entry syntax is forgiving (`https://x:443` matches an
/// incoming `https://x`). The host comparison is case-insensitive (the
/// parser lowercases the host); scheme and port are exact.
///
/// An empty allowlist returns `false` (fail-closed).
fn is_origin_allowed(origin: &Origin, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    let incoming = origin.canonical();
    allowlist.iter().any(|entry| {
        match parse_origin_header(entry) {
            Some(parsed) => parsed.canonical() == incoming,
            None => false,
        }
    })
}

/// Read the `Origin` header from a request and check it against the
/// configured allowlist. Returns `Ok(())` when the request may proceed; on
/// rejection returns the appropriate `(StatusCode, Json)` error tuple and
/// the reason string (for logging).
fn check_origin(
    headers: &HeaderMap,
    allowlist: &[String],
) -> Result<(), ((StatusCode, Json<Value>), &'static str)> {
    let raw = match headers.get(axum::http::header::ORIGIN) {
        Some(v) => v,
        None => {
            return Err((
                err(
                    StatusCode::FORBIDDEN,
                    "forbidden_origin",
                    "Origin header required",
                ),
                "missing",
            ));
        }
    };
    let raw_str = match raw.to_str() {
        Ok(s) => s,
        Err(_) => {
            return Err((
                err(
                    StatusCode::FORBIDDEN,
                    "forbidden_origin",
                    "Origin header not valid ASCII",
                ),
                "non-ascii",
            ));
        }
    };
    let origin = match parse_origin_header(raw_str) {
        Some(o) => o,
        None => {
            return Err((
                err(
                    StatusCode::FORBIDDEN,
                    "forbidden_origin",
                    "Malformed Origin header",
                ),
                "malformed",
            ));
        }
    };
    if !is_origin_allowed(&origin, allowlist) {
        return Err((
            err(
                StatusCode::FORBIDDEN,
                "forbidden_origin",
                "Origin not allowed",
            ),
            "not-allowlisted",
        ));
    }
    Ok(())
}

// ── POST /api/v1/ws/ticket ────────────────────────────────────────────────────

/// Issue a single-use WebSocket authentication ticket (60 s expiry).
pub async fn create_ticket_handler(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let ticket_id = Ulid::new().to_string();
    let expires_at = Utc::now() + Duration::seconds(60);

    let ticket = WsTicket {
        user_id: auth.user_id,
        role: auth.role.as_str().to_string(),
        expires_at,
    };

    state.ws_tickets.insert(ticket_id.clone(), ticket);

    tracing::info!(
        user_id = %auth.user_id,
        username = %auth.username,
        ticket = %ticket_id,
        "WS ticket issued"
    );

    Ok(Json(json!({ "ticket": ticket_id })))
}

// ── GET /api/v1/ws/jobs ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub ticket: String,
}

/// Browser WebSocket upgrade endpoint — authenticates via single-use ticket.
///
/// The handler enforces two independent gates, in this order:
///
/// 1. `Origin` header allowlist (CSWSH defense-in-depth). Performed first so
///    that a cross-origin probe with a leaked/stolen ticket does not consume
///    the legitimate user's ticket.
/// 2. Single-use, 60-second ticket (existing behavior, unchanged).
pub async fn ws_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, (StatusCode, Json<Value>)> {
    // Gate 1: Origin allowlist (CSWSH defense-in-depth).
    let allowlist = &state.config.security.allowed_origins;
    if let Err((http_err, reason)) = check_origin(&headers, allowlist) {
        let raw_origin = headers
            .get(axum::http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<absent>");
        // Never log the ticket value.
        tracing::warn!(
            reason = reason,
            origin = %raw_origin,
            "WebSocket upgrade rejected: forbidden origin"
        );
        return Err(http_err);
    }
    let allowed_origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Validate and consume the ticket atomically.
    let ticket = {
        let entry = state.ws_tickets.get(&q.ticket);
        match entry {
            None => {
                return Err(err(
                    StatusCode::UNAUTHORIZED,
                    "invalid_ticket",
                    "WebSocket ticket not found or already used",
                ));
            },
            Some(t) => {
                if t.expires_at < Utc::now() {
                    drop(t);
                    state.ws_tickets.remove(&q.ticket);
                    return Err(err(
                        StatusCode::UNAUTHORIZED,
                        "ticket_expired",
                        "WebSocket ticket has expired",
                    ));
                }
                t.clone()
            },
        }
    };
    // Single-use: remove immediately after validation.
    state.ws_tickets.remove(&q.ticket);

    tracing::info!(
        user_id = %ticket.user_id,
        role = %ticket.role,
        origin = %allowed_origin,
        "Browser WebSocket connection upgraded"
    );

    let db = state.db.clone();
    Ok(ws.on_upgrade(move |socket| handle_browser_ws(socket, db, ticket)))
}

// ── WebSocket handler ─────────────────────────────────────────────────────────

/// Drive the browser WebSocket: LISTEN on `job_update` and forward payloads.
async fn handle_browser_ws(mut socket: WebSocket, db: sqlx::PgPool, ticket: WsTicket) {
    // Acquire a dedicated PG listener connection.
    let mut listener = match PgListener::connect_with(&db).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, user_id = %ticket.user_id, "Failed to create PgListener");
            let _ = socket
                .send(Message::Text(
                    json!({ "error": "internal_error" }).to_string().into(),
                ))
                .await;
            return;
        },
    };

    if let Err(e) = listener.listen("job_update").await {
        tracing::error!(error = %e, user_id = %ticket.user_id, "PgListener LISTEN failed");
        return;
    }

    tracing::info!(user_id = %ticket.user_id, "Browser WS: LISTEN job_update started");

    loop {
        tokio::select! {
            // Forward PG notifications to the browser.
            notify_result = listener.recv() => {
                match notify_result {
                    Ok(notification) => {
                        let payload = notification.payload().to_string();
                        tracing::debug!(user_id = %ticket.user_id, payload = %payload, "Forwarding job_update");
                        if socket.send(Message::Text(payload.into())).await.is_err() {
                            tracing::info!(user_id = %ticket.user_id, "Browser WS send failed — client disconnected");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, user_id = %ticket.user_id, "PgListener recv error");
                        break;
                    }
                }
            }

            // Handle incoming frames from the browser (ping/close).
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        tracing::info!(user_id = %ticket.user_id, "Browser WS closed by client");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) if socket.send(Message::Pong(data.clone())).await.is_err() => {
                        break;
                    }
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, user_id = %ticket.user_id, "Browser WS recv error");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    tracing::info!(user_id = %ticket.user_id, "Browser WS handler exiting");
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_origin_header ─────────────────────────────────────────────────

    #[test]
    fn parse_basic_https() {
        assert_eq!(
            parse_origin_header("https://app.example.com"),
            Some(Origin {
                scheme: "https".into(),
                host: "app.example.com".into(),
                port: None,
            })
        );
    }

    #[test]
    fn parse_with_explicit_port() {
        assert_eq!(
            parse_origin_header("https://app.example.com:8443"),
            Some(Origin {
                scheme: "https".into(),
                host: "app.example.com".into(),
                port: Some(8443),
            })
        );
    }

    #[test]
    fn parse_lowercases_scheme() {
        assert_eq!(
            parse_origin_header("HTTPS://App.Example.com").unwrap().scheme,
            "https"
        );
    }

    #[test]
    fn parse_lowercases_host() {
        assert_eq!(
            parse_origin_header("https://App.Example.com").unwrap().host,
            "app.example.com"
        );
    }

    #[test]
    fn parse_ignores_path_query_fragment() {
        let o = parse_origin_header("https://app.example.com:443/some/path?q=1#frag").unwrap();
        assert_eq!(o.host, "app.example.com");
        assert_eq!(o.port, Some(443));
    }

    #[test]
    fn parse_strips_trailing_slash() {
        assert_eq!(
            parse_origin_header("https://app.example.com/"),
            Some(Origin {
                scheme: "https".into(),
                host: "app.example.com".into(),
                port: None,
            })
        );
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_origin_header("").is_none());
        assert!(parse_origin_header("   ").is_none());
    }

    #[test]
    fn parse_rejects_unsupported_scheme() {
        assert!(parse_origin_header("ftp://x").is_none());
        assert!(parse_origin_header("file:///etc/passwd").is_none());
        assert!(parse_origin_header("javascript:alert(1)").is_none());
    }

    #[test]
    fn parse_rejects_empty_host() {
        assert!(parse_origin_header("https://").is_none());
        assert!(parse_origin_header("https:///path").is_none());
    }

    #[test]
    fn parse_rejects_host_with_whitespace() {
        assert!(parse_origin_header("https://bad host").is_none());
    }

    #[test]
    fn parse_rejects_malformed_port() {
        assert!(parse_origin_header("https://x:notaport").is_none());
        assert!(parse_origin_header("https://x:99999").is_none());
    }

    #[test]
    fn parse_rejects_ipv6_literal() {
        assert!(parse_origin_header("https://[::1]").is_none());
    }

    #[test]
    fn parse_rejects_no_scheme_separator() {
        assert!(parse_origin_header("app.example.com").is_none());
    }

    // ── canonical ──────────────────────────────────────────────────────────

    #[test]
    fn canonical_strips_default_https_port() {
        let o = Origin {
            scheme: "https".into(),
            host: "x".into(),
            port: Some(443),
        };
        assert_eq!(o.canonical(), "https://x");
    }

    #[test]
    fn canonical_strips_default_http_port() {
        let o = Origin {
            scheme: "http".into(),
            host: "x".into(),
            port: Some(80),
        };
        assert_eq!(o.canonical(), "http://x");
    }

    #[test]
    fn canonical_keeps_non_default_port() {
        let o = Origin {
            scheme: "https".into(),
            host: "x".into(),
            port: Some(8443),
        };
        assert_eq!(o.canonical(), "https://x:8443");
    }

    // ── is_origin_allowed ──────────────────────────────────────────────────

    #[test]
    fn allowed_exact_match() {
        let o = parse_origin_header("https://app.example.com").unwrap();
        assert!(is_origin_allowed(&o, &["https://app.example.com".into()]));
    }

    #[test]
    fn allowed_default_port_normalization_incoming() {
        let o = parse_origin_header("https://app.example.com:443").unwrap();
        assert!(is_origin_allowed(&o, &["https://app.example.com".into()]));
    }

    #[test]
    fn allowed_default_port_normalization_allowlist() {
        let o = parse_origin_header("https://app.example.com").unwrap();
        assert!(is_origin_allowed(&o, &["https://app.example.com:443".into()]));
    }

    #[test]
    fn allowed_case_insensitive_host() {
        let o = parse_origin_header("https://App.Example.com").unwrap();
        assert!(is_origin_allowed(&o, &["https://app.example.com".into()]));
    }

    #[test]
    fn rejected_different_host() {
        let o = parse_origin_header("https://evil.example").unwrap();
        assert!(!is_origin_allowed(&o, &["https://app.example.com".into()]));
    }

    #[test]
    fn rejected_different_scheme() {
        let o = parse_origin_header("http://app.example.com").unwrap();
        assert!(!is_origin_allowed(&o, &["https://app.example.com".into()]));
    }

    #[test]
    fn rejected_different_port() {
        let o = parse_origin_header("https://app.example.com:8443").unwrap();
        assert!(!is_origin_allowed(&o, &["https://app.example.com".into()]));
    }

    #[test]
    fn rejected_empty_allowlist() {
        let o = parse_origin_header("https://app.example.com").unwrap();
        assert!(!is_origin_allowed(&o, &[]));
    }

    #[test]
    fn rejected_garbage_in_allowlist() {
        let o = parse_origin_header("https://app.example.com").unwrap();
        assert!(!is_origin_allowed(&o, &["not a url".into()]));
    }

    #[test]
    fn allowed_multi_entry_allowlist() {
        let o = parse_origin_header("https://app.example.com").unwrap();
        assert!(is_origin_allowed(
            &o,
            &[
                "https://other.example".into(),
                "https://app.example.com".into(),
            ]
        ));
    }

    // ── check_origin (integration of parse + allow) ────────────────────────

    #[test]
    fn check_rejects_missing_header() {
        let h = HeaderMap::new();
        let err = check_origin(&h, &["https://app.example.com".into()]).unwrap_err();
        assert_eq!(err.0 .0, StatusCode::FORBIDDEN);
        assert_eq!(err.1, "missing");
    }

    #[test]
    fn check_rejects_malformed_header() {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::ORIGIN, "not a url".parse().unwrap());
        let err = check_origin(&h, &["https://app.example.com".into()]).unwrap_err();
        assert_eq!(err.0 .0, StatusCode::FORBIDDEN);
        assert_eq!(err.1, "malformed");
    }

    #[test]
    fn check_rejects_disallowed_origin() {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::ORIGIN, "https://evil.example".parse().unwrap());
        let err = check_origin(&h, &["https://app.example.com".into()]).unwrap_err();
        assert_eq!(err.0 .0, StatusCode::FORBIDDEN);
        assert_eq!(err.1, "not-allowlisted");
    }

    #[test]
    fn check_rejects_empty_allowlist() {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::ORIGIN, "https://app.example.com".parse().unwrap());
        let err = check_origin(&h, &[]).unwrap_err();
        assert_eq!(err.0 .0, StatusCode::FORBIDDEN);
        assert_eq!(err.1, "not-allowlisted");
    }

    #[test]
    fn check_allows_valid_origin() {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::ORIGIN, "https://app.example.com".parse().unwrap());
        assert!(check_origin(&h, &["https://app.example.com".into()]).is_ok());
    }

    #[test]
    fn check_allows_default_port_normalization() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::ORIGIN,
            "https://app.example.com:443".parse().unwrap(),
        );
        assert!(check_origin(&h, &["https://app.example.com".into()]).is_ok());
    }

    #[test]
    fn check_allows_case_insensitive_host() {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::ORIGIN, "https://App.Example.com".parse().unwrap());
        assert!(check_origin(&h, &["https://app.example.com".into()]).is_ok());
    }
}
