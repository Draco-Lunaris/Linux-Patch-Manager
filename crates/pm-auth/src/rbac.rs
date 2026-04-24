//! Role-Based Access Control (RBAC) middleware for Axum.
//!
//! Provides:
//! - JWT extraction and validation from `Authorization: Bearer <token>` header
//! - Role enforcement (`admin`, `operator`)
//! - Group-scoped access (enforced at the handler level using `AuthUser` extension)
//! - IP whitelist enforcement

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use ipnet::IpNet;
use parking_lot::RwLock;
use serde_json::json;
use std::net::IpAddr;
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
}

impl UserRole {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
        }
    }

    /// Admin can do everything; operator has limited scope.
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }
}

/// Shared auth configuration injected via Axum state.
#[derive(Clone)]
pub struct AuthConfig {
    /// Ed25519 public key PEM for JWT verification.
    pub verify_key_pem: String,
    /// IP whitelist (empty = allow all). RwLock for runtime updates.
    pub ip_whitelist: Arc<RwLock<Vec<IpNet>>>,
}

impl AuthConfig {
    pub fn new(verify_key_pem: String, ip_whitelist_cidrs: &[String]) -> Self {
        let ip_whitelist = ip_whitelist_cidrs
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();

        Self {
            verify_key_pem,
            ip_whitelist: Arc::new(RwLock::new(ip_whitelist)),
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
}

/// Extract `Authorization: Bearer <token>` from request headers.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// Extract the remote IP from `X-Forwarded-For`.
fn extract_remote_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
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

/// Middleware: authenticate any valid JWT (admin or operator).
///
/// Inserts `AuthUser` into request extensions on success.
/// Rejects with 401 if token is missing/invalid, 403 if IP is blocked.
pub async fn require_auth(auth_config: Arc<AuthConfig>, mut req: Request, next: Next) -> Response {
    // IP whitelist check
    if let Some(ip) = extract_remote_ip(req.headers()) {
        if !auth_config.is_ip_allowed(&ip) {
            tracing::warn!(ip = %ip, "Request blocked by IP whitelist");
            return forbidden("Access denied");
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
