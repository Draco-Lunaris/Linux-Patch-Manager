//! Generic OIDC SSO routes (Keycloak, Azure AD, Custom).
//!
//! Public routes (no auth required):
//!   GET /api/v1/auth/sso/login     — redirect to OIDC provider authorization URL
//!   GET /api/v1/auth/sso/callback  — handle OIDC provider callback, redirect to frontend SPA
//!
//! Backward-compatible aliases:
//!   GET /api/v1/auth/azure/login    → redirects to generic SSO login
//!   GET /api/v1/auth/azure/callback → redirects to generic SSO callback

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Redirect},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use dashmap::DashMap;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use pm_auth::{jwt::issue_access_token, refresh};
use pm_core::audit::{log_event, AuditAction};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::AppState;

// ============================================================
// Data structures
// ============================================================

#[derive(Clone)]
pub struct SsoSession {
    pub code_verifier: String,
    pub created_at: chrono::DateTime<Utc>,
}

/// Single-use, short-lived payload that the SSO callback hands to the SPA
/// via a `?handoff=<code>` query param. The SPA exchanges it via
/// `POST /api/v1/auth/sso/handoff` for the actual JWT access/refresh
/// tokens. Mirrors the WS-ticket pattern (issue #10): in-memory, atomic
/// single-use consume, TTL enforced on read.
///
/// See `tasks/sso-token-handoff-spec.md` §4.1 for the full design.
#[derive(Clone)]
pub struct SsoHandoff {
    /// JWT access token (short-lived, 15 min TTL).
    pub access_token: String,
    /// Opaque refresh token (long-lived, rotating).
    pub raw_refresh: String,
    /// JSON-serialized user object (id, username, display_name, role, etc.).
    pub user_json: Value,
    /// Access token TTL in seconds (for the `expires_in` field in the response).
    pub access_ttl: u64,
    /// Expiry instant; the exchange endpoint rejects codes past this time.
    pub expires_at: std::time::Instant,
}

/// TTL for SSO handoff codes. Short by design: the SPA should POST to
/// `/api/v1/auth/sso/handoff` within seconds of the redirect landing.
///
/// `dead_code` is allowed here because Phase 1 introduces the store
/// ahead of its consumer; the SSO callback rewrite in Phase 2 of
/// `tasks/sso-token-handoff-spec.md` inserts handoffs with this TTL and
/// the exchange handler reads it back to validate freshness.
#[allow(dead_code)]
pub const HANDOFF_TTL_SECS: u64 = 60;

/// Generate a cryptographically random handoff code (32 bytes,
/// base64url-encoded, ~43 chars). Uses the same `rand` crate family as
/// the WS-ticket path.
///
/// `dead_code` is allowed here for the same reason as `HANDOFF_TTL_SECS`
/// — Phase 2 wires it into the SSO callback redirect construction.
#[allow(dead_code)]
pub fn generate_handoff_code() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Request body for `POST /api/v1/auth/sso/handoff`.
///
/// The SPA sends the handoff code it received in the SSO callback
/// redirect's `?handoff=...` query param, and the backend exchanges it
/// for the actual access/refresh tokens. The code is single-use and
/// 60-second TTL.
#[derive(Debug, Deserialize)]
pub struct HandoffRequest {
    pub handoff_code: String,
}

// ============================================================
// Handoff exchange handler
// ============================================================

/// `POST /api/v1/auth/sso/handoff` — exchange a single-use handoff code
/// for the JWT access/refresh tokens + user object. Public route (no
/// JWT required) — the handoff code IS the credential.
///
/// See `tasks/sso-token-handoff-spec.md` §4.2 for the full design.
async fn sso_handoff_exchange(
    State(state): State<AppState>,
    Json(req): Json<HandoffRequest>,
) -> (StatusCode, Json<Value>) {
    sso_handoff_exchange_inner(&state.sso_handoffs, &req.handoff_code).await
}

/// Core exchange logic, separated from the HTTP handler so tests can
/// drive it with a bare `DashMap` (no need to construct a full
/// `AppState` with a real `sqlx::PgPool` and `Arc<AppConfig>`).
///
/// Marked `async` so the race test can use `tokio::join!` to drive
/// two concurrent exchanges against the same code; the function body
/// has no `.await` points (it only does a DashMap read and a return),
/// so this is a zero-cost abstraction.
async fn sso_handoff_exchange_inner(
    handoffs: &DashMap<String, SsoHandoff>,
    code: &str,
) -> (StatusCode, Json<Value>) {
    // Atomically remove the entry (single-use guarantee). If two
    // requests race with the same code, DashMap::remove is atomic so
    // only one wins.
    let removed = handoffs.remove(code);
    let Some((_code, handoff)) = removed else {
        tracing::warn!(
            reason = "unknown_or_already_consumed",
            "SSO handoff exchange failed"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": { "code": "invalid_handoff", "message": "Handoff code is invalid or has expired" }
            })),
        );
    };

    // Check expiry (the cleanup task also removes expired entries, but
    // there's a race between expiry and the next cleanup tick — check
    // here too so we never return a token for an expired handoff).
    if handoff.expires_at <= std::time::Instant::now() {
        tracing::warn!(reason = "expired", "SSO handoff exchange failed");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": { "code": "invalid_handoff", "message": "Handoff code is invalid or has expired" }
            })),
        );
    }

    // Log success without leaking the handoff code or the tokens
    let user_id = handoff
        .user_json
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    tracing::info!(user_id = %user_id, "SSO handoff exchanged");

    (
        StatusCode::OK,
        Json(json!({
            "access_token": handoff.access_token,
            "refresh_token": handoff.raw_refresh,
            "token_type": "Bearer",
            "expires_in": handoff.access_ttl,
            "user": handoff.user_json,
        })),
    )
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[allow(dead_code)]
    access_token: Option<String>,
    id_token: Option<String>,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    email: Option<String>,
    name: Option<String>,
    sub: Option<String>,
    oid: Option<String>,
    preferred_username: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct DbUserForSso {
    id: Uuid,
    username: String,
    display_name: String,
    role: String,
    is_active: bool,
    mfa_enabled: bool,
}

/// OIDC provider configuration from database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OidcConfig {
    pub enabled: bool,
    pub provider_type: String,
    pub display_name: String,
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: String,
}

/// Cached OIDC discovery document.
#[derive(Debug, Clone)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub fetched_at: chrono::DateTime<Utc>,
}

/// Cache for OIDC discovery documents and JWKS with TTL-based refresh.
#[derive(Default)]
pub struct OidcCache {
    pub discovery: Option<OidcDiscovery>,
    pub jwks: Option<serde_json::Value>,
    pub jwks_fetched_at: Option<chrono::DateTime<Utc>>,
}

/// JWKS cache TTL in seconds (1 hour).
const JWKS_CACHE_TTL_SECS: i64 = 3600;
/// Discovery cache TTL in seconds (1 hour).
const DISCOVERY_CACHE_TTL_SECS: i64 = 3600;

// ============================================================
// Router
// ============================================================

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/login", get(sso_login))
        .route("/callback", get(sso_callback))
        .route("/config", get(sso_config))
        // Issue #4: single-use handoff exchange. The SPA POSTs the
        // `?handoff=<code>` it received from the SSO callback redirect
        // and gets the JWT access/refresh tokens in the JSON response.
        // Public route (no JWT) — the handoff code IS the credential.
        // See `tasks/sso-token-handoff-spec.md` §4.2.
        .route("/handoff", post(sso_handoff_exchange))
}

/// Backward-compatible Azure SSO routes — redirect to generic SSO endpoints.
pub fn azure_compat_router() -> Router<AppState> {
    Router::new()
        .route("/login", get(azure_login_redirect))
        .route("/callback", get(azure_callback_redirect))
}

// ============================================================
// GET /api/v1/auth/sso/config
// ============================================================

/// Public endpoint returning minimal SSO configuration for the login page.
/// Returns only: enabled, display_name, auth_url — no secrets exposed.
async fn sso_config(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let config = match load_oidc_config(&state.db).await {
        Ok(c) => c,
        Err(_) => {
            // If we can't load config, SSO is effectively disabled
            return Ok(Json(json!({
                "enabled": false,
                "display_name": "SSO",
                "auth_url": ""
            })));
        },
    };

    Ok(Json(json!({
        "enabled": config.enabled,
        "display_name": if config.display_name.is_empty() { "SSO".to_string() } else { config.display_name },
        "auth_url": "/api/v1/auth/sso/login"
    })))
}

// ============================================================
// GET /api/v1/auth/sso/login
// ============================================================

async fn sso_login(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let config = load_oidc_config(&state.db).await?;

    if !config.enabled {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "SSO is not enabled" } })),
        ));
    }

    if config.discovery_url.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({ "error": { "code": "forbidden", "message": "SSO discovery URL is not configured" } }),
            ),
        ));
    }

    // Fetch OIDC discovery document (with caching)
    let discovery = match fetch_discovery(&state).await {
        Ok(d) => d,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "error": { "code": "internal_error", "message": format!("Failed to fetch OIDC discovery: {}", e) } }),
                ),
            ));
        },
    };

    // Generate PKCE code_verifier (32 random bytes → base64url)
    let mut verifier_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut verifier_bytes);
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    // code_challenge = BASE64URL(SHA256(code_verifier))
    let challenge_digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(challenge_digest);

    // Generate state token
    let state_token = Uuid::new_v4().to_string();

    // Store (state_token, code_verifier) in sso_sessions DashMap
    state.sso_sessions.insert(
        state_token.clone(),
        SsoSession {
            code_verifier,
            created_at: Utc::now(),
        },
    );

    // Build authorization URL from discovery
    let encoded_scopes = urlencoding::encode(&config.scopes);
    let auth_url = format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
        discovery.authorization_endpoint,
        urlencoding::encode(&config.client_id),
        urlencoding::encode(&config.redirect_uri),
        encoded_scopes,
        code_challenge,
        state_token
    );

    Ok(Redirect::to(&auth_url))
}

// ============================================================
// GET /api/v1/auth/sso/callback
// ============================================================

#[derive(Debug, Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn sso_callback(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<CallbackParams>,
) -> Result<Redirect, Redirect> {
    let callback_url = &state.config.security.sso_callback_url;

    let error_redirect = |code: &str, message: &str| -> Redirect {
        let url = format!(
            "{}?error={}&error_description={}",
            callback_url,
            urlencoding::encode(code),
            urlencoding::encode(message)
        );
        Redirect::to(&url)
    };

    if let Some(error) = params.error {
        let desc = params.error_description.unwrap_or_default();
        let message = format!("OIDC provider error: {} - {}", error, desc);
        return Err(error_redirect("sso_error", &message));
    }

    let code = match params.code {
        Some(c) => c,
        None => return Err(error_redirect("bad_request", "Missing authorization code")),
    };

    let state_token = match params.state {
        Some(s) => s,
        None => return Err(error_redirect("bad_request", "Missing state parameter")),
    };

    let sso_session = match state.sso_sessions.remove(&state_token).map(|(_, v)| v) {
        Some(s) => s,
        None => {
            return Err(error_redirect(
                "bad_request",
                "Invalid or expired state token",
            ))
        },
    };

    let config = match load_oidc_config(&state.db).await {
        Ok(c) => c,
        Err(_) => {
            return Err(error_redirect(
                "internal_error",
                "Failed to load OIDC config",
            ))
        },
    };

    let discovery = match fetch_discovery(&state).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to fetch OIDC discovery");
            return Err(error_redirect(
                "internal_error",
                "Failed to fetch OIDC discovery",
            ));
        },
    };

    // Exchange code for tokens
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build HTTP client");
            return Err(error_redirect("internal_error", "HTTP client error"));
        },
    };

    let mut params_vec: Vec<(&str, String)> = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.clone()),
        ("redirect_uri", config.redirect_uri.clone()),
        ("client_id", config.client_id.clone()),
        ("code_verifier", sso_session.code_verifier.clone()),
    ];

    // For confidential clients (Azure AD), include client_secret
    if !config.client_secret.is_empty() {
        params_vec.push(("client_secret", config.client_secret.clone()));
    }

    let token_resp = match client
        .post(&discovery.token_endpoint)
        .form(&params_vec)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Token exchange request failed");
            return Err(error_redirect(
                "sso_error",
                &format!("Token exchange failed: {}", e),
            ));
        },
    };

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        let body = token_resp.text().await.unwrap_or_default();
        tracing::error!(status = %status, body = %body, "Token exchange failed");
        return Err(error_redirect(
            "sso_error",
            &format!("Token exchange failed: HTTP {}", status),
        ));
    }

    let token_data: TokenResponse = match token_resp.json().await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse token response");
            return Err(error_redirect(
                "internal_error",
                "Failed to parse token response",
            ));
        },
    };

    let id_token = match token_data.id_token {
        Some(t) => t,
        None => return Err(error_redirect("sso_error", "No id_token in response")),
    };

    let claims = match verify_id_token(&id_token, &config, &discovery, &state.oidc_cache).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to verify id_token");
            return Err(error_redirect(
                "internal_error",
                "Failed to verify id_token",
            ));
        },
    };

    let email = claims.email.unwrap_or_default();
    let name = claims.name.unwrap_or_default();
    let oidc_sub = claims.sub.unwrap_or_default();
    let azure_oid = claims.oid.unwrap_or_default();
    let preferred_username = claims.preferred_username.unwrap_or_else(|| email.clone());

    let provider_subject = if !oidc_sub.is_empty() {
        oidc_sub.clone()
    } else if !azure_oid.is_empty() {
        azure_oid.clone()
    } else {
        return Err(error_redirect(
            "sso_error",
            "Missing subject identifier in id_token",
        ));
    };

    if email.is_empty() {
        return Err(error_redirect("sso_error", "Missing email in id_token"));
    }

    let auth_provider = match config.provider_type.as_str() {
        "keycloak" => "keycloak",
        "azure" => "azure_sso",
        _ => "oidc",
    };

    // First try exact match: email AND auth_provider
    let user_opt: Option<DbUserForSso> = match sqlx::query_as(
        r#"SELECT id, username, display_name, role::text as role, is_active, mfa_enabled
       FROM users WHERE email = $1 AND auth_provider = $2::auth_provider"#,
    )
    .bind(&email)
    .bind(auth_provider)
    .fetch_optional(&state.db)
    .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "Failed to look up SSO user");
            return Err(error_redirect("internal_error", "Database error"));
        },
    };

    let user = match user_opt {
        Some(u) if !u.is_active => {
            return Err(error_redirect("account_disabled", "Account is disabled"));
        },
        Some(u) => u,
        None => {
            // Try to find existing user by email alone (may have different auth_provider)
            let existing_user: Option<DbUserForSso> = match sqlx::query_as(
                r#"SELECT id, username, display_name, role::text as role, is_active, mfa_enabled
                   FROM users WHERE email = $1"#,
            )
            .bind(&email)
            .fetch_optional(&state.db)
            .await
            {
                Ok(o) => o,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to look up existing user by email");
                    return Err(error_redirect("internal_error", "Database error"));
                },
            };

            match existing_user {
                Some(existing) if !existing.is_active => {
                    return Err(error_redirect("account_disabled", "Account is disabled"));
                },
                Some(existing) => {
                    // Link existing local user to SSO provider
                    tracing::info!(user_id = %existing.id, "Linking existing user to SSO provider");
                    if let Err(e) = sqlx::query(
"UPDATE users SET auth_provider = $1::auth_provider, azure_oid = COALESCE(azure_oid, $2), oidc_sub = COALESCE(oidc_sub, $3) WHERE id = $4",
                    )
                    .bind(auth_provider)
                    .bind(if azure_oid.is_empty() { None } else { Some(azure_oid.as_str()) })
                    .bind(if provider_subject.is_empty() { None } else { Some(provider_subject.as_str()) })
                    .bind(existing.id)
                    .execute(&state.db)
                    .await
                    {
                        tracing::error!(error = %e, "Failed to link user to SSO provider");
                        return Err(error_redirect("internal_error", "Failed to link SSO account"));
                    }

                    log_event(
                        &state.db,
                        AuditAction::UserCreated,
                        None,
                        Some(auth_provider),
                        Some("user"),
                        Some(&existing.id.to_string()),
                        json!({ "action": "sso_link", "auth_provider": auth_provider, "email": email }),
                        None,
                        None,
                    )
                    .await;

                    DbUserForSso {
                        id: existing.id,
                        username: existing.username.clone(),
                        display_name: if name.is_empty() {
                            existing.display_name.clone()
                        } else {
                            name
                        },
                        role: existing.role.clone(),
                        is_active: existing.is_active,
                        mfa_enabled: existing.mfa_enabled,
                    }
                },
                None => {
                    // No existing user - create new one
                    let id: Uuid = match sqlx::query_scalar(
                    r#"INSERT INTO users (username, display_name, email, role, auth_provider, azure_oid, oidc_sub)
           VALUES ($1, $2, $3, 'reporter'::user_role, $4::auth_provider, $5, $6)
                            RETURNING id"#,
                    )
                    .bind(&preferred_username)
                    .bind(&name)
                    .bind(&email)
                    .bind(auth_provider)
                    .bind(if azure_oid.is_empty() { None } else { Some(azure_oid.as_str()) })
                    .bind(if provider_subject.is_empty() { None } else { Some(provider_subject.as_str()) })
                    .fetch_one(&state.db)
                    .await
                    {
                        Ok(id) => id,
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to create SSO user");
                            return Err(error_redirect("internal_error", "Failed to create user"));
                        },
                    };

                    log_event(
                        &state.db,
                        AuditAction::UserCreated,
                        None,
                        Some(auth_provider),
                        Some("user"),
                        Some(&id.to_string()),
                        json!({ "auth_provider": auth_provider, "email": email }),
                        None,
                        None,
                    )
                    .await;

                    DbUserForSso {
                        id,
                        username: preferred_username,
                        display_name: name,
                        role: "reporter".to_string(),
                        is_active: true,
                        mfa_enabled: false,
                    }
                },
            }
        },
    };

    // Update last_login_at and provider subject IDs
    if let Err(e) = sqlx::query(
        "UPDATE users SET last_login_at = NOW(), azure_oid = COALESCE(azure_oid, $1), oidc_sub = COALESCE(oidc_sub, $2) WHERE id = $3",
    )
    .bind(if azure_oid.is_empty() { None } else { Some(azure_oid.as_str()) })
    .bind(if provider_subject.is_empty() { None } else { Some(provider_subject.as_str()) })
    .bind(user.id)
    .execute(&state.db)
    .await
    {
        tracing::error!(error = %e, "Failed to update last_login_at");
        return Err(error_redirect("internal_error", "Database error"));
    }

    let access_ttl = state.config.security.jwt_access_ttl_secs as i64;
    let access_token = match issue_access_token(
        user.id,
        &user.username,
        &user.role,
        access_ttl,
        &state.signing_key_pem,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue access token");
            return Err(error_redirect("internal_error", "Token issuance failed"));
        },
    };

    let raw_refresh = match refresh::issue(&state.db, user.id, None, None).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue refresh token");
            return Err(error_redirect(
                "internal_error",
                "Refresh token issuance failed",
            ));
        },
    };

    log_event(
        &state.db,
        AuditAction::UserLogin,
        Some(user.id),
        Some(&user.username),
        None,
        None,
        json!({ "auth_provider": auth_provider }),
        None,
        None,
    )
    .await;

    let user_json = json!({
        "id": user.id.to_string(),
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "auth_provider": auth_provider,
        "mfa_enabled": user.mfa_enabled,
    });

    // Issue #4 fix: instead of embedding access/refresh tokens in the
    // redirect URL (which leaks through browser history, proxy access
    // logs, and the Referer header), generate a single-use, 60s handoff
    // code, store the payload in `sso_handoffs`, and put ONLY the code
    // in the redirect. The SPA POSTs to `/api/v1/auth/sso/handoff` to
    // exchange the code for tokens. See `tasks/sso-token-handoff-spec.md`
    // §4.1.
    let handoff_code = generate_handoff_code();
    state.sso_handoffs.insert(
        handoff_code.clone(),
        SsoHandoff {
            access_token: access_token.clone(),
            raw_refresh: raw_refresh.0.clone(),
            user_json: user_json.clone(),
            access_ttl: access_ttl as u64,
            expires_at: std::time::Instant::now()
                + std::time::Duration::from_secs(HANDOFF_TTL_SECS),
        },
    );

    let redirect_url = format!("{}?handoff={}", callback_url, handoff_code);

    tracing::info!(
        user_id = %user.id,
        auth_provider = %auth_provider,
        "SSO handoff issued"
    );

    Ok(Redirect::to(&redirect_url))
}

// ============================================================
// Backward-compatible Azure SSO redirect handlers
// ============================================================

async fn azure_login_redirect(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    sso_login(State(state)).await
}

async fn azure_callback_redirect(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<CallbackParams>,
) -> Result<Redirect, Redirect> {
    sso_callback(State(state), axum::extract::Query(params)).await
}

// ============================================================
// Database helpers
// ============================================================

async fn load_oidc_config(pool: &sqlx::PgPool) -> Result<OidcConfig, (StatusCode, Json<Value>)> {
    let row: Option<OidcConfig> = sqlx::query_as(
        "SELECT enabled, provider_type, display_name, discovery_url, client_id, client_secret, redirect_uri, scopes FROM oidc_config WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to load oidc_config");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    Ok(row.unwrap_or(OidcConfig {
        enabled: false,
        provider_type: "azure".to_string(),
        display_name: "Azure AD".to_string(),
        discovery_url: String::new(),
        client_id: String::new(),
        client_secret: String::new(),
        redirect_uri: String::new(),
        scopes: "openid profile email".to_string(),
    }))
}

// ============================================================
// OIDC Discovery & JWKS
// ============================================================

async fn fetch_discovery(state: &AppState) -> Result<OidcDiscovery, String> {
    let config = match load_oidc_config(&state.db).await {
        Ok(c) => c,
        Err(_) => {
            return Err("Failed to load OIDC config".to_string());
        },
    };
    let discovery_url = config.discovery_url;

    // Check cache first
    {
        let cache = state.oidc_cache.lock().await;
        if let Some(ref disc) = cache.discovery {
            let elapsed = Utc::now().signed_duration_since(disc.fetched_at);
            if elapsed.num_seconds() < DISCOVERY_CACHE_TTL_SECS {
                return Ok(disc.clone());
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let resp = client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| format!("Discovery fetch failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "Discovery fetch failed: HTTP {} — {}",
            status, body
        ));
    }

    let doc: Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse discovery document: {}", e))?;

    let discovery = OidcDiscovery {
        issuer: doc
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        authorization_endpoint: doc
            .get("authorization_endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        token_endpoint: doc
            .get("token_endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        jwks_uri: doc
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        userinfo_endpoint: doc
            .get("userinfo_endpoint")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        fetched_at: Utc::now(),
    };

    {
        let mut cache = state.oidc_cache.lock().await;
        cache.discovery = Some(discovery.clone());
    }

    Ok(discovery)
}

async fn verify_id_token(
    token: &str,
    config: &OidcConfig,
    discovery: &OidcDiscovery,
    oidc_cache: &Arc<Mutex<OidcCache>>,
) -> Result<IdTokenClaims, String> {
    let header = decode_header(token).map_err(|e| format!("Failed to decode JWT header: {}", e))?;
    let kid = header.kid.ok_or("JWT header missing 'kid' field")?;

    let jwks = {
        let cache = oidc_cache.lock().await;
        let needs_fetch = match (&cache.jwks, &cache.jwks_fetched_at) {
            (None, _) => true,
            (Some(_), None) => true,
            (Some(_), Some(fetched)) => {
                let elapsed = Utc::now().signed_duration_since(*fetched);
                elapsed.num_seconds() > JWKS_CACHE_TTL_SECS
            },
        };

        if needs_fetch {
            drop(cache);
            let jwks_value = fetch_jwks(&discovery.jwks_uri).await?;
            let mut cache = oidc_cache.lock().await;
            cache.jwks = Some(jwks_value);
            cache.jwks_fetched_at = Some(Utc::now());
            cache.jwks.clone().unwrap()
        } else {
            cache.jwks.clone().unwrap()
        }
    };

    let keys_array = jwks
        .get("keys")
        .ok_or("JWKS response missing 'keys' array")?
        .as_array()
        .ok_or("JWKS 'keys' is not an array")?;

    let jwk = keys_array
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid.as_str()))
        .ok_or_else(|| format!("No matching JWK found for kid: {}", kid))?;

    let n = jwk
        .get("n")
        .and_then(|v| v.as_str())
        .ok_or("JWK missing 'n' (modulus) field")?;
    let e = jwk
        .get("e")
        .and_then(|v| v.as_str())
        .ok_or("JWK missing 'e' (exponent) field")?;

    let decoding_key = DecodingKey::from_rsa_components(n, e)
        .map_err(|e| format!("Failed to construct RSA decoding key: {}", e))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.iss = Some(HashSet::from([discovery.issuer.clone()]));
    validation.aud = Some(HashSet::from([config.client_id.clone()]));
    validation.leeway = 60;

    let token_data = decode::<IdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| format!("JWT signature verification failed: {}", e))?;

    Ok(token_data.claims)
}

async fn fetch_jwks(jwks_uri: &str) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client for JWKS fetch: {}", e))?;

    let resp = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| format!("JWKS fetch request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("JWKS fetch failed: HTTP {} — {}", status, body));
    }

    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Failed to parse JWKS response: {}", e))
}

#[cfg(test)]
mod tests {
    //! Unit tests for the SSO handoff exchange endpoint and cleanup task.
    //!
    //! Per `tasks/sso-token-handoff-spec.md` §6.1–6.2.
    //!
    //! The tests call `sso_handoff_exchange_inner` directly with a bare
    //! `DashMap<String, SsoHandoff>`. This avoids the need to construct
    //! a full `AppState` (which has `sqlx::PgPool` and `Arc<AppConfig>`
    //! fields that can't be cheaply mocked) and keeps the tests focused
    //! on the exchange logic. The HTTP handler is a thin wrapper that
    //! extracts the code from the request body and delegates.

    use super::*;
    use dashmap::DashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn fresh_handoffs() -> Arc<DashMap<String, SsoHandoff>> {
        Arc::new(DashMap::new())
    }

    fn make_handoff(access: &str, refresh: &str, user_id: &str) -> SsoHandoff {
        SsoHandoff {
            access_token: access.to_string(),
            raw_refresh: refresh.to_string(),
            user_json: json!({ "id": user_id, "username": "testuser" }),
            access_ttl: 900,
            expires_at: Instant::now() + Duration::from_secs(HANDOFF_TTL_SECS),
        }
    }

    /// 1. handoff_exchange_success — create a handoff, exchange it,
    ///    expect 200 with the access/refresh/user fields.
    #[tokio::test]
    async fn handoff_exchange_success() {
        let handoffs = fresh_handoffs();
        let code = generate_handoff_code();
        handoffs.insert(
            code.clone(),
            make_handoff("jwt-access", "refresh-raw", "user-123"),
        );

        let (status, body) = sso_handoff_exchange_inner(&handoffs, &code).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["access_token"], "jwt-access");
        assert_eq!(body["refresh_token"], "refresh-raw");
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 900);
        assert_eq!(body["user"]["id"], "user-123");
    }

    /// 2. handoff_exchange_single_use — exchange once (success),
    ///    exchange the same code again (expect 400 invalid_handoff).
    #[tokio::test]
    async fn handoff_exchange_single_use() {
        let handoffs = fresh_handoffs();
        let code = generate_handoff_code();
        handoffs.insert(code.clone(), make_handoff("a", "r", "u"));

        // First exchange succeeds
        let (status1, _) = sso_handoff_exchange_inner(&handoffs, &code).await;
        assert_eq!(status1, StatusCode::OK);

        // Second exchange with the same code fails (entry was removed)
        let (status2, body2) = sso_handoff_exchange_inner(&handoffs, &code).await;
        assert_eq!(status2, StatusCode::BAD_REQUEST);
        assert_eq!(body2["error"]["code"], "invalid_handoff");
    }

    /// 3. handoff_exchange_unknown_code — exchange a code that was
    ///    never issued (expect 400 invalid_handoff).
    #[tokio::test]
    async fn handoff_exchange_unknown_code() {
        let handoffs = fresh_handoffs();
        let (status, body) = sso_handoff_exchange_inner(&handoffs, "never-issued-code").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_handoff");
    }

    /// 4. handoff_exchange_expired_code — create a handoff with
    ///    expires_at in the past, exchange (expect 400 invalid_handoff).
    #[tokio::test]
    async fn handoff_exchange_expired_code() {
        let handoffs = fresh_handoffs();
        let code = generate_handoff_code();
        let mut h = make_handoff("a", "r", "u");
        h.expires_at = Instant::now() - Duration::from_secs(1); // already expired
        handoffs.insert(code.clone(), h);

        let (status, body) = sso_handoff_exchange_inner(&handoffs, &code).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_handoff");
    }

    /// 5. handoff_exchange_race — two concurrent exchanges with the
    ///    same code; exactly one succeeds, the other gets 400.
    #[tokio::test]
    async fn handoff_exchange_race() {
        let handoffs = fresh_handoffs();
        let code = generate_handoff_code();
        handoffs.insert(code.clone(), make_handoff("a", "r", "u"));

        // DashMap::remove is atomic, so only one of two concurrent
        // calls can win. The other gets None and returns 400.
        let h1 = handoffs.clone();
        let h2 = handoffs.clone();
        let c1 = code.clone();
        let c2 = code.clone();
        let (r1, r2) = tokio::join!(
            sso_handoff_exchange_inner(&h1, &c1),
            sso_handoff_exchange_inner(&h2, &c2),
        );

        let status1 = r1.0;
        let status2 = r2.0;
        let successes = [status1, status2]
            .iter()
            .filter(|s| **s == StatusCode::OK)
            .count();
        let failures = [status1, status2]
            .iter()
            .filter(|s| **s == StatusCode::BAD_REQUEST)
            .count();
        assert_eq!(successes, 1, "exactly one exchange should succeed");
        assert_eq!(failures, 1, "exactly one exchange should fail");
    }

    /// 6. handoff_exchange_malformed_body — exchange with an empty
    ///    code (expect 400 invalid_handoff).
    #[tokio::test]
    async fn handoff_exchange_malformed_body() {
        let handoffs = fresh_handoffs();
        let (status, body) = sso_handoff_exchange_inner(&handoffs, "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_handoff");
    }

    /// 7. handoff_cleanup_removes_expired — create 3 handoffs with
    ///    varying `expires_at`, run one tick of the cleanup task,
    ///    assert only the non-expired ones remain.
    #[tokio::test]
    async fn handoff_cleanup_removes_expired() {
        let handoffs = fresh_handoffs();
        // 2 expired, 1 fresh
        for (i, expired) in [true, false, true].iter().enumerate() {
            let mut h = make_handoff(&format!("a{}", i), "r", "u");
            if *expired {
                h.expires_at = Instant::now() - Duration::from_secs(1);
            }
            handoffs.insert(format!("code-{}", i), h);
        }
        assert_eq!(handoffs.len(), 3);

        // Simulate one tick of the cleanup task (mirrors the logic
        // in main.rs lines 174-188)
        let now = Instant::now();
        handoffs.retain(|_, v| v.expires_at > now);

        assert_eq!(handoffs.len(), 1);
        assert!(handoffs.contains_key("code-1"));
    }
}
