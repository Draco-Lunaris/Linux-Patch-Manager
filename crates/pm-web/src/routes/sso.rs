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
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
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
pub struct OidcCache {
    pub discovery: Option<OidcDiscovery>,
    pub jwks: Option<serde_json::Value>,
    pub jwks_fetched_at: Option<chrono::DateTime<Utc>>,
}

impl Default for OidcCache {
    fn default() -> Self {
        Self {
            discovery: None,
            jwks: None,
            jwks_fetched_at: None,
        }
    }
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
                        display_name: name
                            .is_empty()
                            .then(|| existing.display_name.clone())
                            .unwrap_or(name),
                        role: existing.role.clone(),
                        is_active: existing.is_active,
                        mfa_enabled: existing.mfa_enabled,
                    }
                },
                None => {
                    // No existing user - create new one
                    let id: Uuid = match sqlx::query_scalar(
                        r#"INSERT INTO users (username, display_name, email, role, auth_provider, azure_oid, oidc_sub)
           VALUES ($1, $2, $3, 'operator'::user_role, $4::auth_provider, $5, $6)
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
                        role: "operator".to_string(),
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

    let redirect_url = format!(
        "{}?access_token={}&refresh_token={}&token_type=Bearer&expires_in={}&user={}",
        callback_url,
        urlencoding::encode(&access_token),
        urlencoding::encode(&raw_refresh.0),
        access_ttl,
        urlencoding::encode(&user_json.to_string()),
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
