//! Azure SSO OAuth2/OIDC flow routes.
//!
//! Public routes (no auth required):
//!   GET /api/v1/auth/azure/login    — redirect to Azure AD authorization URL
//!   GET /api/v1/auth/azure/callback — handle Azure AD callback, redirect to frontend SPA

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

/// Cache for Azure AD JWKS (JSON Web Key Set) with TTL-based refresh.
pub struct JwksCache {
    pub keys: Option<serde_json::Value>,
    pub fetched_at: Option<chrono::DateTime<Utc>>,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self {
            keys: None,
            fetched_at: None,
        }
    }
}

/// JWKS cache TTL in seconds (1 hour).
const JWKS_CACHE_TTL_SECS: i64 = 3600;

// ============================================================
// Router
// ============================================================

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/login", get(azure_login))
        .route("/callback", get(azure_callback))
}

// ============================================================
// GET /api/v1/auth/azure/login
// ============================================================

async fn azure_login(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    // Read Azure SSO config from DB
    let row: Option<(bool, String, String, String, String)> = sqlx::query_as(
        "SELECT enabled, tenant_id, client_id, redirect_uri, scopes FROM azure_sso_config WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to load azure_sso_config");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let (enabled, tenant_id, client_id, redirect_uri, scopes) = match row {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    json!({ "error": { "code": "forbidden", "message": "Azure SSO is not configured" } }),
                ),
            ));
        },
    };

    if !enabled {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({ "error": { "code": "forbidden", "message": "Azure SSO is not enabled" } }),
            ),
        ));
    }

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

    // Build authorization URL
    let encoded_scopes = urlencoding::encode(&scopes);
    let auth_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?client_id={}&response_type=code&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
        tenant_id, client_id, redirect_uri, encoded_scopes, code_challenge, state_token
    );

    // Redirect to Azure AD
    Ok(Redirect::to(&auth_url))
}

// ============================================================
// GET /api/v1/auth/azure/callback
// ============================================================

#[derive(Debug, Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn azure_callback(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<CallbackParams>,
) -> Result<Redirect, Redirect> {
    let callback_url = &state.config.security.sso_callback_url;

    // Helper to build error redirect
    let error_redirect = |code: &str, message: &str| -> Redirect {
        let url = format!(
            "{}?error={}&error_description={}",
            callback_url,
            urlencoding::encode(code),
            urlencoding::encode(message)
        );
        Redirect::to(&url)
    };

    // Check for error from Azure AD
    if let Some(error) = params.error {
        let desc = params.error_description.unwrap_or_default();
        let message = format!("Azure AD error: {} - {}", error, desc);
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

    // Look up code_verifier from sso_sessions
    let sso_session = match state.sso_sessions.remove(&state_token).map(|(_, v)| v) {
        Some(s) => s,
        None => {
            return Err(error_redirect(
                "bad_request",
                "Invalid or expired state token",
            ))
        },
    };

    // Read Azure SSO config (including client_secret for token exchange)
    let row: Option<(bool, String, String, String, String)> = match sqlx::query_as(
        "SELECT enabled, tenant_id, client_id, client_secret, redirect_uri FROM azure_sso_config WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Failed to load azure_sso_config");
            return Err(error_redirect("internal_error", "Database error"));
        }
    };

    let (_enabled, tenant_id, client_id, client_secret, redirect_uri) = match row {
        Some(r) => r,
        None => {
            return Err(error_redirect("internal_error", "Azure SSO not configured"));
        },
    };

    // Exchange code for tokens
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );

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

    let params = [
        ("grant_type", "authorization_code".to_string()),
        ("code", code.clone()),
        ("redirect_uri", redirect_uri.clone()),
        ("client_id", client_id.clone()),
        ("client_secret", client_secret.clone()),
        ("code_verifier", sso_session.code_verifier.clone()),
    ];

    let form_params: Vec<(&str, String)> = params.to_vec();

    let token_resp = match client.post(&token_url).form(&form_params).send().await {
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

    // Verify id_token JWT signature using Azure AD JWKS and validate claims
    let id_token = match token_data.id_token {
        Some(t) => t,
        None => return Err(error_redirect("sso_error", "No id_token in response")),
    };

    let claims = match verify_id_token(&id_token, &tenant_id, &client_id, &state.jwks_cache).await {
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
    let oid = claims.oid.unwrap_or_default();
    let preferred_username = claims.preferred_username.unwrap_or_else(|| email.clone());

    if email.is_empty() || oid.is_empty() {
        return Err(error_redirect(
            "sso_error",
            "Missing email or oid in id_token",
        ));
    }

    // Look up or create user
    let user_opt: Option<DbUserForSso> = match sqlx::query_as(
        r#"SELECT id, username, display_name, role, is_active, mfa_enabled
           FROM users WHERE email = $1 AND auth_provider = 'azure_sso'"#,
    )
    .bind(&email)
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
            // Auto-create user with role=operator, auth_provider=azure_sso
            let id: Uuid = match sqlx::query_scalar(
                r#"INSERT INTO users (username, display_name, email, role, auth_provider, azure_oid)
                   VALUES ($1, $2, $3, 'operator', 'azure_sso', $4)
                   RETURNING id"#,
            )
            .bind(&preferred_username)
            .bind(&name)
            .bind(&email)
            .bind(&oid)
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
                Some("azure_sso"),
                Some("user"),
                Some(&id.to_string()),
                json!({ "auth_provider": "azure_sso", "email": email }),
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
    };

    // Update last_login_at and azure_oid
    if let Err(e) = sqlx::query(
        "UPDATE users SET last_login_at = NOW(), azure_oid = COALESCE(azure_oid, $1) WHERE id = $2",
    )
    .bind(&oid)
    .bind(user.id)
    .execute(&state.db)
    .await
    {
        tracing::error!(error = %e, "Failed to update last_login_at");
        return Err(error_redirect("internal_error", "Database error"));
    }

    // Issue JWT access token + refresh token
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
        json!({ "auth_provider": "azure_sso" }),
        None,
        None,
    )
    .await;

    // Build user JSON for query parameter
    let user_json = json!({
        "id": user.id.to_string(),
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
    });

    // Redirect to frontend SPA with tokens as query parameters
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
// JWT Verification Helpers
// ============================================================

/// Verify the id_token JWT signature using Azure AD JWKS and validate standard claims.
///
/// Steps:
/// 1. Decode JWT header to extract `kid` (key ID)
/// 2. Fetch JWKS from Azure AD if cache is empty or expired (1-hour TTL)
/// 3. Find the matching JWK by `kid`
/// 4. Construct RSA public key from JWK modulus (`n`) and exponent (`e`)
/// 5. Validate issuer, audience, and expiry via `jsonwebtoken::decode`
async fn verify_id_token(
    token: &str,
    tenant_id: &str,
    client_id: &str,
    jwks_cache: &Arc<Mutex<JwksCache>>,
) -> Result<IdTokenClaims, String> {
    // 1. Decode JWT header to get the kid
    let header = decode_header(token).map_err(|e| format!("Failed to decode JWT header: {}", e))?;

    let kid = header.kid.ok_or("JWT header missing 'kid' field")?;

    // 2. Check JWKS cache — fetch if expired or missing
    let jwks = {
        let cache = jwks_cache.lock().await;
        let needs_fetch = match (&cache.keys, &cache.fetched_at) {
            (None, _) => true,
            (Some(_), None) => true,
            (Some(_), Some(fetched)) => {
                let elapsed = Utc::now().signed_duration_since(*fetched);
                elapsed.num_seconds() > JWKS_CACHE_TTL_SECS
            },
        };

        if needs_fetch {
            // Drop lock before making async HTTP request
            drop(cache);

            let jwks_value = fetch_jwks(tenant_id).await?;

            let mut cache = jwks_cache.lock().await;
            cache.keys = Some(jwks_value);
            cache.fetched_at = Some(Utc::now());
            cache.keys.clone().unwrap()
        } else {
            cache.keys.clone().unwrap()
        }
    };

    // 3. Find the matching JWK by kid
    let keys_array = jwks
        .get("keys")
        .ok_or("JWKS response missing 'keys' array")?
        .as_array()
        .ok_or("JWKS 'keys' is not an array")?;

    let jwk = keys_array
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid.as_str()))
        .ok_or_else(|| format!("No matching JWK found for kid: {}", kid))?;

    // 4. Construct RSA public key from JWK modulus (n) and exponent (e)
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

    // 5. Configure validation rules
    let mut validation = Validation::new(Algorithm::RS256);
    validation.iss = Some(HashSet::from([format!(
        "https://login.microsoftonline.com/{}/v2.0",
        tenant_id
    )]));
    validation.aud = Some(HashSet::from([client_id.to_string()]));
    validation.leeway = 60; // 60 seconds clock skew tolerance

    // 6. Decode and verify the JWT
    let token_data = decode::<IdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| format!("JWT signature verification failed: {}", e))?;

    Ok(token_data.claims)
}

/// Fetch the JWKS from the Azure AD discovery endpoint.
async fn fetch_jwks(tenant_id: &str) -> Result<serde_json::Value, String> {
    let jwks_url = format!(
        "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
        tenant_id
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client for JWKS fetch: {}", e))?;

    let resp = client
        .get(&jwks_url)
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
