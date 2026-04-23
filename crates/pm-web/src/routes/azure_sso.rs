//! Azure SSO OAuth2/OIDC flow routes.
//!
//! Public routes (no auth required):
//!   GET /api/v1/auth/azure/login    — redirect to Azure AD authorization URL
//!   GET /api/v1/auth/azure/callback — handle Azure AD callback

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Redirect},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use pm_auth::{jwt::issue_access_token, refresh};
use pm_core::audit::{log_event, AuditAction};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
                Json(json!({ "error": { "code": "forbidden", "message": "Azure SSO is not configured" } })),
            ));
        }
    };

    if !enabled {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Azure SSO is not enabled" } })),
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
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check for error from Azure AD
    if let Some(error) = params.error {
        let desc = params.error_description.unwrap_or_default();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "sso_error", "message": format!("Azure AD error: {} - {}", error, desc) } })),
        ));
    }

    let code = params.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "bad_request", "message": "Missing authorization code" } })),
        )
    })?;

    let state_token = params.state.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "bad_request", "message": "Missing state parameter" } })),
        )
    })?;

    // Look up code_verifier from sso_sessions
    let sso_session = state
        .sso_sessions
        .remove(&state_token)
        .map(|(_, v)| v)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": { "code": "bad_request", "message": "Invalid or expired state token" } })),
            )
        })?;

    // Read Azure SSO config (including client_secret for token exchange)
    let row: Option<(bool, String, String, String, String)> = sqlx::query_as(
        "SELECT enabled, tenant_id, client_id, client_secret, redirect_uri FROM azure_sso_config WHERE id = 1",
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

    let (_enabled, tenant_id, client_id, client_secret, redirect_uri) = match row {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Azure SSO not configured" } })),
            ));
        }
    };

    // Exchange code for tokens
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to build HTTP client");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "HTTP client error" } })),
            )
        })?;

    let params = [
        ("grant_type", "authorization_code".to_string()),
        ("code", code.clone()),
        ("redirect_uri", redirect_uri.clone()),
        ("client_id", client_id.clone()),
        ("client_secret", client_secret.clone()),
        ("code_verifier", sso_session.code_verifier.clone()),
    ];

    let form_params: Vec<(&str, String)> = params.to_vec();

    let token_resp = client
        .post(&token_url)
        .form(&form_params)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Token exchange request failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": { "code": "sso_error", "message": format!("Token exchange failed: {}", e) } })),
            )
        })?;

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        let body = token_resp.text().await.unwrap_or_default();
        tracing::error!(status = %status, body = %body, "Token exchange failed");
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": { "code": "sso_error", "message": format!("Token exchange failed: HTTP {}", status) } })),
        ));
    }

    let token_data: TokenResponse = token_resp
        .json()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to parse token response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Failed to parse token response" } })),
            )
        })?;

    // Decode id_token JWT (without verification — trust HTTPS channel)
    let id_token = token_data.id_token.ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": { "code": "sso_error", "message": "No id_token in response" } })),
        )
    })?;

    let claims = decode_jwt_payload(&id_token).map_err(|e| {
        tracing::error!(error = %e, "Failed to decode id_token");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Failed to decode id_token" } })),
        )
    })?;

    let email = claims.email.unwrap_or_default();
    let name = claims.name.unwrap_or_default();
    let oid = claims.oid.unwrap_or_default();
    let preferred_username = claims.preferred_username.unwrap_or_else(|| email.clone());

    if email.is_empty() || oid.is_empty() {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": { "code": "sso_error", "message": "Missing email or oid in id_token" } })),
        ));
    }

    // Look up or create user
    let user_opt: Option<DbUserForSso> = sqlx::query_as(
        r#"SELECT id, username, display_name, role, is_active, mfa_enabled
           FROM users WHERE email = $1 AND auth_provider = 'azure_sso'"#,
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to look up SSO user");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let user = match user_opt {
        Some(u) if !u.is_active => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": { "code": "account_disabled", "message": "Account is disabled" } })),
            ));
        }
        Some(u) => u,
        None => {
            // Auto-create user with role=operator, auth_provider=azure_sso
            let id: Uuid = sqlx::query_scalar(
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
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create SSO user");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Failed to create user" } })),
                )
            })?;

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
        }
    };

    // Update last_login_at and azure_oid
    sqlx::query("UPDATE users SET last_login_at = NOW(), azure_oid = COALESCE(azure_oid, $1) WHERE id = $2")
        .bind(&oid)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update last_login_at");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

    // Issue JWT access token + refresh token
    let access_ttl = state.config.security.jwt_access_ttl_secs as i64;
    let access_token = issue_access_token(
        user.id,
        &user.username,
        &user.role,
        access_ttl,
        &state.signing_key_pem,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to issue access token");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Token issuance failed" } })),
        )
    })?;

    let raw_refresh = refresh::issue(&state.db, user.id, None, None)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to issue refresh token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Refresh token issuance failed" } })),
            )
        })?;

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

    Ok(Json(json!({
        "access_token": access_token,
        "refresh_token": raw_refresh.0,
        "token_type": "Bearer",
        "expires_in": access_ttl,
        "user": {
            "id": user.id.to_string(),
            "username": user.username,
            "display_name": user.display_name,
            "role": user.role,
            "mfa_enabled": user.mfa_enabled,
        }
    })))
}

// ============================================================
// Helpers
// ============================================================

/// Decode JWT payload without verification (trust HTTPS channel from Azure AD).
fn decode_jwt_payload(token: &str) -> Result<IdTokenClaims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    let payload_b64 = parts[1];
    // Add padding if needed
    let mut payload_b64_padded = payload_b64.to_string();
    while payload_b64_padded.len() % 4 != 0 {
        payload_b64_padded.push('=');
    }

    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload_b64_padded)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JSON parse error: {}", e))
}
