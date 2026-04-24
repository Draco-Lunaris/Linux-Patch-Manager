//! Authentication route handlers.
//!
//! Public routes (no auth required):
//!   POST /api/v1/auth/login
//!   POST /api/v1/auth/refresh
//!   POST /api/v1/auth/logout
//!
//! Protected routes (JWT required):
//!   GET  /api/v1/auth/mfa/setup
//!   POST /api/v1/auth/mfa/verify

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use pm_auth::{
    mfa_totp,
    rbac::AuthUser,
    session::{self, LoginRequest, LoginResponse},
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;

// ============================================================
// Public router — no authentication required
// ============================================================

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login_handler))
        .route("/refresh", post(refresh_handler))
        .route("/logout", post(logout_handler))
}

// ============================================================
// Protected router — requires valid JWT (applied by caller)
// ============================================================

pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/mfa/setup", get(mfa_setup_handler))
        .route("/mfa/verify", post(mfa_verify_handler))
}

// ============================================================
// Helpers
// ============================================================

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn remote_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
}

// ============================================================
// POST /api/v1/auth/login
// ============================================================

async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<Value>)> {
    let ip = remote_ip(&headers);
    let ua = user_agent(&headers);

    session::login(
        &state.db,
        &req,
        &state.signing_key_pem,
        state.config.security.jwt_access_ttl_secs as i64,
        ua.as_deref(),
        ip.as_deref(),
    )
    .await
    .map(Json)
    .map_err(|e| {
        use pm_auth::session::SessionError;
        let (status, code, message) = match e {
            SessionError::InvalidCredentials | SessionError::InvalidMfaCode => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid username or password",
            ),
            SessionError::MfaRequired => (
                StatusCode::UNAUTHORIZED,
                "mfa_required",
                "MFA code required",
            ),
            SessionError::AccountDisabled => (
                StatusCode::FORBIDDEN,
                "account_disabled",
                "Account is disabled",
            ),
            _ => {
                tracing::error!(error = %e, "Login error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An error occurred",
                )
            },
        };
        (
            status,
            Json(json!({ "error": { "code": code, "message": message } })),
        )
    })
}

// ============================================================
// POST /api/v1/auth/refresh
// ============================================================

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

async fn refresh_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<Value>)> {
    let ip = remote_ip(&headers);
    let ua = user_agent(&headers);

    session::refresh_session(
        &state.db,
        &req.refresh_token,
        &state.signing_key_pem,
        state.config.security.jwt_access_ttl_secs as i64,
        ua.as_deref(),
        ip.as_deref(),
    )
    .await
    .map(Json)
    .map_err(|e| {
        use pm_auth::session::SessionError;
        let (status, code, msg) = match e {
            SessionError::Refresh(_) => (
                StatusCode::UNAUTHORIZED,
                "invalid_refresh_token",
                "Refresh token is invalid or expired",
            ),
            SessionError::AccountDisabled => (
                StatusCode::FORBIDDEN,
                "account_disabled",
                "Account is disabled",
            ),
            _ => {
                tracing::error!(error = %e, "Refresh error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An error occurred",
                )
            },
        };
        (
            status,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    })
}

// ============================================================
// POST /api/v1/auth/logout
// ============================================================

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    refresh_token: String,
}

async fn logout_handler(
    State(state): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    session::logout(&state.db, &req.refresh_token)
        .await
        .map(|_| Json(json!({ "message": "Logged out successfully" })))
        .map_err(|e| {
            tracing::error!(error = %e, "Logout error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "An error occurred" } })),
            )
        })
}

// ============================================================
// GET /api/v1/auth/mfa/setup  (JWT required — via middleware)
// ============================================================

async fn mfa_setup_handler(
    auth_user: AuthUser,
) -> Result<Json<mfa_totp::TotpSetup>, (StatusCode, Json<Value>)> {
    mfa_totp::generate_setup(&auth_user.username)
        .map(Json)
        .map_err(|e| {
            tracing::error!(error = %e, "TOTP setup error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
            )
        })
}

// ============================================================
// POST /api/v1/auth/mfa/verify  (JWT required — via middleware)
// ============================================================

#[derive(Debug, Deserialize)]
struct MfaVerifyRequest {
    secret_base32: String,
    code: String,
}

async fn mfa_verify_handler(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(req): Json<MfaVerifyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let valid =
        mfa_totp::verify_code(&auth_user.username, &req.secret_base32, &req.code).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
            )
        })?;

    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "invalid_code", "message": "Invalid TOTP code" } })),
        ));
    }

    sqlx::query("UPDATE users SET totp_secret = $1, mfa_enabled = TRUE WHERE id = $2")
        .bind(&req.secret_base32)
        .bind(auth_user.user_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to save TOTP secret");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Failed to enable MFA" } })),
            )
        })?;

    tracing::info!(user_id = %auth_user.user_id, "MFA enabled for user");
    Ok(Json(json!({ "message": "MFA enabled successfully" })))
}
