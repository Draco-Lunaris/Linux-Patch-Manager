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
    routing::delete,
    routing::{get, post},
    Router,
};
use pm_auth::{
    hash_password, mfa_totp,
    rbac::AuthUser,
    session::{self, LoginRequest, LoginResponse},
    validate_password_strength, verify_password,
};
use serde::Deserialize;
use serde_json::{json, Value};

use uuid::Uuid;

use crate::AppState;

// ============================================================
// Public router — no authentication required
// ============================================================

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login_handler))
        .route("/refresh", post(refresh_handler))
        .route("/logout", post(logout_handler))
        .route(
            "/force-change-password",
            post(force_change_password_handler),
        )
}

// ============================================================
// Protected router — requires valid JWT (applied by caller)
// ============================================================

pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/mfa/setup", get(mfa_setup_handler))
        .route("/mfa/verify", post(mfa_verify_handler))
        .route("/mfa", delete(disable_mfa))
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
            SessionError::PasswordResetRequired => (
                StatusCode::FORBIDDEN,
                "password_reset_required",
                "Password reset is required before login",
            ),
            SessionError::AccountLocked => (
                StatusCode::LOCKED,
                "account_locked",
                "Account is locked due to too many failed login attempts",
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

// ============================================================
// POST /api/v1/auth/force-change-password  (PUBLIC — no JWT)
// ============================================================

#[derive(Debug, Deserialize)]
struct ForceChangePasswordRequest {
    username: String,
    current_password: String,
    new_password: String,
}

async fn force_change_password_handler(
    State(state): State<AppState>,
    Json(req): Json<ForceChangePasswordRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Validate new password strength
    if let Err(msg) = validate_password_strength(&req.new_password) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "weak_password", "message": msg } })),
        ));
    }

    // Look up user by username
    let row: Option<(Uuid, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, password_hash, force_password_reset FROM users WHERE username = $1 AND auth_provider = 'local'",
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to fetch user");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let (user_id, hash_opt, _force_reset) = match row {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({ "error": { "code": "invalid_credentials", "message": "Invalid username or password" } }),
                ),
            ));
        },
    };

    // Verify current password
    let hash_str = hash_opt.as_deref().unwrap_or("");
    let valid = verify_password(&req.current_password, hash_str).unwrap_or(false);

    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                json!({ "error": { "code": "invalid_credentials", "message": "Invalid username or password" } }),
            ),
        ));
    }

    // Hash and update password, clear force_password_reset
    let new_hash = hash_password(&req.new_password).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
        )
    })?;

    sqlx::query(
        "UPDATE users SET password_hash = $1, force_password_reset = FALSE, failed_login_attempts = 0, locked_until = NULL, updated_at = NOW() WHERE id = $2",
    )
    .bind(&new_hash)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to update password");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Failed to update password" } })),
        )
    })?;

    tracing::info!(user_id = %user_id, username = %req.username, "Password changed via force-change-password");

    Ok(Json(json!({ "message": "Password changed successfully" })))
}

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

    // Encrypt the TOTP secret before persisting (issue #6 fix)
    let key = crate::secret_key::get().map_err(|e| {
        tracing::error!(error = %e, "Failed to load secret-encryption key");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "error": { "code": "internal_error", "message": "Encryption key error" } }),
            ),
        )
    })?;
    let (ciphertext, nonce) = pm_core::crypto::encrypt(&req.secret_base32, key).map_err(|e| {
        tracing::error!(error = %e, "Failed to encrypt TOTP secret");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Encryption error" } })),
        )
    })?;
    sqlx::query("UPDATE users SET totp_secret_encrypted = $1, totp_secret_nonce = $2, mfa_enabled = TRUE WHERE id = $3")
        .bind(&ciphertext)
        .bind(&nonce)
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

// ============================================================
// DELETE /api/v1/auth/mfa  (JWT required — disable own MFA)
// ============================================================

#[derive(Debug, Deserialize)]
struct DisableMfaRequest {
    password: String,
}

async fn disable_mfa(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(req): Json<DisableMfaRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Verify current password to confirm identity
    let hash: Option<String> = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch password hash");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?
        .flatten();

    let hash_str = hash.unwrap_or_default();
    let valid = verify_password(&req.password, &hash_str).unwrap_or(false);

    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "invalid_password", "message": "Current password is incorrect" } }),
            ),
        ));
    }

    sqlx::query("UPDATE users SET totp_secret_encrypted = NULL, totp_secret_nonce = NULL, mfa_enabled = FALSE WHERE id = $1")
        .bind(auth_user.user_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to disable MFA");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Failed to disable MFA" } })),
            )
        })?;

    tracing::info!(user_id = %auth_user.user_id, "MFA disabled for user");
    Ok(Json(json!({ "message": "MFA disabled successfully" })))
}
