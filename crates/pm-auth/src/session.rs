//! Session management: login flow, logout, token issuance.
//!
//! Login flow: password → MFA → access token + refresh token
//! Logout: revoke refresh token
//! Force logout: revoke all tokens for a user

use chrono::Utc;
use pm_core::models::{AuthProvider, UserRole};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    jwt::{self, JwtError},
    mfa_totp,
    password::{self, PasswordError},
    refresh::{self, RefreshError},
};

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Account is disabled")]
    AccountDisabled,
    #[error("Password reset required")]
    PasswordResetRequired,
    #[error("MFA required")]
    MfaRequired,
    #[error("Invalid MFA code")]
    InvalidMfaCode,
    #[error("Account locked due to too many failed attempts")]
    AccountLocked,
    #[error("JWT error: {0}")]
    Jwt(#[from] JwtError),
    #[error("Refresh token error: {0}")]
    Refresh(#[from] RefreshError),
    #[error("Password error: {0}")]
    Password(#[from] PasswordError),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Successful login response returned to the client.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    /// Short-lived JWT access token (15 minutes).
    pub access_token: String,
    /// Opaque refresh token (1-hour sliding window).
    pub refresh_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Access token TTL in seconds.
    pub expires_in: i64,
    /// User information.
    pub user: SessionUser,
}

/// User summary embedded in login response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub mfa_enabled: bool,
}

/// Database user row fetched during login.
#[derive(Debug, sqlx::FromRow)]
struct DbUser {
    id: Uuid,
    username: String,
    display_name: String,
    role: UserRole,
    auth_provider: AuthProvider,
    password_hash: Option<String>,
    totp_secret: Option<String>,
    mfa_enabled: bool,
    is_active: bool,
    force_password_reset: bool,
    failed_login_attempts: i32,
    locked_until: Option<chrono::DateTime<Utc>>,
}

/// Login request payload.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// TOTP code (required if MFA is enabled).
    pub totp_code: Option<String>,
}

/// Perform the full login flow for local accounts.
///
/// Steps:
/// 1. Look up user by username
/// 2. Verify password (Argon2id)
/// 3. Check account active state
/// 4. Verify MFA if enabled
/// 5. Issue access token + refresh token
/// 6. Update last_login_at
pub async fn login(
    pool: &PgPool,
    req: &LoginRequest,
    signing_key_pem: &str,
    access_ttl_secs: i64,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Result<LoginResponse, SessionError> {
    // 1. Fetch user by username
    let user: Option<DbUser> = sqlx::query_as(
        r#"
        SELECT id, username, display_name, role, auth_provider,
               password_hash, totp_secret, mfa_enabled, is_active, force_password_reset,
               failed_login_attempts, locked_until
        FROM users
        WHERE username = $1 AND auth_provider = 'local'
        "#,
    )
    .bind(&req.username)
    .fetch_optional(pool)
    .await?;

    // Use constant-time comparison approach: always run Argon2 even on miss
    let user = match user {
        Some(u) => u,
        None => {
            // Prevent timing-based username enumeration
            let _ = password::hash_password("dummy-timing-fill");
            return Err(SessionError::InvalidCredentials);
        },
    };

    // 2a. Check if account is locked due to too many failed attempts
    if let Some(locked_until) = user.locked_until {
        if locked_until > Utc::now() {
            tracing::warn!(username = %req.username, "Login blocked: account locked until {}", locked_until);
            return Err(SessionError::AccountLocked);
        }
        // Lockout period has expired — reset counters
        sqlx::query(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1",
        )
        .bind(user.id)
        .execute(pool)
        .await?;
    }

    // 2. Verify password
    let hash = user.password_hash.as_deref().unwrap_or("");
    let valid = password::verify_password(&req.password, hash).unwrap_or(false);

    if !valid {
        // Increment failed login attempts
        let new_attempts = user.failed_login_attempts + 1;
        if new_attempts >= 5 {
            let lock_until = Utc::now() + chrono::Duration::minutes(30);
            sqlx::query(
                "UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3",
            )
            .bind(new_attempts)
            .bind(lock_until)
            .bind(user.id)
            .execute(pool)
            .await?;
            tracing::warn!(username = %req.username, "Account locked after {} failed attempts", new_attempts);
        } else {
            sqlx::query("UPDATE users SET failed_login_attempts = $1 WHERE id = $2")
                .bind(new_attempts)
                .bind(user.id)
                .execute(pool)
                .await?;
        }
        tracing::warn!(username = %req.username, "Login failed: invalid password (attempt {})", new_attempts);
        return Err(SessionError::InvalidCredentials);
    }

    // 3. Check account state
    if !user.is_active {
        tracing::warn!(username = %req.username, "Login failed: account disabled");
        return Err(SessionError::AccountDisabled);
    }

    // 3b. Check if password reset is required
    if user.force_password_reset {
        tracing::warn!(username = %req.username, "Login blocked: password reset required");
        return Err(SessionError::PasswordResetRequired);
    }

    // 4. MFA check
    if user.mfa_enabled {
        let code = req.totp_code.as_deref().ok_or(SessionError::MfaRequired)?;
        let secret = user.totp_secret.as_deref().unwrap_or("");

        let mfa_ok = mfa_totp::verify_code(&user.username, secret, code).unwrap_or(false);

        if !mfa_ok {
            tracing::warn!(username = %req.username, "Login failed: invalid MFA code");
            return Err(SessionError::InvalidMfaCode);
        }
    }

    // 5. Issue tokens
    let access_token = jwt::issue_access_token(
        user.id,
        &user.username,
        &user.role.to_string(),
        access_ttl_secs,
        signing_key_pem,
    )?;

    let raw_refresh = refresh::issue(pool, user.id, user_agent, ip_address).await?;

    // 6. Update last_login_at
    sqlx::query("UPDATE users SET last_login_at = $1, failed_login_attempts = 0, locked_until = NULL WHERE id = $2")
        .bind(Utc::now())
        .bind(user.id)
        .execute(pool)
        .await?;

    tracing::info!(user_id = %user.id, username = %user.username, "Login successful");

    Ok(LoginResponse {
        access_token,
        refresh_token: raw_refresh.0,
        token_type: "Bearer".to_string(),
        expires_in: access_ttl_secs,
        user: SessionUser {
            id: user.id.to_string(),
            username: user.username,
            display_name: user.display_name,
            role: user.role.to_string(),
            mfa_enabled: user.mfa_enabled,
        },
    })
}

/// Refresh an access token using a valid refresh token.
///
/// The old refresh token is revoked and a new one issued (rotation).
pub async fn refresh_session(
    pool: &PgPool,
    raw_refresh_token: &str,
    signing_key_pem: &str,
    access_ttl_secs: i64,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Result<LoginResponse, SessionError> {
    let (new_refresh, user_id) =
        refresh::rotate(pool, raw_refresh_token, user_agent, ip_address).await?;

    // Fetch user for token claims
    let user: DbUser = sqlx::query_as(
        r#"
        SELECT id, username, display_name, role, auth_provider,
               password_hash, totp_secret, mfa_enabled, is_active, force_password_reset,
               failed_login_attempts, locked_until
        FROM users WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    if !user.is_active {
        // Revoke all tokens and deny
        let _ = refresh::revoke_all_for_user(pool, user_id).await;
        return Err(SessionError::AccountDisabled);
    }

    let access_token = jwt::issue_access_token(
        user.id,
        &user.username,
        &user.role.to_string(),
        access_ttl_secs,
        signing_key_pem,
    )?;

    Ok(LoginResponse {
        access_token,
        refresh_token: new_refresh.0,
        token_type: "Bearer".to_string(),
        expires_in: access_ttl_secs,
        user: SessionUser {
            id: user.id.to_string(),
            username: user.username,
            display_name: user.display_name,
            role: user.role.to_string(),
            mfa_enabled: user.mfa_enabled,
        },
    })
}

/// Logout: revoke the current refresh token.
pub async fn logout(pool: &PgPool, raw_refresh_token: &str) -> Result<(), SessionError> {
    refresh::revoke(pool, raw_refresh_token).await?;
    Ok(())
}

/// Force-logout: revoke all refresh tokens for a user.
pub async fn force_logout(pool: &PgPool, user_id: Uuid) -> Result<u64, SessionError> {
    let count = refresh::revoke_all_for_user(pool, user_id).await?;
    Ok(count)
}
