//! Opaque refresh token management.
//!
//! - 256-bit cryptographically random opaque tokens
//! - Stored as SHA-256 hash in the database (never the raw token)
//! - 1-hour sliding inactivity timeout, updated on each use
//! - Rotated on use (old token revoked, new one issued)
//! - Revocable by admin force-logout

use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// Length of the raw refresh token in bytes (256 bits).
const TOKEN_BYTES: usize = 32;

/// Sliding inactivity window: 1 hour.
const INACTIVITY_TIMEOUT_HOURS: i64 = 1;

#[derive(Debug, Error)]
pub enum RefreshError {
    #[error("Refresh token not found or revoked")]
    Invalid,
    #[error("Refresh token expired")]
    Expired,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Raw (plaintext) refresh token — returned to the client, never stored.
#[derive(Debug, Clone)]
pub struct RawRefreshToken(pub String);

impl RawRefreshToken {
    /// Hex-encode a raw 256-bit random token.
    pub fn generate() -> Self {
        let mut bytes = [0u8; TOKEN_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Return the SHA-256 hash of this token for database storage.
    pub fn hash(&self) -> String {
        let digest = Sha256::digest(self.0.as_bytes());
        hex::encode(digest)
    }
}

/// Database row representation of a stored refresh token.
#[derive(Debug, sqlx::FromRow)]
pub struct StoredRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub expires_at: chrono::DateTime<Utc>,
    pub revoked: bool,
}

/// Issue a new refresh token for the given user and store it in the database.
///
/// Returns the raw (plaintext) token to be sent to the client.
pub async fn issue(
    pool: &PgPool,
    user_id: Uuid,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Result<RawRefreshToken, RefreshError> {
    let token = RawRefreshToken::generate();
    let hash = token.hash();
    let expires_at = Utc::now() + Duration::hours(INACTIVITY_TIMEOUT_HOURS);

    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
        VALUES ($1, $2, $3, $4, $5::inet)
        "#,
    )
    .bind(user_id)
    .bind(&hash)
    .bind(expires_at)
    .bind(user_agent)
    .bind(ip_address)
    .execute(pool)
    .await?;

    tracing::debug!(user_id = %user_id, "Refresh token issued");
    Ok(token)
}

/// Validate a refresh token, then rotate it (revoke old, issue new).
///
/// Returns `(new_raw_token, user_id)` if valid.
pub async fn rotate(
    pool: &PgPool,
    raw_token: &str,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Result<(RawRefreshToken, Uuid), RefreshError> {
    let hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
    let now = Utc::now();

    // Look up token
    let row: Option<StoredRefreshToken> = sqlx::query_as(
        r#"
        SELECT id, user_id, expires_at, revoked
        FROM refresh_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?;

    let stored = row.ok_or(RefreshError::Invalid)?;

    if stored.revoked {
        return Err(RefreshError::Invalid);
    }

    if stored.expires_at < now {
        return Err(RefreshError::Expired);
    }

    // Revoke old token
    sqlx::query("UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE id = $1")
        .bind(stored.id)
        .execute(pool)
        .await?;

    // Issue new token
    let new_token = issue(pool, stored.user_id, user_agent, ip_address).await?;

    tracing::debug!(user_id = %stored.user_id, "Refresh token rotated");
    Ok((new_token, stored.user_id))
}

/// Revoke all refresh tokens for a user (force logout).
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<u64, RefreshError> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE user_id = $1 AND revoked = FALSE",
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    tracing::info!(user_id = %user_id, rows = result.rows_affected(), "All refresh tokens revoked");
    Ok(result.rows_affected())
}

/// Revoke a single refresh token by its raw value.
pub async fn revoke(pool: &PgPool, raw_token: &str) -> Result<(), RefreshError> {
    let hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

    sqlx::query(
        "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE token_hash = $1",
    )
    .bind(&hash)
    .execute(pool)
    .await?;

    Ok(())
}
