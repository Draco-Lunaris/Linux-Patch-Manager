//! One-shot migration helper for issue #6 (Secret Encryption at Rest).
//!
//! Reads plaintext secrets from the old columns/rows, encrypts them with the
//! secret-encryption key, and writes to the new BYTEA columns. Verifies the
//! round-trip (encrypt -> decrypt = original plaintext) before committing.
//!
//! USAGE:
//!   export DATABASE_URL="postgres://patch_manager:<password>@localhost/patch_manager"
//!   cargo run -p migrate-secrets
//!
//! This tool is safe to run multiple times (idempotent — re-encrypts and overwrites).
//!
//! See `tasks/secret-encryption-spec.md` section 4.5 for the design.

use anyhow::{Context, Result};
use pm_core::crypto;
use sqlx::PgPool;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Load secret-encryption key
    let key = crypto::load_or_create_key(Path::new(crypto::SECRET_ENCRYPTION_KEY_PATH))
        .context("Failed to load secret-encryption key")?;
    eprintln!(
        "Loaded secret-encryption key from {}",
        crypto::SECRET_ENCRYPTION_KEY_PATH
    );

    // 2. Connect to database
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL environment variable not set")?;
    let pool = PgPool::connect(&database_url)
        .await
        .context("Failed to connect to database")?;
    eprintln!("Connected to database");

    let mut success_count = 0u32;
    let mut skip_count = 0u32;

    // 3. Migrate OIDC client_secret
    if let Some(plaintext) = read_oidc_client_secret(&pool).await? {
        if plaintext.is_empty() {
            eprintln!("[skip] OIDC client_secret is empty");
            skip_count += 1;
        } else {
            write_oidc_client_secret(&pool, &plaintext, &key).await?;
            eprintln!("[ok]   OIDC client_secret encrypted");
            success_count += 1;
        }
    } else {
        eprintln!("[skip] OIDC client_secret column not found (already migrated?)");
        skip_count += 1;
    }

    // 4. Migrate SMTP password
    if let Some(plaintext) = read_smtp_password(&pool).await? {
        if plaintext.is_empty() {
            eprintln!("[skip] SMTP password is empty");
            skip_count += 1;
        } else {
            write_smtp_password(&pool, &plaintext, &key).await?;
            eprintln!("[ok]   SMTP password encrypted");
            success_count += 1;
        }
    } else {
        eprintln!("[skip] SMTP password row not found (already migrated?)");
        skip_count += 1;
    }

    // 5. Migrate TOTP secrets for all users
    let totp_count = migrate_totp_secrets(&pool, &key).await?;
    eprintln!("[ok]   {} TOTP secret(s) encrypted", totp_count);
    success_count += totp_count;

    eprintln!(
        "\nMigration complete: {} encrypted, {} skipped",
        success_count, skip_count
    );
    eprintln!(
        "Next step: apply migration 020_encrypt_secrets_at_rest.sql to drop the old columns."
    );
    Ok(())
}

async fn read_oidc_client_secret(pool: &PgPool) -> Result<Option<String>> {
    // Try to read the old column. If it doesn't exist, return None.
    let row: Result<Option<(Option<String>,)>, sqlx::Error> =
        sqlx::query_as("SELECT client_secret FROM oidc_config WHERE id = 1")
            .fetch_optional(pool)
            .await;
    match row {
        Ok(Some((secret,))) => Ok(secret),
        Ok(None) => Ok(None),
        Err(e) => {
            // Column not found = already migrated
            eprintln!("  (oidc_config.client_secret column check: {})", e);
            Ok(None)
        },
    }
}

async fn write_oidc_client_secret(pool: &PgPool, plaintext: &str, key: &[u8; 32]) -> Result<()> {
    let (ciphertext, nonce) = crypto::encrypt(plaintext, key)?;
    // Round-trip verification
    let recovered = crypto::decrypt(&ciphertext, &nonce, key)?;
    if recovered != plaintext {
        anyhow::bail!(
            "OIDC round-trip failed: expected {}, got {}",
            plaintext,
            recovered
        );
    }
    sqlx::query(
        "UPDATE oidc_config SET client_secret_encrypted = $1, client_secret_nonce = $2 WHERE id = 1",
    )
    .bind(&ciphertext)
    .bind(&nonce)
    .execute(pool)
    .await
    .context("Failed to update oidc_config")?;
    Ok(())
}

async fn read_smtp_password(pool: &PgPool) -> Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM system_config WHERE key = 'smtp_password'")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(v,)| v))
}

async fn write_smtp_password(pool: &PgPool, plaintext: &str, key: &[u8; 32]) -> Result<()> {
    let (ciphertext, nonce) = crypto::encrypt(plaintext, key)?;
    // Round-trip verification
    let recovered = crypto::decrypt(&ciphertext, &nonce, key)?;
    if recovered != plaintext {
        anyhow::bail!(
            "SMTP round-trip failed: expected {}, got {}",
            plaintext,
            recovered
        );
    }
    // Delete old row, write two new rows
    sqlx::query("DELETE FROM system_config WHERE key = 'smtp_password'")
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO system_config (key, value) VALUES ($1, $2)")
        .bind("smtp_password_encrypted")
        .bind(hex_encode(&ciphertext))
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO system_config (key, value) VALUES ($1, $2)")
        .bind("smtp_password_nonce")
        .bind(hex_encode(&nonce))
        .execute(pool)
        .await?;
    Ok(())
}

async fn migrate_totp_secrets(pool: &PgPool, key: &[u8; 32]) -> Result<u32> {
    // Read all users with totp_secret set
    let users: Vec<(uuid::Uuid, String)> =
        sqlx::query_as("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL")
            .fetch_all(pool)
            .await
            .context("Failed to read users with totp_secret")?;

    let count = users.len() as u32;
    for (user_id, plaintext) in users {
        let (ciphertext, nonce) = crypto::encrypt(&plaintext, key)?;
        // Round-trip verification
        let recovered = crypto::decrypt(&ciphertext, &nonce, key)?;
        if recovered != plaintext {
            anyhow::bail!("TOTP round-trip failed for user {}", user_id);
        }
        sqlx::query(
            "UPDATE users SET totp_secret_encrypted = $1, totp_secret_nonce = $2 WHERE id = $3",
        )
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(user_id)
        .execute(pool)
        .await
        .context("Failed to update user totp_secret")?;
    }
    Ok(count)
}

/// Hex-encode bytes for storage in TEXT columns (system_config).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
