use crate::config::DatabaseConfig;
use crate::models::{CreateEnrollmentRequest, EnrollmentRequest};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use uuid::Uuid;

/// Initialize and return a PostgreSQL connection pool.
pub async fn init_pool(cfg: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .connect(&cfg.url)
        .await?;

    tracing::info!(
        max_connections = cfg.max_connections,
        "PostgreSQL connection pool initialized"
    );

    Ok(pool)
}

/// Run embedded SQLx migrations.
/// Uses a PostgreSQL advisory lock to ensure only one writer runs migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    tracing::info!("Acquiring advisory lock for migrations");

    // Advisory lock key — consistent hash of the application name
    const LOCK_KEY: i64 = 0x7061_7463_686d_6772; // "patchmgr" bytes

    // Acquire advisory lock; blocks until granted
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(LOCK_KEY)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to acquire advisory lock");
            e
        })
        .expect("Advisory lock must be acquired before running migrations");

    tracing::info!("Running database migrations");
    let result = sqlx::migrate!("../../migrations").run(pool).await;

    // Always release the lock
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_KEY)
        .execute(pool)
        .await
        .ok();

    match &result {
        Ok(_) => tracing::info!("Database migrations completed successfully"),
        Err(e) => tracing::error!(error = %e, "Database migrations failed"),
    }

    result
}

// ============================================================
// Enrollment Requests
// ============================================================

pub async fn create_enrollment_request(
    pool: &PgPool,
    req: CreateEnrollmentRequest,
    token_hash: String,
) -> Result<EnrollmentRequest, sqlx::Error> {
    sqlx::query_as::<
        _,
        EnrollmentRequest,
    >(
        r#"
        INSERT INTO enrollment_requests (machine_id, fqdn, ip_address, os_details, polling_token)
        VALUES ($1, $2, $3::inet, $4, $5)
        RETURNING id, machine_id, fqdn, ip_address, os_details, polling_token, created_at, expires_at
        "#,
    )
    .bind(req.machine_id)
    .bind(req.fqdn)
    .bind(req.ip_address)
    .bind(req.os_details)
    .bind(token_hash)
    .fetch_one(pool)
    .await
}

pub async fn list_enrollment_requests(
    pool: &PgPool,
) -> Result<Vec<EnrollmentRequest>, sqlx::Error> {
    sqlx::query_as::<_, EnrollmentRequest>(
        "SELECT id, machine_id, fqdn, ip_address, os_details, polling_token, created_at, expires_at FROM enrollment_requests ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

pub async fn delete_enrollment_request(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM enrollment_requests WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Check that the database schema is at the expected version.
/// Used by the worker to wait until migrations have been applied.
pub async fn check_schema_version(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = true")
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}
