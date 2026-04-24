use crate::config::DatabaseConfig;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

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

/// Check that the database schema is at the expected version.
/// Used by the worker to wait until migrations have been applied.
pub async fn check_schema_version(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = true")
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}
