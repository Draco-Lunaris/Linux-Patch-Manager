//! pm-worker — Linux Patch Manager background worker.
//!
//! Handles scheduled polling, job execution, maintenance window scheduling,
//! retry logic, email notifications, and data pruning.

use pm_core::{
    config::AppConfig,
    db,
    logging,
};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tokio::time;

/// Minimum number of applied migrations the worker requires before
/// accepting work. Prevents the worker from running against a schema
/// that hasn't been migrated yet.
const REQUIRED_MIGRATION_COUNT: i64 = 1;

/// How long to wait between schema-version checks before giving up.
const SCHEMA_CHECK_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config_path = std::env::var("PATCH_MANAGER_CONFIG")
        .unwrap_or_else(|_| "/etc/patch-manager/config.toml".to_string());

    let config = AppConfig::load(&config_path)
        .unwrap_or_else(|_| {
            eprintln!("Config file not found or invalid, using defaults");
            AppConfig::default()
        });

    // Initialize logging
    logging::init(&config.logging);

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "patch-manager-worker starting");

    // Initialize database pool
    let pool = db::init_pool(&config.database).await?;

    // Wait for schema to be at the expected version (web process runs migrations)
    wait_for_schema(&pool).await?;

    let config = Arc::new(config);

    // Spawn worker tasks
    let heartbeat_handle = tokio::spawn(run_heartbeat(
        pool.clone(),
        config.worker.heartbeat_interval_secs,
    ));

    // TODO M4: spawn health_poller, patch_data_poller
    // TODO M5: spawn job_executor
    // TODO M6: spawn job_scheduler

    tracing::info!("Worker tasks started");

    // Wait for all tasks (they run indefinitely)
    let _ = tokio::join!(heartbeat_handle);

    Ok(())
}

/// Wait until the database schema has at least `REQUIRED_MIGRATION_COUNT`
/// successful migrations applied. Retries every 5 seconds up to
/// `SCHEMA_CHECK_TIMEOUT`.
async fn wait_for_schema(pool: &PgPool) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + SCHEMA_CHECK_TIMEOUT;

    loop {
        match db::check_schema_version(pool).await {
            Ok(count) if count >= REQUIRED_MIGRATION_COUNT => {
                tracing::info!(migration_count = count, "Schema version check passed");
                return Ok(());
            }
            Ok(count) => {
                tracing::warn!(
                    migration_count = count,
                    required = REQUIRED_MIGRATION_COUNT,
                    "Schema not ready, waiting..."
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "Schema version check failed, retrying...");
            }
        }

        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Schema not ready after {}s — is the web process running migrations?",
                SCHEMA_CHECK_TIMEOUT.as_secs()
            );
        }

        time::sleep(Duration::from_secs(5)).await;
    }
}

/// Writes a heartbeat row to `worker_heartbeat` every `interval_secs`.
/// The web process can query this to confirm the worker is alive.
async fn run_heartbeat(pool: PgPool, interval_secs: u64) {
    let interval = Duration::from_secs(interval_secs);
    let mut ticker = time::interval(interval);

    loop {
        ticker.tick().await;

        let result = sqlx::query(
            r#"
            INSERT INTO worker_heartbeat (id, last_seen, worker_version)
            VALUES (1, NOW(), $1)
            ON CONFLICT (id) DO UPDATE
                SET last_seen = EXCLUDED.last_seen,
                    worker_version = EXCLUDED.worker_version
            "#,
        )
        .bind(env!("CARGO_PKG_VERSION"))
        .execute(&pool)
        .await;

        match result {
            Ok(_) => tracing::debug!("Worker heartbeat written"),
            Err(e) => tracing::error!(error = %e, "Worker heartbeat failed"),
        }
    }
}
