//! Package sync worker — pulls packages from GitHub Releases into the
//! manager-hosted package repository.
//!
//! Runs on a configurable schedule (default: hourly). Delegates the actual
//! fetch/download/import/sign logic to `pm_core::repo_sync` (shared with the
//! manual admin trigger in `pm-web`).
//!
//! Added for issue #116 (M13). Consolidated in Phase 5.

use pm_core::config::AppConfig;
use pm_core::repo_sync;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time;

/// Run the package sync worker loop indefinitely.
///
/// On each tick, delegates to `repo_sync::run_sync_cycle()` and persists
/// results to the database.
pub async fn run_package_sync_worker(pool: PgPool, config: Arc<AppConfig>) {
    let sync_config = &config.worker.package_sync;

    if !sync_config.enabled {
        tracing::info!("Package sync worker disabled — not starting");
        return;
    }

    let interval_secs = sync_config.interval_secs;
    let mut ticker = time::interval(std::time::Duration::from_secs(interval_secs));

    tracing::info!(interval_secs, "Package sync worker started");

    loop {
        ticker.tick().await;

        if let Err(e) = run_scheduled_sync(&pool, &config).await {
            tracing::error!(error = %e, "Package sync cycle failed");
        }
    }
}

/// Run a single scheduled sync cycle.
///
/// 1. Create sync_log entry in DB
/// 2. Fetch existing packages from DB for skip-if-exists
/// 3. Call shared `repo_sync::run_sync_cycle()`
/// 4. Persist synced packages to `repo_packages` table
/// 5. Update sync_log with results
async fn run_scheduled_sync(pool: &PgPool, config: &Arc<AppConfig>) -> Result<(), anyhow::Error> {
    let sync_config = &config.worker.package_sync;
    let repo_dir = &config.repo.dir;

    // Create sync_log entry.
    let sync_log_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO repo_sync_log (triggered_by, status) VALUES ('scheduler', 'running') RETURNING id",
    )
    .fetch_one(pool)
    .await?;

    tracing::info!(sync_log_id = %sync_log_id, "Package sync cycle started");

    // Fetch existing packages from DB for skip-if-exists logic.
    let existing = fetch_existing_packages(pool).await;

    // Run the shared sync logic.
    let result = match repo_sync::run_sync_cycle(
        sync_config,
        repo_dir,
        Some(&config.repo.apk_rsa_private_key_path),
        &existing,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Sync cycle failed");
            mark_sync_failed(pool, sync_log_id, &format!("Sync error: {e}")).await;
            return Err(e);
        },
    };

    // Persist synced packages to repo_packages table.
    for pkg in &result.synced_packages {
        let _ = sqlx::query(
            "INSERT INTO repo_packages (filename, version, distro, distro_codename, arch, file_size, sha256, source, sync_log_id, published_at)
             VALUES ($1, $2, $3, $4, 'amd64', $5, $6, 'github', $7, $8)
             ON CONFLICT (filename, version, distro, arch) DO UPDATE SET
                published_at = EXCLUDED.published_at,
                distro_codename = EXCLUDED.distro_codename,
                sha256 = EXCLUDED.sha256,
                file_size = EXCLUDED.file_size",
        )
        .bind(&pkg.filename)
        .bind(&pkg.version)
        .bind(&pkg.distro)
        .bind(&pkg.distro_codename)
        .bind(pkg.file_size)
        .bind(&pkg.sha256)
        .bind(sync_log_id)
        .bind(pkg.published_at)
        .execute(pool)
        .await;
    }

    // Update sync_log with results.
    let status = if result.errors.is_empty() {
        "success"
    } else {
        "partial"
    };
    let error_msg = if result.errors.is_empty() {
        None
    } else {
        Some(result.errors.join("; "))
    };

    sqlx::query(
        "UPDATE repo_sync_log SET status = $2, packages_synced = $3, packages_skipped = $4, error_message = $5, finished_at = NOW() WHERE id = $1",
    )
    .bind(sync_log_id)
    .bind(status)
    .bind(result.packages_synced)
    .bind(result.packages_skipped)
    .bind(error_msg)
    .execute(pool)
    .await?;

    tracing::info!(
        sync_log_id = %sync_log_id,
        packages_synced = result.packages_synced,
        packages_skipped = result.packages_skipped,
        status,
        "Package sync cycle completed"
    );

    Ok(())
}

/// Fetch existing packages from the DB for skip-if-exists logic.
async fn fetch_existing_packages(pool: &PgPool) -> Vec<repo_sync::ExistingPackage> {
    let rows: Vec<(String, String, String, Option<String>)> =
        match sqlx::query_as("SELECT filename, version, distro, sha256 FROM repo_packages")
            .fetch_all(pool)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to fetch existing packages for skip check");
                return Vec::new();
            },
        };

    rows.into_iter()
        .map(
            |(filename, version, distro, sha256)| repo_sync::ExistingPackage {
                filename,
                version,
                distro,
                sha256,
            },
        )
        .collect()
}

/// Mark a sync log entry as failed.
async fn mark_sync_failed(pool: &PgPool, sync_log_id: uuid::Uuid, error: &str) {
    let _ = sqlx::query(
        "UPDATE repo_sync_log SET status = 'failed', error_message = $2, finished_at = NOW() WHERE id = $1",
    )
    .bind(sync_log_id)
    .bind(error)
    .execute(pool)
    .await;
}
