//! Admin routes for package repository management (M11).
//!
//! Provides endpoints for manual sync triggers, sync status, and package listing.
//! All routes require Admin role.

use crate::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};

type SyncLogRow = (
    uuid::Uuid,
    String,
    String,
    i32,
    i32,
    Option<String>,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
);

type PackageRow = (
    uuid::Uuid,
    String,
    String,
    String,
    Option<String>,
    String,
    i64,
    String,
    chrono::DateTime<chrono::Utc>,
);

/// Admin-only repo management routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/repo/sync", post(trigger_sync))
        .route("/repo/sync-status", get(sync_status))
        .route("/repo/packages", get(list_packages))
        .route("/repo/regenerate-metadata", post(regenerate_metadata))
}

/// `POST /api/v1/admin/repo/sync`
///
/// Trigger a manual package sync from GitHub Releases.
/// Creates a sync_log entry with triggered_by='manual'.
/// The actual sync runs asynchronously in the package sync worker.
async fn trigger_sync(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let sync_log_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO repo_sync_log (triggered_by, status) VALUES ('manual', 'running') RETURNING id",
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create manual sync log");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            ));
        }
    };

    let pool = state.db.clone();
    let config = state.config.clone();
    tokio::spawn(async move {
        tracing::info!(sync_log_id = %sync_log_id, "Manual repo sync started");
        if let Err(e) = run_manual_sync(&pool, &config, sync_log_id).await {
            tracing::error!(sync_log_id = %sync_log_id, error = %e, "Manual repo sync failed");
        }
    });

    Ok(Json(json!({
        "message": "Package sync triggered",
        "sync_log_id": sync_log_id
    })))
}

/// Run a manual package sync cycle.
async fn run_manual_sync(
    pool: &sqlx::PgPool,
    config: &std::sync::Arc<pm_core::config::AppConfig>,
    sync_log_id: uuid::Uuid,
) -> Result<(), anyhow::Error> {
    let sync_config = &config.worker.package_sync;
    let repo_dir = &config.repo.dir;

    let result = match pm_core::repo_sync::run_sync_cycle(
        sync_config,
        repo_dir,
        Some(&config.repo.apk_rsa_private_key_path),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(sync_log_id = %sync_log_id, error = %e, "Manual sync failed");
            let _ = sqlx::query(
                "UPDATE repo_sync_log SET status = 'failed', error_message = $2, finished_at = NOW() WHERE id = $1",
            )
            .bind(sync_log_id)
            .bind(format!("Sync error: {e}"))
            .execute(pool).await;
            return Err(e);
        },
    };

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
        .execute(pool).await;
    }

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
    .execute(pool).await?;

    tracing::info!(
        sync_log_id = %sync_log_id,
        packages_synced = result.packages_synced,
        packages_skipped = result.packages_skipped,
        status,
        "Manual repo sync completed"
    );

    Ok(())
}

/// `GET /api/v1/admin/repo/sync-status`
async fn sync_status(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let sync_logs: Vec<Value> = sqlx::query_as::<_, SyncLogRow>(
        "SELECT id, triggered_by, status, packages_synced, packages_skipped, error_message, started_at, finished_at
         FROM repo_sync_log ORDER BY started_at DESC LIMIT 10",
    )
    .fetch_all(&state.db)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                json!({
                    "id": row.0,
                    "triggered_by": row.1,
                    "status": row.2,
                    "packages_synced": row.3,
                    "packages_skipped": row.4,
                    "error_message": row.5,
                    "started_at": row.6,
                    "finished_at": row.7,
                })
            })
            .collect()
    })
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to fetch sync status");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let total_packages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repo_packages")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    Ok(Json(json!({
        "recent_syncs": sync_logs,
        "total_packages": total_packages,
    })))
}

/// `GET /api/v1/admin/repo/packages`
async fn list_packages(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let packages: Vec<Value> = sqlx::query_as::<_, PackageRow>(
        "SELECT id, filename, version, distro, distro_codename, arch, file_size, source, synced_at
         FROM repo_packages ORDER BY synced_at DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                json!({
                    "id": row.0,
                    "filename": row.1,
                    "version": row.2,
                    "distro": row.3,
                    "distro_codename": row.4,
                    "arch": row.5,
                    "file_size": row.6,
                    "source": row.7,
                    "synced_at": row.8,
                })
            })
            .collect()
    })
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to list repo packages");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    Ok(Json(json!({
        "packages": packages,
        "count": packages.len(),
    })))
}

/// `POST /api/v1/admin/repo/regenerate-metadata`
///
/// Regenerate repository metadata for all supported distro formats (apt,
/// dnf, apk, pacman). Also prunes stale .deb files from the pool and
/// re-signs dnf/pacman metadata with GPG. Useful after manual package
/// uploads or GPG key rotation.
async fn regenerate_metadata(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let repo_dir = state.config.repo.dir.clone();
    let rsa_key_path = state.config.repo.apk_rsa_private_key_path.clone();

    tokio::spawn(async move {
        tracing::info!("Manual metadata regeneration started for all distro formats");

        // APT — regenerate all suites (also prunes stale .deb files).
        let apt_errors = pm_core::repo_metadata::regenerate_all_apt_metadata(&repo_dir).await;
        if apt_errors.is_empty() {
            tracing::info!("APT metadata regenerated successfully");
        } else {
            tracing::warn!(
                error_count = apt_errors.len(),
                "APT metadata regeneration completed with errors"
            );
        }

        // DNF — generate metadata and GPG-sign repomd.xml.
        if let Err(e) = pm_core::repo_metadata::generate_dnf_metadata(&repo_dir).await {
            tracing::warn!(error = %e, "Failed to regenerate dnf metadata");
        }
        let dnf_codename = pm_core::repo_metadata::DNF_CODENAME;
        let repomd_path = format!("{repo_dir}/dnf/{dnf_codename}/repodata/repomd.xml");
        let repomd_sig_path = format!("{repo_dir}/dnf/{dnf_codename}/repodata/repomd.xml.asc");
        if std::path::Path::new(&repomd_path).exists() {
            if let Err(e) =
                pm_core::gpg::sign_file_detached(&repomd_path, &repomd_sig_path, true).await
            {
                tracing::warn!(
                    error = %e,
                    "GPG sign repomd.xml failed (non-fatal but dnf clients will not trust this repo)"
                );
            }
        }

        // APK — generate APKINDEX.tar.gz with embedded RSA signature.
        let rsa_priv_path = if rsa_key_path.is_empty() {
            std::env::var("LPA_APK_RSA_PRIVATE_KEY_PATH")
                .unwrap_or_else(|_| "/etc/patch-manager/ca/lpa-repo-rsa.pem".to_string())
        } else {
            rsa_key_path
        };
        if let Err(e) =
            pm_core::repo_metadata::generate_apk_metadata(&repo_dir, Some(&rsa_priv_path)).await
        {
            tracing::warn!(
                error = %e,
                "Failed to generate signed APKINDEX (Alpine clients will not trust this repo)"
            );
        }

        // Pacman — generate repo database and GPG-sign lpa-repo.db.tar.zst + lpa-repo.db.
        if let Err(e) = pm_core::repo_metadata::generate_pacman_metadata(&repo_dir).await {
            tracing::warn!(error = %e, "Failed to regenerate pacman metadata");
        }
        let db_zst_path = format!("{repo_dir}/pacman/x86_64/lpa-repo.db.tar.zst");
        let db_zst_sig_path = format!("{repo_dir}/pacman/x86_64/lpa-repo.db.tar.zst.sig");
        if std::path::Path::new(&db_zst_path).exists() {
            if let Err(e) =
                pm_core::gpg::sign_file_detached(&db_zst_path, &db_zst_sig_path, false).await
            {
                tracing::warn!(
                    error = %e,
                    "GPG sign lpa-repo.db.tar.zst failed (non-fatal but pacman clients will not trust this repo)"
                );
            }
        }
        let db_gz_path = format!("{repo_dir}/pacman/x86_64/lpa-repo.db");
        let db_gz_sig_path = format!("{repo_dir}/pacman/x86_64/lpa-repo.db.sig");
        if std::path::Path::new(&db_gz_path).exists() {
            if let Err(e) =
                pm_core::gpg::sign_file_detached(&db_gz_path, &db_gz_sig_path, false).await
            {
                tracing::warn!(
                    error = %e,
                    "GPG sign lpa-repo.db failed (non-fatal but pacman clients will not trust this repo)"
                );
            }
        }

        tracing::info!("Manual metadata regeneration completed for all distro formats");
    });

    Ok(Json(
        json!({ "message": "Metadata regeneration triggered for all distro formats" }),
    ))
}
