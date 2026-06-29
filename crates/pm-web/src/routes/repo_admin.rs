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

/// Admin-only repo management routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/repo/sync", post(trigger_sync))
        .route("/repo/sync-status", get(sync_status))
        .route("/repo/packages", get(list_packages))
}

/// `POST /api/v1/admin/repo/sync`
///
/// Trigger a manual package sync from GitHub Releases.
/// Creates a sync_log entry with triggered_by='manual'.
/// The actual sync runs asynchronously in the package sync worker.
async fn trigger_sync(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Create a manual sync log entry.
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

    // Spawn the actual sync as a background task.
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
///
/// Fetches releases from GitHub API, downloads package assets, imports into
/// reprepro/createrepo_c, and updates the sync_log entry.
async fn run_manual_sync(
    pool: &sqlx::PgPool,
    config: &std::sync::Arc<pm_core::config::AppConfig>,
    sync_log_id: uuid::Uuid,
) -> Result<(), anyhow::Error> {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct GithubAsset {
        name: String,
        browser_download_url: String,
        size: u64,
    }

    #[derive(Debug, Deserialize)]
    struct GithubRelease {
        tag_name: String,
        prerelease: bool,
        assets: Vec<GithubAsset>,
    }

    let sync_config = &config.worker.package_sync;
    let repo_dir = &config.repo.dir;

    // Fetch releases from GitHub API.
    let url = format!(
        "https://api.github.com/repos/{}/releases?per_page={}",
        sync_config.github_repo,
        sync_config.max_releases.min(100)
    );

    let client = reqwest::Client::builder()
        .user_agent("Linux-Patch-Manager-Sync/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut req = client.get(&url);
    if !sync_config.github_token.is_empty() {
        req = req.header(
            "Authorization",
            format!("Bearer {}", sync_config.github_token),
        );
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GitHub API returned {}: {}", status, body);
    }

    let releases: Vec<GithubRelease> = resp.json().await?;
    let releases: Vec<GithubRelease> = releases
        .into_iter()
        .filter(|r| !r.prerelease)
        .take(sync_config.max_releases as usize)
        .collect();

    tracing::info!(sync_log_id = %sync_log_id, releases = releases.len(), "Fetched releases from GitHub");

    let mut packages_synced = 0i32;
    let mut packages_skipped = 0i32;
    let mut errors: Vec<String> = Vec::new();

    for release in &releases {
        for asset in &release.assets {
            // Only process package files.
            let is_pkg = asset.name.ends_with(".deb")
                || asset.name.ends_with(".rpm")
                || asset.name.ends_with(".apk")
                || asset.name.ends_with(".pkg.tar.zst");

            if !is_pkg {
                packages_skipped += 1;
                continue;
            }

            // Determine distro from filename.
            let distro = if asset.name.ends_with(".deb") {
                "apt"
            } else if asset.name.ends_with(".rpm") {
                "dnf"
            } else if asset.name.ends_with(".apk") {
                "apk"
            } else {
                "pacman"
            };

            // Detect codename from filename.
            let lower = asset.name.to_ascii_lowercase();
            let codename: Option<&str> = match distro {
                "apt" => ["noble", "jammy", "bookworm", "trixie"]
                    .iter()
                    .find(|c| lower.contains(*c))
                    .copied(),
                "dnf" => {
                    if lower.contains("el9") || lower.contains("fc") {
                        Some("el9")
                    } else {
                        None
                    }
                },
                "apk" => {
                    if lower.contains("v3.21") {
                        Some("v3.21")
                    } else {
                        None
                    }
                },
                "pacman" => Some("x86_64"),
                _ => None,
            };

            // Download the asset.
            let download_path = format!("{repo_dir}/tmp/{}", asset.name);
            if let Some(parent) = std::path::Path::new(&download_path).parent() {
                tokio::fs::create_dir_all(parent).await.ok();
            }

            tracing::info!(asset = %asset.name, "Downloading package asset");

            let dl_resp = match client.get(&asset.browser_download_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    errors.push(format!("Download failed for {}: {}", asset.name, e));
                    packages_skipped += 1;
                    continue;
                },
            };

            if !dl_resp.status().is_success() {
                errors.push(format!(
                    "Download failed for {}: HTTP {}",
                    asset.name,
                    dl_resp.status()
                ));
                packages_skipped += 1;
                continue;
            }

            let bytes = match dl_resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!("Download body failed for {}: {}", asset.name, e));
                    packages_skipped += 1;
                    continue;
                },
            };

            if let Err(e) = tokio::fs::write(&download_path, &bytes).await {
                errors.push(format!("Write failed for {}: {}", asset.name, e));
                packages_skipped += 1;
                continue;
            }

            // Import into repo.
            let import_ok = match distro {
                "apt" => {
                    let cn = codename.unwrap_or("noble");
                    let output = tokio::process::Command::new("reprepro")
                        .arg("-b")
                        .arg(format!("{repo_dir}/apt"))
                        .arg("includedeb")
                        .arg(cn)
                        .arg(&download_path)
                        .output()
                        .await;
                    match output {
                        Ok(o) if o.status.success() => true,
                        Ok(o) => {
                            errors.push(format!(
                                "reprepro failed for {}: {}",
                                asset.name,
                                String::from_utf8_lossy(&o.stderr)
                            ));
                            false
                        },
                        Err(e) => {
                            errors
                                .push(format!("reprepro command failed for {}: {}", asset.name, e));
                            false
                        },
                    }
                },
                "dnf" => {
                    let dest_dir = format!("{repo_dir}/dnf/el9/Packages");
                    let _ = tokio::fs::create_dir_all(&dest_dir).await;
                    let filename = std::path::Path::new(&download_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("pkg.rpm");
                    let dest = format!("{dest_dir}/{filename}");
                    if let Err(e) = tokio::fs::copy(&download_path, &dest).await {
                        errors.push(format!("Copy failed for {}: {}", asset.name, e));
                        false
                    } else {
                        let output = tokio::process::Command::new("createrepo_c")
                            .arg("--update")
                            .arg(format!("{repo_dir}/dnf/el9"))
                            .output()
                            .await;
                        match output {
                            Ok(o) if o.status.success() => true,
                            Ok(o) => {
                                errors.push(format!(
                                    "createrepo_c failed for {}: {}",
                                    asset.name,
                                    String::from_utf8_lossy(&o.stderr)
                                ));
                                false
                            },
                            Err(e) => {
                                errors.push(format!(
                                    "createrepo_c command failed for {}: {}",
                                    asset.name, e
                                ));
                                false
                            },
                        }
                    }
                },
                "apk" | "pacman" => {
                    let subdir = if distro == "apk" {
                        "apk/v3.21"
                    } else {
                        "pacman/x86_64"
                    };
                    let dest_dir = format!("{repo_dir}/{subdir}");
                    let _ = tokio::fs::create_dir_all(&dest_dir).await;
                    let filename = std::path::Path::new(&download_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("pkg");
                    let dest = format!("{dest_dir}/{filename}");
                    match tokio::fs::copy(&download_path, &dest).await {
                        Ok(_) => true,
                        Err(e) => {
                            errors.push(format!("Copy failed for {}: {}", asset.name, e));
                            false
                        },
                    }
                },
                _ => false,
            };

            if import_ok {
                let _ = sqlx::query(
                    "INSERT INTO repo_packages (filename, version, distro, distro_codename, arch, file_size, source, sync_log_id)\n                     VALUES ($1, $2, $3, $4, 'amd64', $5, 'github', $6)\n                     ON CONFLICT (filename, version, distro, arch) DO NOTHING",
                )
                .bind(&asset.name)
                .bind(&release.tag_name)
                .bind(distro)
                .bind(codename)
                .bind(asset.size as i64)
                .bind(sync_log_id)
                .execute(pool).await;

                packages_synced += 1;
                tracing::info!(asset = %asset.name, "Package imported successfully");
            } else {
                packages_skipped += 1;
            }

            // Clean up temp file.
            let _ = tokio::fs::remove_file(&download_path).await;
        }
    }

    // Update sync_log with results.
    let status = if errors.is_empty() {
        "success"
    } else {
        "partial"
    };
    let error_msg = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };

    sqlx::query(
        "UPDATE repo_sync_log SET status = $2, packages_synced = $3, packages_skipped = $4, error_message = $5, finished_at = NOW() WHERE id = $1",
    )
    .bind(sync_log_id)
    .bind(status)
    .bind(packages_synced)
    .bind(packages_skipped)
    .bind(error_msg)
    .execute(pool).await?;

    tracing::info!(
        sync_log_id = %sync_log_id,
        packages_synced,
        packages_skipped,
        status,
        "Manual repo sync completed"
    );

    Ok(())
}

/// `GET /api/v1/admin/repo/sync-status`
///
/// Returns the status of the most recent sync operations.
async fn sync_status(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let sync_logs: Vec<Value> = sqlx::query_as::<_, (uuid::Uuid, String, String, i32, i32, Option<String>, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>)>(
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

    // Get total package count.
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
///
/// Lists all packages in the manager-hosted repo.
async fn list_packages(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let packages: Vec<Value> = sqlx::query_as::<_, (uuid::Uuid, String, String, String, Option<String>, String, i64, bool, String, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, filename, version, distro, distro_codename, arch, file_size, gpg_signed, source, synced_at
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
                    "gpg_signed": row.7,
                    "source": row.8,
                    "synced_at": row.9,
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
