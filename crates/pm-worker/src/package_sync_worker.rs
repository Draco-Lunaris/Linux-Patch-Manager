//! Package sync worker — pulls packages from GitHub Releases into the
//! manager-hosted package repository.
//!
//! Runs on a configurable schedule (default: hourly). Fetches the last N
//! releases from the GitHub API, downloads package assets, imports them into
//! reprepro (apt) / createrepo_c (dnf), and tracks sync status in the database.
//!
//! Added for issue #116 (M13).

use pm_core::config::AppConfig;
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time;

/// GitHub API release asset representation.
#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// GitHub API release representation.
#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

/// Run the package sync worker loop indefinitely.
///
/// On each tick, fetches releases from GitHub API, downloads package assets,
/// imports into the repo, and updates the database.
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

        if let Err(e) = run_sync_cycle(&pool, &config).await {
            tracing::error!(error = %e, "Package sync cycle failed");
        }
    }
}

/// Run a single sync cycle.
///
/// 1. Create sync_log entry in DB
/// 2. Fetch releases from GitHub API (last N releases)
/// 3. Download package assets
/// 4. Import into reprepro/createrepo_c
/// 5. Update sync_log with results
async fn run_sync_cycle(pool: &PgPool, config: &Arc<AppConfig>) -> Result<(), anyhow::Error> {
    let sync_config = &config.worker.package_sync;
    let repo_dir = &config.repo.dir;

    // Create sync_log entry.
    let sync_log_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO repo_sync_log (triggered_by, status) VALUES ('scheduler', 'running') RETURNING id",
    )
    .fetch_one(pool)
    .await?;

    tracing::info!(sync_log_id = %sync_log_id, "Package sync cycle started");

    // Fetch releases from GitHub API.
    let releases = match fetch_github_releases(sync_config).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Failed to fetch GitHub releases");
            mark_sync_failed(pool, sync_log_id, &format!("GitHub API error: {e}")).await;
            return Err(e);
        },
    };

    let mut packages_synced = 0i32;
    let mut packages_skipped = 0i32;
    let mut errors: Vec<String> = Vec::new();

    for release in &releases {
        for asset in &release.assets {
            // Only process package files.
            if !is_package_file(&asset.name) {
                packages_skipped += 1;
                continue;
            }

            // Determine distro from filename.
            let distro = detect_distro_from_filename(&asset.name);
            if distro.is_none() {
                packages_skipped += 1;
                continue;
            }

            let distro = distro.unwrap();
            let codename = detect_codename_from_filename(&asset.name, &distro);

            // Download the asset.
            let download_path = format!(
                "{repo_dir}/tmp/{asset_name}",
                repo_dir = repo_dir,
                asset_name = asset.name
            );
            match download_asset(&asset.browser_download_url, &download_path, sync_config).await {
                Ok(()) => {
                    // Import into repo.
                    if let Err(e) =
                        import_to_repo(&download_path, &distro, codename.as_deref(), repo_dir).await
                    {
                        errors.push(format!("Import failed for {}: {e}", asset.name));
                        packages_skipped += 1;
                    } else {
                        // Record in repo_packages table.
                        let _ = sqlx::query(
                            "INSERT INTO repo_packages (filename, version, distro, distro_codename, arch, file_size, source, sync_log_id)
                             VALUES ($1, $2, $3, $4, 'amd64', $5, 'github', $6)
                             ON CONFLICT (filename, version, distro, arch) DO NOTHING",
                        )
                        .bind(&asset.name)
                        .bind(&release.tag_name)
                        .bind(&distro)
                        .bind(codename.as_deref())
                        .bind(asset.size as i64)
                        .bind(sync_log_id)
                        .execute(pool)
                        .await;

                        packages_synced += 1;
                    }

                    // Clean up temp file.
                    let _ = tokio::fs::remove_file(&download_path).await;
                },
                Err(e) => {
                    errors.push(format!("Download failed for {}: {e}", asset.name));
                    packages_skipped += 1;
                },
            }
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
    .execute(pool)
    .await?;

    tracing::info!(
        sync_log_id = %sync_log_id,
        packages_synced,
        packages_skipped,
        status,
        "Package sync cycle completed"
    );

    Ok(())
}

/// Fetch releases from GitHub API (last N releases, excluding prereleases unless allowed).
async fn fetch_github_releases(
    config: &pm_core::config::PackageSyncConfig,
) -> Result<Vec<GithubRelease>, anyhow::Error> {
    let url = format!(
        "https://api.github.com/repos/{}/releases?per_page={}",
        config.github_repo,
        config.max_releases.min(100)
    );

    let client = reqwest::Client::builder()
        .user_agent("Linux-Patch-Manager-Sync/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut req = client.get(&url);
    if !config.github_token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", config.github_token));
    }

    let resp = req.send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("GitHub API returned status: {}", resp.status());
    }

    let releases: Vec<GithubRelease> = resp.json().await?;

    // Filter out prereleases.
    let filtered: Vec<GithubRelease> = releases
        .into_iter()
        .filter(|r| !r.prerelease)
        .take(config.max_releases as usize)
        .collect();

    Ok(filtered)
}

/// Download a GitHub asset to a local path.
async fn download_asset(
    url: &str,
    path: &str,
    config: &pm_core::config::PackageSyncConfig,
) -> Result<(), anyhow::Error> {
    // Ensure tmp directory exists.
    if let Some(parent) = std::path::Path::new(path).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    let client = reqwest::Client::builder()
        .user_agent("Linux-Patch-Manager-Sync/1.0")
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut req = client.get(url);
    if !config.github_token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", config.github_token));
    }

    let resp = req.send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("Download failed with status: {}", resp.status());
    }

    let bytes = resp.bytes().await?;
    tokio::fs::write(path, bytes).await?;

    Ok(())
}

/// Import a package file into the appropriate repo format.
async fn import_to_repo(
    file_path: &str,
    distro: &str,
    codename: Option<&str>,
    repo_dir: &str,
) -> Result<(), anyhow::Error> {
    match distro {
        "apt" => {
            let codename = codename.unwrap_or("noble");
            let output = tokio::process::Command::new("reprepro")
                .arg("-b")
                .arg(format!("{repo_dir}/apt"))
                .arg("includedeb")
                .arg(codename)
                .arg(file_path)
                .output()
                .await?;

            if !output.status.success() {
                anyhow::bail!(
                    "reprepro includedeb failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        },
        "dnf" => {
            // Copy RPM to dnf repo directory and regenerate metadata.
            let dest_dir = format!("{repo_dir}/dnf/el9/Packages");
            tokio::fs::create_dir_all(&dest_dir).await.ok();
            let filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package.rpm");
            let dest = format!("{dest_dir}/{filename}");
            tokio::fs::copy(file_path, &dest).await?;

            let output = tokio::process::Command::new("createrepo_c")
                .arg("--update")
                .arg(format!("{repo_dir}/dnf/el9"))
                .output()
                .await?;

            if !output.status.success() {
                anyhow::bail!(
                    "createrepo_c failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        },
        "apk" => {
            // Copy APK to apk repo directory.
            let dest_dir = format!("{repo_dir}/apk/v3.21");
            tokio::fs::create_dir_all(&dest_dir).await.ok();
            let filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package.apk");
            let dest = format!("{dest_dir}/{filename}");
            tokio::fs::copy(file_path, &dest).await?;

            // Generate APK index.
            let output = tokio::process::Command::new("apk")
                .arg("index")
                .arg("-o")
                .arg(format!("{dest_dir}/APKINDEX.tar.gz"))
                .arg(&dest)
                .output()
                .await?;

            if !output.status.success() {
                tracing::warn!(
                    "apk index failed (non-fatal): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        },
        "pacman" => {
            // Copy to pacman repo directory.
            let dest_dir = format!("{repo_dir}/pacman/x86_64");
            tokio::fs::create_dir_all(&dest_dir).await.ok();
            let filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package.pkg.tar.zst");
            let dest = format!("{dest_dir}/{filename}");
            tokio::fs::copy(file_path, &dest).await?;

            // Update pacman repo database.
            let output = tokio::process::Command::new("repo-add")
                .arg(format!("{dest_dir}/lpa-repo.db.tar.zst"))
                .arg(&dest)
                .output()
                .await?;

            if !output.status.success() {
                tracing::warn!(
                    "repo-add failed (non-fatal): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        },
        _ => {
            anyhow::bail!("Unsupported distro: {distro}");
        },
    }

    Ok(())
}

/// Check if a filename is a recognized package file.
fn is_package_file(name: &str) -> bool {
    name.ends_with(".deb")
        || name.ends_with(".rpm")
        || name.ends_with(".apk")
        || name.ends_with(".pkg.tar.zst")
}

/// Detect repo format (apt/dnf/apk/pacman) from filename patterns.
fn detect_distro_from_filename(name: &str) -> Option<String> {
    if name.ends_with(".deb") {
        Some("apt".to_string())
    } else if name.ends_with(".rpm") {
        Some("dnf".to_string())
    } else if name.ends_with(".apk") {
        Some("apk".to_string())
    } else if name.ends_with(".pkg.tar.zst") {
        Some("pacman".to_string())
    } else {
        None
    }
}

/// Detect codename from filename patterns.
///
/// Expected patterns: `*_noble_amd64.deb`, `*_jammy_amd64.deb`,
/// `*_bookworm_amd64.deb`, `*_trixie_amd64.deb`, `*_el9.x86_64.rpm`, etc.
fn detect_codename_from_filename(name: &str, distro: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    match distro {
        "apt" => {
            for codename in &["noble", "jammy", "bookworm", "trixie"] {
                if lower.contains(codename) {
                    return Some(codename.to_string());
                }
            }
            None
        },
        "dnf" => {
            if lower.contains("el9") || lower.contains("fc") {
                Some("el9".to_string())
            } else {
                None
            }
        },
        "apk" => {
            if lower.contains("v3.21") {
                Some("v3.21".to_string())
            } else {
                None
            }
        },
        "pacman" => Some("x86_64".to_string()),
        _ => None,
    }
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
