//! Shared package sync logic for the manager-hosted package repository.
//!
//! Both the scheduled worker (`pm-worker`) and the manual admin trigger
//! (`pm-web` routes) call these functions to avoid code duplication.
//!
//! Added for Phase 5 of issue #116 gap fix (consolidate sync logic).

use crate::config::PackageSyncConfig;
use chrono::{DateTime, Utc};
use serde::Deserialize;

/// GitHub API release asset representation.
#[derive(Debug, Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

/// GitHub API release representation.
#[derive(Debug, Deserialize)]
pub struct GithubRelease {
    pub tag_name: String,
    pub prerelease: bool,
    pub assets: Vec<GithubAsset>,
    /// ISO 8601 timestamp from the GitHub API — may be null for drafts.
    #[serde(default)]
    pub published_at: Option<DateTime<Utc>>,
}

/// Information about a successfully synced package — for DB persistence.
#[derive(Debug, Clone)]
pub struct SyncedPackage {
    pub filename: String,
    pub version: String,
    pub distro: String,
    pub distro_codename: Option<String>,
    pub file_size: i64,
    pub sha256: Option<String>,
    /// When the GitHub release was published. Stored in repo_packages.published_at
    /// so version resolution can sort by release date.
    pub published_at: Option<DateTime<Utc>>,
}

/// Result of a sync cycle — counts, errors, and synced package details for DB update.
#[derive(Debug, Default)]
pub struct SyncResult {
    pub packages_synced: i32,
    pub packages_skipped: i32,
    pub errors: Vec<String>,
    /// Details of each successfully synced package — for repo_packages table INSERT.
    pub synced_packages: Vec<SyncedPackage>,
}

/// Fetch releases from GitHub API (last N releases, excluding prereleases unless allowed).
pub async fn fetch_github_releases(
    config: &PackageSyncConfig,
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

    let resp = client.get(&url).send().await?;

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

/// Download a GitHub asset to a local path and compute its SHA256 checksum.
///
/// Returns the hex-encoded SHA256 digest for storage in `repo_packages.sha256`.
pub async fn download_asset(
    url: &str,
    path: &str,
    _config: &PackageSyncConfig,
) -> Result<String, anyhow::Error> {
    use sha2::{Digest, Sha256};

    // Ensure tmp directory exists — propagate error instead of silently swallowing it.
    if let Some(parent) = std::path::Path::new(path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let client = reqwest::Client::builder()
        .user_agent("Linux-Patch-Manager-Sync/1.0")
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let resp = client.get(url).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("Download failed with status: {}", resp.status());
    }

    let bytes = resp.bytes().await?;

    // Compute SHA256 checksum for integrity tracking.
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hex::encode(hasher.finalize());

    tokio::fs::write(path, bytes).await?;

    Ok(digest)
}

/// Import a package file into the appropriate repo format.
///
/// All metadata generation is done in pure Rust via `repo_metadata`.
/// GPG signing of metadata files is handled within each generator
/// using `pm_core::gpg::sign_file_detached()` / `sign_file_clearsign()`.
pub async fn import_to_repo(
    file_path: &str,
    distro: &str,
    codename: Option<&str>,
    repo_dir: &str,
    apk_rsa_private_key_path: Option<&str>,
) -> Result<(), anyhow::Error> {
    use crate::repo_metadata;

    match distro {
        "apt" => {
            let suite = codename.unwrap_or("u2404");

            // Copy .deb to apt pool directory.
            let pool_dir = format!("{repo_dir}/apt/pool");
            tokio::fs::create_dir_all(&pool_dir).await?;
            let filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package.deb");
            let dest = format!("{pool_dir}/{filename}");
            tokio::fs::copy(file_path, &dest).await?;

            // Generate apt metadata (Packages, Release, InRelease, Release.gpg).
            repo_metadata::generate_apt_metadata(repo_dir, suite).await?;
        },
        "dnf" => {
            // Copy RPM to dnf repo Packages directory.
            let codename = crate::repo_metadata::DNF_CODENAME;
            let dest_dir = format!("{repo_dir}/dnf/{codename}/Packages");
            tokio::fs::create_dir_all(&dest_dir).await?;
            let filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package.rpm");
            let dest = format!("{dest_dir}/{filename}");
            tokio::fs::copy(file_path, &dest).await?;

            // Generate DNF metadata (primary.xml.gz, filelists.xml.gz, repomd.xml).
            repo_metadata::generate_dnf_metadata(repo_dir).await?;

            // Sign repomd.xml with detached GPG signature for dnf verification.
            let codename = crate::repo_metadata::DNF_CODENAME;
            let repomd_path = format!("{repo_dir}/dnf/{codename}/repodata/repomd.xml");
            let repomd_sig_path = format!("{repo_dir}/dnf/{codename}/repodata/repomd.xml.asc");
            if std::path::Path::new(&repomd_path).exists() {
                if let Err(e) =
                    crate::gpg::sign_file_detached(&repomd_path, &repomd_sig_path, true).await
                {
                    tracing::warn!(error = %e, "GPG sign repomd.xml failed (non-fatal but clients will not trust this repo)");
                }
            }
        },
        "apk" => {
            // Copy APK to apk repo directory (apk/{codename}/{arch}/).
            // apk fetches packages from the arch subdirectory, same as
            // generate_apk_metadata which writes APKINDEX there.
            let codename = crate::repo_metadata::APK_CODENAME;
            let dest_dir = format!("{repo_dir}/apk/{codename}/x86_64");
            tokio::fs::create_dir_all(&dest_dir).await?;
            let filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package.apk");
            let dest = format!("{dest_dir}/{filename}");
            tokio::fs::copy(file_path, &dest).await?;

            // Re-sign the .apk with the manager's RSA key.
            // CI-built .apk files are signed by an ephemeral abuild-keygen
            // key that agents do not have in /etc/apk/keys/. The manager
            // must re-sign each .apk with its own lpa-repo RSA key (the
            // same key used for APKINDEX signing) so that apk 3.x can
            // verify the per-package signature.
            let rsa_priv_path = match apk_rsa_private_key_path {
                Some(p) if !p.is_empty() => p.to_string(),
                _ => std::env::var("LPA_APK_RSA_PRIVATE_KEY_PATH")
                    .unwrap_or_else(|_| "/etc/patch-manager/ca/lpa-repo-rsa.pem".to_string()),
            };

            // Re-sign the .apk in a blocking task (file I/O + RSA signing).
            let dest_clone = dest.clone();
            let rsa_priv_clone = rsa_priv_path.clone();
            match tokio::task::spawn_blocking(move || {
                crate::repo_metadata::resign_apk(&dest_clone, &rsa_priv_clone)
            })
            .await
            {
                Ok(Ok(())) => {
                    tracing::info!(
                        filename = %filename,
                        "APK re-signed with manager RSA key"
                    );
                },
                Ok(Err(e)) => {
                    tracing::warn!(
                        error = %e,
                        filename = %filename,
                        "Failed to re-sign APK — apk will report UNTRUSTED for this package"
                    );
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        filename = %filename,
                        "Re-sign task panicked — apk will report UNTRUSTED for this package"
                    );
                },
            }

            // Generate APK index (APKINDEX.tar.gz) with embedded RSA signature.
            // apk 3.x expects the signature as a .SIGN.RSA.<keyname> tar entry,
            // not as a detached .sig file. The signing happens inside
            // generate_apk_metadata using the RSA private key.
            // generate_apk_metadata does RSA signing in a blocking task
            // internally (RSA signing is CPU-bound).
            match repo_metadata::generate_apk_metadata(repo_dir, Some(&rsa_priv_path)).await {
                Ok(()) => {
                    tracing::info!(
                        dest_dir = %dest_dir,
                        "APKINDEX.tar.gz generated with embedded RSA-SHA256 signature for apk 3.x"
                    );
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Failed to generate signed APKINDEX (Alpine clients will not trust this repo)"
                    );
                },
            }
        },
        "pacman" => {
            // Copy to pacman repo directory.
            let dest_dir = format!("{repo_dir}/pacman/x86_64");
            tokio::fs::create_dir_all(&dest_dir).await?;
            let filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package.pkg.tar.zst");
            let dest = format!("{dest_dir}/{filename}");
            tokio::fs::copy(file_path, &dest).await?;

            // Generate pacman repo database (lpa-repo.db.tar.zst + lpa-repo.db) in pure Rust.
            repo_metadata::generate_pacman_metadata(repo_dir).await?;

            // Sign lpa-repo.db.tar.zst with detached GPG signature for pacman verification.
            let db_zst_path = format!("{dest_dir}/lpa-repo.db.tar.zst");
            let db_zst_sig_path = format!("{dest_dir}/lpa-repo.db.tar.zst.sig");
            if std::path::Path::new(&db_zst_path).exists() {
                if let Err(e) =
                    crate::gpg::sign_file_detached(&db_zst_path, &db_zst_sig_path, false).await
                {
                    tracing::warn!(error = %e, "GPG sign lpa-repo.db.tar.zst failed (non-fatal but clients will not trust this repo)");
                }
            }

            // Also sign lpa-repo.db (gzip variant) for clients that download .db
            let db_gz_path = format!("{dest_dir}/lpa-repo.db");
            let db_gz_sig_path = format!("{dest_dir}/lpa-repo.db.sig");
            if std::path::Path::new(&db_gz_path).exists() {
                if let Err(e) =
                    crate::gpg::sign_file_detached(&db_gz_path, &db_gz_sig_path, false).await
                {
                    tracing::warn!(error = %e, "GPG sign lpa-repo.db failed (non-fatal but clients will not trust this repo)");
                }
            }
        },
        _ => {
            anyhow::bail!("Unsupported distro: {distro}");
        },
    }

    Ok(())
}

/// Check if a filename is a recognized package file.
pub fn is_package_file(name: &str) -> bool {
    name.ends_with(".deb")
        || name.ends_with(".rpm")
        || name.ends_with(".apk")
        || name.ends_with(".pkg.tar.zst")
}

/// Check if a filename is a manager .deb package.
///
/// Manager packages are named `linux-patch-manager_*.deb` (see
/// `scripts/build-package.sh`). Agent packages are named
/// `linux-patch-api_*.deb`. Manager packages are synced into the apt pool
/// AND tracked in `repo_packages` (with `distro='apt'`, no codename) so
/// they appear in the Repo Management UI. They are filtered out of the
/// agent upgrade catalog by filename pattern in `upgrades.rs`.
pub fn is_manager_package(name: &str) -> bool {
    name.starts_with("linux-patch-manager") && name.ends_with(".deb")
}

/// Detect repo format (apt/dnf/apk/pacman) from filename patterns.
pub fn detect_distro_from_filename(name: &str) -> Option<String> {
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

/// Detect the apt suite (filename token) from a .deb filename.
///
/// The suite name IS the token that appears in the filename (e.g. `u2404`
/// from `linux-patch-api_2.4.2_u2404_amd64.deb`). No codename mapping —
/// the token is used directly as the `dists/<suite>/` directory name and
/// the apt suite in `sources.list`.
///
/// For non-apt distros, returns the sub-directory identifier (e.g. `el9`,
/// `v3.21`, `x86_64`).
pub fn detect_codename_from_filename(name: &str, distro: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    match distro {
        "apt" => {
            // The token appears as _<token>_ in the filename.
            for suite in crate::repo_metadata::APT_SUITES {
                if lower.contains(&format!("_{suite}_")) {
                    return Some(suite.to_string());
                }
            }
            None
        },
        "dnf" => {
            let codename = crate::repo_metadata::DNF_CODENAME;
            if lower.contains(codename) || lower.contains("fc") {
                Some(codename.to_string())
            } else {
                None
            }
        },
        "apk" => {
            let codename = crate::repo_metadata::APK_CODENAME;
            if lower.contains(codename) {
                Some(codename.to_string())
            } else {
                None
            }
        },
        "pacman" => Some("x86_64".to_string()),
        _ => None,
    }
}

/// Information about an existing package in the local repo, used by
/// `run_sync_cycle` to skip re-downloading unchanged assets.
#[derive(Debug, Clone)]
pub struct ExistingPackage {
    pub filename: String,
    pub version: String,
    pub distro: String,
    pub sha256: Option<String>,
}

/// Sync manager .deb packages from the manager's own GitHub Releases into
/// the apt pool.
///
/// This is separate from agent package sync because:
/// 1. Manager packages come from a different GitHub repo
///    (`manager_github_repo`, default `Draco-Lunaris/Linux-Patch-Manager`).
/// 2. Manager packages are NOT recorded in `repo_packages` — that table
///    drives the agent upgrade UI. The manager .deb just needs to be in
///    the apt pool so the manager host's `apt-get upgrade` finds it during
///    scheduled maintenance.
/// 3. Only .deb is supported (the manager targets Ubuntu 24.04).
///
/// Returns the count of manager packages downloaded (0 if none found or
/// already up-to-date). Errors are collected into `result.errors` rather
/// than propagated, so a manager-sync failure does not abort the agent sync.
pub async fn sync_manager_packages(
    config: &PackageSyncConfig,
    repo_dir: &str,
    result: &mut SyncResult,
) {
    let repo = &config.manager_github_repo;
    if repo.is_empty() {
        return;
    }

    let url = format!(
        "https://api.github.com/repos/{}/releases?per_page={}",
        repo,
        config.max_releases.min(100)
    );

    let client = match reqwest::Client::builder()
        .user_agent("Linux-Patch-Manager-Sync/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result
                .errors
                .push(format!("Manager sync: HTTP client build failed: {e}"));
            return;
        },
    };

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            result
                .errors
                .push(format!("Manager sync: GitHub API request failed: {e}"));
            return;
        },
    };

    if !resp.status().is_success() {
        result.errors.push(format!(
            "Manager sync: GitHub API returned status: {}",
            resp.status()
        ));
        return;
    }

    let releases: Vec<GithubRelease> = match resp.json().await {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!(
                "Manager sync: failed to parse GitHub response: {e}"
            ));
            return;
        },
    };

    let releases: Vec<GithubRelease> = releases
        .into_iter()
        .filter(|r| !r.prerelease)
        .take(config.max_releases as usize)
        .collect();

    let pool_dir = format!("{repo_dir}/apt/pool");
    if let Err(e) = tokio::fs::create_dir_all(&pool_dir).await {
        result
            .errors
            .push(format!("Manager sync: failed to create apt pool dir: {e}"));
        return;
    }

    let version_from_tag = |tag: &str| tag.strip_prefix('v').unwrap_or(tag).to_string();

    for release in &releases {
        let version = version_from_tag(&release.tag_name);

        for asset in &release.assets {
            if !is_manager_package(&asset.name) {
                continue;
            }

            let dest = format!("{pool_dir}/{}", asset.name);

            // Skip if already present on disk.
            if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
                tracing::debug!(
                    filename = %asset.name,
                    "Manager package already in apt pool — skipping download"
                );
                // Still register in synced_packages so it gets upserted into
                // repo_packages and appears in the Repo Management UI.
                result.synced_packages.push(SyncedPackage {
                    filename: asset.name.clone(),
                    version: version.clone(),
                    distro: "apt".to_string(),
                    distro_codename: None,
                    file_size: asset.size as i64,
                    sha256: None,
                    published_at: release.published_at,
                });
                continue;
            }

            // Download to tmp then move into pool.
            let tmp_path = format!("{repo_dir}/tmp/{}", asset.name);
            match download_asset(&asset.browser_download_url, &tmp_path, config).await {
                Ok(sha256) => {
                    if let Err(e) = tokio::fs::copy(&tmp_path, &dest).await {
                        result.errors.push(format!(
                            "Manager sync: failed to copy {} to pool: {e}",
                            asset.name
                        ));
                    } else {
                        tracing::info!(
                            filename = %asset.name,
                            version = %release.tag_name,
                            "Manager .deb synced to apt pool"
                        );
                        result.packages_synced += 1;
                        result.synced_packages.push(SyncedPackage {
                            filename: asset.name.clone(),
                            version: version.clone(),
                            distro: "apt".to_string(),
                            distro_codename: None,
                            file_size: asset.size as i64,
                            sha256: Some(sha256),
                            published_at: release.published_at,
                        });
                    }
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                },
                Err(e) => {
                    result.errors.push(format!(
                        "Manager sync: download failed for {}: {e}",
                        asset.name
                    ));
                },
            }
        }
    }
}

/// Run a full sync cycle: fetch releases, download assets, import into repo.
///
/// This is the shared entry point called by both the scheduled worker and
/// the manual admin trigger. The caller is responsible for creating and
/// updating the `repo_sync_log` DB entry.
///
/// `existing_packages` is the list of packages already in the local repo
/// (from the `repo_packages` DB table). Assets matching an existing package
/// by (filename, version, distro) with a matching sha256 are skipped — no
/// re-download. If the sha256 differs or is missing, the asset is re-downloaded.
///
/// Returns a `SyncResult` with counts and errors for the caller to persist.
pub async fn run_sync_cycle(
    config: &PackageSyncConfig,
    repo_dir: &str,
    apk_rsa_private_key_path: Option<&str>,
    existing_packages: &[ExistingPackage],
) -> Result<SyncResult, anyhow::Error> {
    let sync_config = config;

    let releases = fetch_github_releases(sync_config).await?;

    let mut result = SyncResult::default();

    // Build a lookup set of (filename, version, distro) -> sha256 for fast checks.
    let existing_map: std::collections::HashMap<(String, String, String), Option<String>> =
        existing_packages
            .iter()
            .map(|p| {
                (
                    (p.filename.clone(), p.version.clone(), p.distro.clone()),
                    p.sha256.clone(),
                )
            })
            .collect();

    for release in &releases {
        for asset in &release.assets {
            // Only process package files.
            if !is_package_file(&asset.name) {
                result.packages_skipped += 1;
                continue;
            }

            // Determine distro from filename.
            let distro = detect_distro_from_filename(&asset.name);
            if distro.is_none() {
                result.packages_skipped += 1;
                continue;
            }

            let distro = distro.unwrap();
            let codename = detect_codename_from_filename(&asset.name, &distro);
            let version = release
                .tag_name
                .strip_prefix('v')
                .unwrap_or(&release.tag_name)
                .to_string();

            // Check if we already have this package with the same sha256.
            let key = (asset.name.clone(), version.clone(), distro.clone());
            if let Some(Some(_existing_sha)) = existing_map.get(&key) {
                // We have a record. Verify the local file still exists on disk.
                let local_path = local_package_path(repo_dir, &distro, &codename, &asset.name);
                if let Some(ref local) = local_path {
                    if tokio::fs::try_exists(local).await.unwrap_or(false) {
                        // File exists on disk and sha256 matches — skip download.
                        tracing::debug!(
                            filename = %asset.name,
                            version = %version,
                            "Skipping unchanged package (sha256 match)"
                        );
                        result.packages_skipped += 1;
                        continue;
                    }
                }
            }

            // Download the asset.
            let download_path = format!("{repo_dir}/tmp/{}", asset.name);
            match download_asset(&asset.browser_download_url, &download_path, sync_config).await {
                Ok(sha256) => {
                    // Import into repo.
                    if let Err(e) = import_to_repo(
                        &download_path,
                        &distro,
                        codename.as_deref(),
                        repo_dir,
                        apk_rsa_private_key_path,
                    )
                    .await
                    {
                        result
                            .errors
                            .push(format!("Import failed for {}: {e}", asset.name));
                        result.packages_skipped += 1;
                    } else {
                        result.packages_synced += 1;
                        result.synced_packages.push(SyncedPackage {
                            filename: asset.name.clone(),
                            version,
                            distro: distro.clone(),
                            distro_codename: codename.clone(),
                            file_size: asset.size as i64,
                            sha256: Some(sha256),
                            published_at: release.published_at,
                        });
                    }

                    // Clean up temp file.
                    let _ = tokio::fs::remove_file(&download_path).await;
                },
                Err(e) => {
                    result
                        .errors
                        .push(format!("Download failed for {}: {e}", asset.name));
                    result.packages_skipped += 1;
                },
            }
        }
    }

    // Sync manager .deb packages from the manager's own GitHub Releases
    // into the apt pool and repo_packages DB. This is done here (not in
    // the agent release loop above) because manager packages come from a
    // different repo. The .deb is placed in the pool for apt-get upgrade
    // on the manager host, and registered in repo_packages so it shows up
    // in the Repo Management UI. Metadata is regenerated below by the
    // existing regenerate_all_apt_metadata call.
    sync_manager_packages(sync_config, repo_dir, &mut result).await;

    // Regenerate apt metadata for all suites so every dists/<suite>/ index
    // reflects the current pool contents.
    let metadata_errors = crate::repo_metadata::regenerate_all_apt_metadata(repo_dir).await;
    for (suite, error) in metadata_errors {
        result.errors.push(format!(
            "apt metadata regeneration failed for {suite}: {error}"
        ));
    }

    Ok(result)
}

/// Resolve the on-disk path of a package file in the repo directory.
/// Returns None if the distro/format is unknown.
fn local_package_path(
    repo_dir: &str,
    distro: &str,
    _codename: &Option<String>,
    filename: &str,
) -> Option<String> {
    match distro {
        "apt" => Some(format!("{repo_dir}/apt/pool/{filename}")),
        "dnf" => {
            let codename = crate::repo_metadata::DNF_CODENAME;
            Some(format!("{repo_dir}/dnf/{codename}/Packages/{filename}"))
        },
        "apk" => {
            let codename = crate::repo_metadata::APK_CODENAME;
            Some(format!("{repo_dir}/apk/{codename}/x86_64/{filename}"))
        },
        "pacman" => Some(format!("{repo_dir}/pacman/x86_64/{filename}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_package_file_recognizes_all_formats() {
        assert!(is_package_file("linux-patch-api_1.0.0_u2404_amd64.deb"));
        assert!(is_package_file("linux-patch-api-1.0.0-1.el9.x86_64.rpm"));
        assert!(is_package_file("linux-patch-api-1.0.0-r0.apk"));
        assert!(is_package_file(
            "linux-patch-api-1.0.0-1-x86_64.pkg.tar.zst"
        ));
    }

    #[test]
    fn test_is_package_file_rejects_non_packages() {
        assert!(!is_package_file("README.md"));
        assert!(!is_package_file("checksums.txt"));
        assert!(!is_package_file("source.tar.gz"));
        assert!(!is_package_file(""));
    }

    #[test]
    fn test_is_manager_package_recognizes_manager_deb() {
        assert!(is_manager_package("linux-patch-manager_1.6.4-1_amd64.deb"));
        assert!(is_manager_package("linux-patch-manager_2.0.0-1_amd64.deb"));
    }

    #[test]
    fn test_is_manager_package_rejects_agent_deb() {
        assert!(!is_manager_package(
            "linux-patch-api_2.6.11_u2404_amd64.deb"
        ));
    }

    #[test]
    fn test_is_manager_package_rejects_non_deb() {
        assert!(!is_manager_package(
            "linux-patch-manager-1.0.0-1.el9.x86_64.rpm"
        ));
        assert!(!is_manager_package("README.md"));
    }

    #[test]
    fn test_detect_distro_deb() {
        assert_eq!(
            detect_distro_from_filename("pkg_1.0_u2404_amd64.deb"),
            Some("apt".to_string())
        );
    }

    #[test]
    fn test_detect_distro_rpm() {
        assert_eq!(
            detect_distro_from_filename("pkg-1.0.el9.x86_64.rpm"),
            Some("dnf".to_string())
        );
    }

    #[test]
    fn test_detect_distro_apk() {
        assert_eq!(
            detect_distro_from_filename("pkg-1.0-r0.apk"),
            Some("apk".to_string())
        );
    }

    #[test]
    fn test_detect_distro_pacman() {
        assert_eq!(
            detect_distro_from_filename("pkg-1.0-1-x86_64.pkg.tar.zst"),
            Some("pacman".to_string())
        );
    }

    #[test]
    fn test_detect_distro_unknown() {
        assert_eq!(detect_distro_from_filename("file.txt"), None);
    }

    #[test]
    fn test_detect_suite_apt_u2404() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_1.5.6_u2404_amd64.deb", "apt"),
            Some("u2404".to_string())
        );
    }

    #[test]
    fn test_detect_suite_apt_u2204() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_1.5.6_u2204_amd64.deb", "apt"),
            Some("u2204".to_string())
        );
    }

    #[test]
    fn test_detect_suite_apt_u2604() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_2.1.1_u2604_amd64.deb", "apt"),
            Some("u2604".to_string())
        );
    }

    #[test]
    fn test_detect_suite_apt_debian12() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_1.5.6_debian12_amd64.deb", "apt"),
            Some("debian12".to_string())
        );
    }

    #[test]
    fn test_detect_suite_apt_debian13() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_1.5.6_debian13_amd64.deb", "apt"),
            Some("debian13".to_string())
        );
    }

    #[test]
    fn test_detect_suite_dnf_el9() {
        assert_eq!(
            detect_codename_from_filename("pkg-1.0.el9.x86_64.rpm", "dnf"),
            Some(crate::repo_metadata::DNF_CODENAME.to_string())
        );
    }

    #[test]
    fn test_detect_suite_apk_v321() {
        assert_eq!(
            detect_codename_from_filename("pkg-1.0-v3.21.apk", "apk"),
            Some(crate::repo_metadata::APK_CODENAME.to_string())
        );
    }

    #[test]
    fn test_detect_suite_pacman() {
        assert_eq!(
            detect_codename_from_filename("pkg-1.0-1-x86_64.pkg.tar.zst", "pacman"),
            Some("x86_64".to_string())
        );
    }

    #[test]
    fn test_detect_suite_unknown_distro() {
        assert_eq!(detect_codename_from_filename("file.deb", "unknown"), None);
    }

    #[test]
    fn test_detect_suite_apt_not_found() {
        assert_eq!(
            detect_codename_from_filename("pkg_1.0_amd64.deb", "apt"),
            None
        );
    }

    #[test]
    fn test_synced_package_struct() {
        let pkg = SyncedPackage {
            filename: "test.deb".to_string(),
            version: "v1.0.0".to_string(),
            distro: "apt".to_string(),
            distro_codename: Some("u2404".to_string()),
            file_size: 1024,
            sha256: Some("abc123".to_string()),
            published_at: None,
        };
        assert_eq!(pkg.filename, "test.deb");
        assert_eq!(pkg.sha256, Some("abc123".to_string()));
    }

    #[test]
    fn test_sync_result_default() {
        let result = SyncResult::default();
        assert_eq!(result.packages_synced, 0);
        assert_eq!(result.packages_skipped, 0);
        assert!(result.errors.is_empty());
        assert!(result.synced_packages.is_empty());
    }
}
