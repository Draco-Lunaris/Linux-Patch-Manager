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
) -> Result<(), anyhow::Error> {
    use crate::repo_metadata;

    match distro {
        "apt" => {
            let codename = codename.unwrap_or("noble");

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
            repo_metadata::generate_apt_metadata(repo_dir, codename).await?;
        },
        "dnf" => {
            // Copy RPM to dnf repo Packages directory.
            let dest_dir = format!("{repo_dir}/dnf/el9/Packages");
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
            let repomd_path = format!("{repo_dir}/dnf/el9/repodata/repomd.xml");
            let repomd_sig_path = format!("{repo_dir}/dnf/el9/repodata/repomd.xml.asc");
            if std::path::Path::new(&repomd_path).exists() {
                if let Err(e) =
                    crate::gpg::sign_file_detached(&repomd_path, &repomd_sig_path, true).await
                {
                    tracing::warn!(error = %e, "GPG sign repomd.xml failed (non-fatal but clients will not trust this repo)");
                }
            }
        },
        "apk" => {
            // Copy APK to apk repo directory.
            let dest_dir = format!("{repo_dir}/apk/v3.21");
            tokio::fs::create_dir_all(&dest_dir).await?;
            let filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package.apk");
            let dest = format!("{dest_dir}/{filename}");
            tokio::fs::copy(file_path, &dest).await?;

            // Generate APK index (APKINDEX.tar.gz) in pure Rust.
            repo_metadata::generate_apk_metadata(repo_dir).await?;

            // Sign APKINDEX.tar.gz with detached GPG signature for apk verification.
            let apkindex_path = format!("{dest_dir}/APKINDEX.tar.gz");
            let apkindex_sig_path = format!("{dest_dir}/APKINDEX.tar.gz.sig");
            if std::path::Path::new(&apkindex_path).exists() {
                if let Err(e) =
                    crate::gpg::sign_file_detached(&apkindex_path, &apkindex_sig_path, false).await
                {
                    tracing::warn!(error = %e, "GPG sign APKINDEX.tar.gz failed (non-fatal but clients will not trust this repo)");
                }
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

            // Generate pacman repo database (lpa-repo.db.tar.zst) in pure Rust.
            repo_metadata::generate_pacman_metadata(repo_dir).await?;

            // Sign lpa-repo.db.tar.zst with detached GPG signature for pacman verification.
            let db_path = format!("{dest_dir}/lpa-repo.db.tar.zst");
            let db_sig_path = format!("{dest_dir}/lpa-repo.db.tar.zst.sig");
            if std::path::Path::new(&db_path).exists() {
                if let Err(e) = crate::gpg::sign_file_detached(&db_path, &db_sig_path, false).await
                {
                    tracing::warn!(error = %e, "GPG sign lpa-repo.db.tar.zst failed (non-fatal but clients will not trust this repo)");
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

/// Detect codename from filename patterns.
///
/// Recognizes both Debian-suite codenames (`noble`, `jammy`, `bookworm`,
/// `trixie`, `resolute`) and the `os_package_mappings` filename tokens
/// (`_u2404_`, `_u2204_`, `_u2604_`, `_debian12_`, `_debian13_`) that the
/// agent's .deb assets use. The token form is mapped to the corresponding
/// apt suite so that `generate_apt_metadata` (which scans the pool by
/// codename) includes the file in the correct
/// `dists/<codename>/main/binary-amd64/Packages` index.
///
/// Expected patterns:
/// - `*_noble_amd64.deb`, `*_jammy_amd64.deb`, `*_bookworm_amd64.deb`,
///   `*_trixie_amd64.deb`, `*_resolute_amd64.deb`
/// - `*_u2404_amd64.deb` → `noble`, `*_u2204_amd64.deb` → `jammy`,
///   `*_u2604_amd64.deb` → `resolute`, `*_debian12_amd64.deb` → `bookworm`,
///   `*_debian13_amd64.deb` → `trixie`
/// - `*_el9.x86_64.rpm`, `*_fc43.x86_64.rpm`, etc.
pub fn detect_codename_from_filename(name: &str, distro: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    match distro {
        "apt" => {
            let token_to_codename: &[(&str, &str)] = &[
                ("_u2404_", "noble"),
                ("_u2204_", "jammy"),
                ("_u2604_", "resolute"),
                ("_debian12_", "bookworm"),
                ("_debian13_", "trixie"),
            ];
            for (token, codename) in token_to_codename {
                if lower.contains(token) {
                    return Some((*codename).to_string());
                }
            }
            for codename in &["noble", "jammy", "bookworm", "trixie", "resolute"] {
                if lower.contains(codename) {
                    return Some((*codename).to_string());
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

/// Run a full sync cycle: fetch releases, download assets, import into repo.
///
/// This is the shared entry point called by both the scheduled worker and
/// the manual admin trigger. The caller is responsible for creating and
/// updating the `repo_sync_log` DB entry.
///
/// Returns a `SyncResult` with counts and errors for the caller to persist.
pub async fn run_sync_cycle(
    config: &PackageSyncConfig,
    repo_dir: &str,
) -> Result<SyncResult, anyhow::Error> {
    let sync_config = config;

    let releases = fetch_github_releases(sync_config).await?;

    let mut result = SyncResult::default();

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

            // Download the asset.
            let download_path = format!("{repo_dir}/tmp/{}", asset.name);
            match download_asset(&asset.browser_download_url, &download_path, sync_config).await {
                Ok(sha256) => {
                    // Import into repo.
                    if let Err(e) =
                        import_to_repo(&download_path, &distro, codename.as_deref(), repo_dir).await
                    {
                        result
                            .errors
                            .push(format!("Import failed for {}: {e}", asset.name));
                        result.packages_skipped += 1;
                    } else {
                        result.packages_synced += 1;
                        let version = release
                            .tag_name
                            .strip_prefix('v')
                            .unwrap_or(&release.tag_name)
                            .to_string();
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

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_package_file_recognizes_all_formats() {
        assert!(is_package_file("linux-patch-api_1.0.0_noble_amd64.deb"));
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
    fn test_detect_distro_deb() {
        assert_eq!(
            detect_distro_from_filename("pkg_1.0_noble_amd64.deb"),
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
    fn test_detect_codename_apt_noble() {
        assert_eq!(
            detect_codename_from_filename("pkg_1.0_noble_amd64.deb", "apt"),
            Some("noble".to_string())
        );
    }

    #[test]
    fn test_detect_codename_apt_jammy() {
        assert_eq!(
            detect_codename_from_filename("pkg_1.0_jammy_amd64.deb", "apt"),
            Some("jammy".to_string())
        );
    }

    #[test]
    fn test_detect_codename_apt_bookworm() {
        assert_eq!(
            detect_codename_from_filename("pkg_1.0_bookworm_amd64.deb", "apt"),
            Some("bookworm".to_string())
        );
    }

    #[test]
    fn test_detect_codename_apt_trixie() {
        assert_eq!(
            detect_codename_from_filename("pkg_1.0_trixie_amd64.deb", "apt"),
            Some("trixie".to_string())
        );
    }

    #[test]
    fn test_detect_codename_dnf_el9() {
        assert_eq!(
            detect_codename_from_filename("pkg-1.0.el9.x86_64.rpm", "dnf"),
            Some("el9".to_string())
        );
    }

    #[test]
    fn test_detect_codename_apk_v321() {
        assert_eq!(
            detect_codename_from_filename("pkg-1.0-v3.21.apk", "apk"),
            Some("v3.21".to_string())
        );
    }

    #[test]
    fn test_detect_codename_pacman() {
        assert_eq!(
            detect_codename_from_filename("pkg-1.0-1-x86_64.pkg.tar.zst", "pacman"),
            Some("x86_64".to_string())
        );
    }

    #[test]
    fn test_detect_codename_unknown_distro() {
        assert_eq!(detect_codename_from_filename("file.deb", "unknown"), None);
    }

    #[test]
    fn test_detect_codename_apt_not_found() {
        assert_eq!(
            detect_codename_from_filename("pkg_1.0_amd64.deb", "apt"),
            None
        );
    }

    #[test]
    fn test_detect_codename_apt_u2404_maps_to_noble() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_1.5.6_u2404_amd64.deb", "apt"),
            Some("noble".to_string())
        );
    }

    #[test]
    fn test_detect_codename_apt_u2204_maps_to_jammy() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_1.5.6_u2204_amd64.deb", "apt"),
            Some("jammy".to_string())
        );
    }

    #[test]
    fn test_detect_codename_apt_u2604_maps_to_resolute() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_2.1.1_u2604_amd64.deb", "apt"),
            Some("resolute".to_string())
        );
    }

    #[test]
    fn test_detect_codename_apt_debian12_maps_to_bookworm() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_1.5.6_debian12_amd64.deb", "apt"),
            Some("bookworm".to_string())
        );
    }

    #[test]
    fn test_detect_codename_apt_debian13_maps_to_trixie() {
        assert_eq!(
            detect_codename_from_filename("linux-patch-api_1.5.6_debian13_amd64.deb", "apt"),
            Some("trixie".to_string())
        );
    }

    #[test]
    fn test_synced_package_struct() {
        let pkg = SyncedPackage {
            filename: "test.deb".to_string(),
            version: "v1.0.0".to_string(),
            distro: "apt".to_string(),
            distro_codename: Some("noble".to_string()),
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
