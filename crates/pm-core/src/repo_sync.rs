//! Shared package sync logic for the manager-hosted package repository.
//!
//! Both the scheduled worker (`pm-worker`) and the manual admin trigger
//! (`pm-web` routes) call these functions to avoid code duplication.
//!
//! Added for Phase 5 of issue #116 gap fix (consolidate sync logic).

use crate::config::PackageSyncConfig;
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

    // Ensure tmp directory exists.
    if let Some(parent) = std::path::Path::new(path).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
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
/// For apt, reprepro auto-signs Release/InRelease via SignWith config.
/// For dnf/apk/pacman, metadata is signed with detached GPG signatures
/// using `pm_core::gpg::sign_file_detached()`.
pub async fn import_to_repo(
    file_path: &str,
    distro: &str,
    codename: Option<&str>,
    repo_dir: &str,
) -> Result<(), anyhow::Error> {
    use crate::gpg;

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

            // Sign repomd.xml with detached GPG signature for dnf verification.
            let repomd_path = format!("{repo_dir}/dnf/el9/repodata/repomd.xml");
            let repomd_sig_path = format!("{repo_dir}/dnf/el9/repodata/repomd.xml.asc");
            if std::path::Path::new(&repomd_path).exists() {
                if let Err(e) = gpg::sign_file_detached(&repomd_path, &repomd_sig_path, true).await
                {
                    tracing::warn!(error = %e, "GPG sign repomd.xml failed (non-fatal but clients will not trust this repo)");
                }
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

            // Sign APKINDEX.tar.gz with detached GPG signature for apk verification.
            let apkindex_path = format!("{dest_dir}/APKINDEX.tar.gz");
            let apkindex_sig_path = format!("{dest_dir}/APKINDEX.tar.gz.sig");
            if std::path::Path::new(&apkindex_path).exists() {
                if let Err(e) =
                    gpg::sign_file_detached(&apkindex_path, &apkindex_sig_path, false).await
                {
                    tracing::warn!(error = %e, "GPG sign APKINDEX.tar.gz failed (non-fatal but clients will not trust this repo)");
                }
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

            // Sign lpa-repo.db.tar.zst with detached GPG signature for pacman verification.
            let db_path = format!("{dest_dir}/lpa-repo.db.tar.zst");
            let db_sig_path = format!("{dest_dir}/lpa-repo.db.tar.zst.sig");
            if std::path::Path::new(&db_path).exists() {
                if let Err(e) = gpg::sign_file_detached(&db_path, &db_sig_path, false).await {
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
/// Expected patterns: `*_noble_amd64.deb`, `*_jammy_amd64.deb`,
/// `*_bookworm_amd64.deb`, `*_trixie_amd64.deb`, `*_el9.x86_64.rpm`, etc.
pub fn detect_codename_from_filename(name: &str, distro: &str) -> Option<String> {
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
                        result.synced_packages.push(SyncedPackage {
                            filename: asset.name.clone(),
                            version: release.tag_name.clone(),
                            distro: distro.clone(),
                            distro_codename: codename.clone(),
                            file_size: asset.size as i64,
                            sha256: Some(sha256),
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
    fn test_synced_package_struct() {
        let pkg = SyncedPackage {
            filename: "test.deb".to_string(),
            version: "v1.0.0".to_string(),
            distro: "apt".to_string(),
            distro_codename: Some("noble".to_string()),
            file_size: 1024,
            sha256: Some("abc123".to_string()),
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
