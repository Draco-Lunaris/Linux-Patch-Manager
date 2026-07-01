//! GPG key management for the manager-hosted package repository.
//!
//! Each manager instance generates and manages its own unique GPG signing key.
//! The key is stored alongside the CA root/key in the manager's configuration
//! directory (e.g., `/etc/patch-manager/ca/`).
//!
//! On startup, `ensure_signing_key()` checks for an existing key and auto-generates
//! one if missing. The key is used to sign repo metadata (Release, repomd.xml,
//! APKINDEX.tar.gz, lpa-repo.db.tar.zst) — not individual packages.
//!
//! Added for issue #116 (M13/M16 gap fix).

use std::path::Path;

/// GPG key identity used for repo signing.
const GPG_KEY_NAME: &str = "Linux Patch API Repo";
const GPG_KEY_EMAIL: &str = "lpa-repo@localhost";
const GPG_KEY_EXPIRY: &str = "2y";

/// Result of GPG key bootstrap.
#[derive(Debug)]
pub struct GpgKeyInfo {
    /// The GPG key ID (e.g., "ABCD1234EF567890").
    pub key_id: String,
    /// Path to the ASCII-armored public key file.
    pub public_key_path: String,
    /// Path to the ASCII-armored private key file.
    pub private_key_path: String,
    /// Whether the key was newly generated (true) or already existed (false).
    pub newly_generated: bool,
}

/// Error type for GPG operations.
#[derive(Debug, thiserror::Error)]
pub enum GpgError {
    #[error("GPG command failed: {0}")]
    CommandFailed(String),
    #[error("Failed to parse GPG output: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Ensure a GPG signing key exists for the manager-hosted repo.
///
/// If the private key file already exists, reads the key ID from it.
/// If missing, generates a new RSA 4096 signing-only key with 2-year expiry,
/// exports public and private keys to the configured paths.
///
/// Returns key info including the key ID needed for reprepro SignWith config.
pub async fn ensure_signing_key(
    public_key_path: &str,
    private_key_path: &str,
) -> Result<GpgKeyInfo, GpgError> {
    // If private key already exists, read the key ID from it.
    if Path::new(private_key_path).exists() {
        tracing::info!(
            private_key_path,
            "GPG signing key already exists — skipping generation"
        );
        let key_id = extract_key_id_from_private_key(private_key_path).await?;
        return Ok(GpgKeyInfo {
            key_id,
            public_key_path: public_key_path.to_string(),
            private_key_path: private_key_path.to_string(),
            newly_generated: false,
        });
    }

    tracing::info!(
        public_key_path,
        private_key_path,
        "GPG signing key not found — generating new key"
    );

    // Ensure parent directory exists.
    if let Some(parent) = Path::new(private_key_path).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    // Generate the key via gpg --batch --gen-key.
    // We use --gen-key with stdin pipe to pass the key generation script.
    let gen_key_script = format!(
        "Key-Type: RSA\nKey-Length: 4096\nKey-Usage: sign\nName-Real: {name}\nName-Email: {email}\nExpire-Date: {expiry}\n%no-protection\n%commit\n",
        name = GPG_KEY_NAME,
        email = GPG_KEY_EMAIL,
        expiry = GPG_KEY_EXPIRY,
    );

    let mut child = tokio::process::Command::new("gpg")
        .arg("--batch")
        .arg("--gen-key")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| GpgError::CommandFailed(format!("Failed to spawn gpg --gen-key: {e}")))?;

    // Write the key generation script to stdin.
    if let Some(stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let mut stdin = stdin;
        stdin
            .write_all(gen_key_script.as_bytes())
            .await
            .map_err(|e| GpgError::CommandFailed(format!("Failed to write to gpg stdin: {e}")))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| GpgError::CommandFailed(format!("gpg --gen-key failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpgError::CommandFailed(format!(
            "gpg --gen-key failed: {stderr}"
        )));
    }

    tracing::info!(
        name = GPG_KEY_NAME,
        email = GPG_KEY_EMAIL,
        "GPG signing key generated successfully"
    );

    // Export the public key.
    export_public_key(GPG_KEY_EMAIL, public_key_path).await?;

    // Export the private key.
    export_private_key(GPG_KEY_EMAIL, private_key_path).await?;

    // Set restrictive permissions on the private key.
    let _ = tokio::process::Command::new("chmod")
        .arg("0600")
        .arg(private_key_path)
        .output()
        .await;

    // Get the key ID.
    let key_id = get_key_id(GPG_KEY_EMAIL).await?;

    tracing::info!(
        key_id = %key_id,
        public_key_path,
        private_key_path,
        "GPG key bootstrap complete"
    );

    Ok(GpgKeyInfo {
        key_id,
        public_key_path: public_key_path.to_string(),
        private_key_path: private_key_path.to_string(),
        newly_generated: true,
    })
}

/// Export the public key to a file (ASCII-armored).
async fn export_public_key(email: &str, path: &str) -> Result<(), GpgError> {
    let output = tokio::process::Command::new("gpg")
        .arg("--armor")
        .arg("--export")
        .arg(email)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| GpgError::CommandFailed(format!("gpg --export failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpgError::CommandFailed(format!(
            "gpg --export failed: {stderr}"
        )));
    }

    tokio::fs::write(path, &output.stdout)
        .await
        .map_err(|e| GpgError::CommandFailed(format!("Failed to write public key: {e}")))?;

    tracing::info!(path, "GPG public key exported");
    Ok(())
}

/// Export the private key to a file (ASCII-armored).
async fn export_private_key(email: &str, path: &str) -> Result<(), GpgError> {
    let output = tokio::process::Command::new("gpg")
        .arg("--armor")
        .arg("--export-secret-keys")
        .arg(email)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| GpgError::CommandFailed(format!("gpg --export-secret-keys failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpgError::CommandFailed(format!(
            "gpg --export-secret-keys failed: {stderr}"
        )));
    }

    tokio::fs::write(path, &output.stdout)
        .await
        .map_err(|e| GpgError::CommandFailed(format!("Failed to write private key: {e}")))?;

    tracing::info!(path, "GPG private key exported");
    Ok(())
}

/// Get the key ID for a given email from the GPG keyring.
async fn get_key_id(email: &str) -> Result<String, GpgError> {
    let output = tokio::process::Command::new("gpg")
        .arg("--list-keys")
        .arg("--with-colons")
        .arg(email)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| GpgError::CommandFailed(format!("gpg --list-keys failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpgError::CommandFailed(format!(
            "gpg --list-keys failed: {stderr}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse colon-separated output. Look for "pub" line, key ID is in field 4 (short ID)
    // or field 5 (fingerprint). We want the short key ID (last 16 chars of fingerprint).
    for line in stdout.lines() {
        if line.starts_with("pub:") {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 5 {
                let fingerprint = fields[4];
                // Short key ID = last 16 chars of fingerprint.
                let key_id = if fingerprint.len() >= 16 {
                    fingerprint[fingerprint.len() - 16..].to_string()
                } else {
                    fingerprint.to_string()
                };
                return Ok(key_id);
            }
        }
    }

    Err(GpgError::ParseError(format!(
        "Could not find key ID for {email} in gpg output"
    )))
}

/// Extract the key ID from an existing private key file.
/// Imports the key into the keyring (if not already present) and reads the ID.
async fn extract_key_id_from_private_key(private_key_path: &str) -> Result<String, GpgError> {
    // Import the private key into the keyring (idempotent — gpg handles duplicates).
    let _ = tokio::process::Command::new("gpg")
        .arg("--batch")
        .arg("--import")
        .arg(private_key_path)
        .output()
        .await;

    // Now get the key ID by email.
    get_key_id(GPG_KEY_EMAIL).await
}

/// Sign a file with a detached signature using the manager's GPG key.
///
/// Used by the package sync worker to sign repo metadata files:
/// - repomd.xml (dnf)
/// - APKINDEX.tar.gz (apk)
/// - lpa-repo.db.tar.zst (pacman)
///
/// For apt, reprepro handles signing via SignWith config — this function is not needed.
pub async fn sign_file_detached(
    file_path: &str,
    signature_path: &str,
    armor: bool,
) -> Result<(), GpgError> {
    let mut cmd = tokio::process::Command::new("gpg");
    cmd.arg("--batch").arg("--yes").arg("--detach-sign");

    if armor {
        cmd.arg("--armor");
    }

    cmd.arg("--output").arg(signature_path).arg(file_path);

    let output = cmd
        .output()
        .await
        .map_err(|e| GpgError::CommandFailed(format!("gpg --detach-sign failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpgError::CommandFailed(format!(
            "gpg --detach-sign failed for {file_path}: {stderr}"
        )));
    }

    Ok(())
}

/// Ensure the manager-hosted package repository directory structure exists.
///
/// Creates base directories for all four distro formats and generates the
/// reprepro `conf/distributions` file with `SignWith <key-id>` for apt.
///
/// This must be called after `ensure_signing_key()` so the key ID is available.
pub async fn ensure_repo_directories(repo_dir: &str, gpg_key_id: &str) -> Result<(), GpgError> {
    // Base directories.
    let dirs = [
        format!("{repo_dir}/apt"),
        format!("{repo_dir}/dnf"),
        format!("{repo_dir}/dnf/el9/Packages"),
        format!("{repo_dir}/apk"),
        format!("{repo_dir}/apk/v3.21"),
        format!("{repo_dir}/pacman"),
        format!("{repo_dir}/pacman/x86_64"),
        format!("{repo_dir}/tmp"),
    ];

    for dir in &dirs {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| GpgError::CommandFailed(format!("Failed to create {dir}: {e}")))?;
    }

    tracing::info!(repo_dir, "Package repo directory structure initialized");

    // Create reprepro conf/distributions with SignWith for apt auto-signing.
    let conf_dir = format!("{repo_dir}/apt/conf");
    tokio::fs::create_dir_all(&conf_dir)
        .await
        .map_err(|e| GpgError::CommandFailed(format!("Failed to create {conf_dir}: {e}")))?;

    let distributions_path = format!("{conf_dir}/distributions");
    if !Path::new(&distributions_path).exists() {
        let distributions_content = generate_reprepro_distributions(gpg_key_id);
        tokio::fs::write(&distributions_path, &distributions_content)
            .await
            .map_err(|e| GpgError::CommandFailed(format!("Failed to write distributions: {e}")))?;
        tracing::info!(
            path = %distributions_path,
            key_id = gpg_key_id,
            "reprepro conf/distributions created with SignWith"
        );
    } else {
        // Verify SignWith is present; add if missing.
        let existing = tokio::fs::read_to_string(&distributions_path)
            .await
            .unwrap_or_default();
        if !existing.contains("SignWith") && !gpg_key_id.is_empty() {
            let updated = generate_reprepro_distributions(gpg_key_id);
            tokio::fs::write(&distributions_path, &updated)
                .await
                .map_err(|e| {
                    GpgError::CommandFailed(format!("Failed to update distributions: {e}"))
                })?;
            tracing::info!(
                path = %distributions_path,
                key_id = gpg_key_id,
                "reprepro conf/distributions updated with SignWith"
            );
        } else {
            tracing::debug!(path = %distributions_path, "reprepro conf/distributions already configured");
        }
    }

    Ok(())
}

/// Generate reprepro conf/distributions content with SignWith for all supported codenames.
fn generate_reprepro_distributions(gpg_key_id: &str) -> String {
    let codenames = ["noble", "jammy", "bookworm", "trixie"];
    let mut content = String::new();

    for codename in &codenames {
        content.push_str(&format!(
            "Origin: Linux Patch API\n\
             Label: Linux Patch API Repo\n\
             Suite: {codename}\n\
             Codename: {codename}\n\
             Architectures: amd64\n\
             Components: main\n\
             Description: Linux Patch API agent packages for Ubuntu/Debian {codename}\n\
             SignWith: {key_id}\n\n",
            codename = codename,
            key_id = gpg_key_id,
        ));
    }

    content
}
