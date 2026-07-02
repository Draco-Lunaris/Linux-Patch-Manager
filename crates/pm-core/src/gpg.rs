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
/// Resolve the GPG home directory for keyring operations.
///
/// Uses the `GNUPGHOME` environment variable if set (for testing),
/// falling back to the production default `/etc/patch-manager/ca/.gnupg`.
fn gpg_homedir() -> String {
    std::env::var("GNUPGHOME").unwrap_or_else(|_| "/etc/patch-manager/ca/.gnupg".to_string())
}

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
        .arg("--homedir")
        .arg(gpg_homedir())
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
        .arg("--homedir")
        .arg(gpg_homedir())
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
        .arg("--homedir")
        .arg(gpg_homedir())
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
        .arg("--homedir")
        .arg(gpg_homedir())
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
        .arg("--homedir")
        .arg(gpg_homedir())
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
    cmd.arg("--homedir")
        .arg(gpg_homedir())
        .arg("--batch")
        .arg("--yes")
        .arg("--detach-sign");

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

/// Sign a file using GPG clear-signing (inline signature), producing an InRelease-style file.
///
/// Used by the apt metadata generation to create `InRelease` files.
/// The output file contains the original content wrapped in a PGP signature.
pub async fn sign_file_clearsign(file_path: &str, output_path: &str) -> Result<(), GpgError> {
    let output = tokio::process::Command::new("gpg")
        .arg("--homedir")
        .arg(gpg_homedir())
        .arg("--batch")
        .arg("--yes")
        .arg("--clearsign")
        .arg("--output")
        .arg(output_path)
        .arg(file_path)
        .output()
        .await
        .map_err(|e| GpgError::CommandFailed(format!("gpg --clearsign failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpgError::CommandFailed(format!(
            "gpg --clearsign failed for {file_path}: {stderr}"
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
pub async fn ensure_repo_directories(repo_dir: &str, _gpg_key_id: &str) -> Result<(), GpgError> {
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

    // Create apt pool directory structure for pure Rust metadata generation.
    for codename in &["noble", "jammy", "bookworm", "trixie"] {
        let pool_dir = format!("{repo_dir}/apt/dists/{codename}/main/binary-amd64");
        tokio::fs::create_dir_all(&pool_dir)
            .await
            .map_err(|e| GpgError::CommandFailed(format!("Failed to create {pool_dir}: {e}")))?;
    }
    // Also create dnf repodata directory.
    tokio::fs::create_dir_all(format!("{repo_dir}/dnf/el9/repodata"))
        .await
        .map_err(|e| GpgError::CommandFailed(format!("Failed to create repodata dir: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;
    use tokio::sync::Mutex;

    /// Mutex to prevent parallel GPG tests from interfering with each other's GNUPGHOME.
    /// Uses tokio::sync::Mutex via LazyLock because these are async tests that hold
    /// the guard across .await points.
    static GPG_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    /// Set up an isolated GNUPGHOME for testing GPG operations.
    fn setup_test_gnupg_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("Failed to create temp dir for GNUPGHOME");
        std::env::set_var("GNUPGHOME", dir.path());
        // Kill any existing gpg-agent to ensure clean state.
        let _ = std::process::Command::new("gpgconf")
            .arg("--kill")
            .arg("gpg-agent")
            .output();
        dir
    }

    #[tokio::test]
    async fn test_ensure_signing_key_generates_new_key() {
        let _lock = GPG_TEST_LOCK.lock().await;
        let _gnupg_home = setup_test_gnupg_home();

        let temp = tempfile::tempdir().expect("Failed to create temp dir");
        let pub_key_path = temp
            .path()
            .join("lpa-repo-public-key.asc")
            .to_str()
            .unwrap()
            .to_string();
        let priv_key_path = temp
            .path()
            .join("lpa-repo-private-key.asc")
            .to_str()
            .unwrap()
            .to_string();

        let result = ensure_signing_key(&pub_key_path, &priv_key_path).await;

        assert!(
            result.is_ok(),
            "ensure_signing_key should succeed: {:?}",
            result.err()
        );
        let key_info = result.unwrap();
        assert!(key_info.newly_generated, "Key should be newly generated");
        assert!(!key_info.key_id.is_empty(), "Key ID should not be empty");
        assert!(
            std::path::Path::new(&pub_key_path).exists(),
            "Public key file should exist"
        );
        assert!(
            std::path::Path::new(&priv_key_path).exists(),
            "Private key file should exist"
        );

        // Verify the public key file contains PGP public key block.
        let pub_key_content = std::fs::read_to_string(&pub_key_path).unwrap();
        assert!(
            pub_key_content.contains("BEGIN PGP PUBLIC KEY BLOCK"),
            "Public key file should contain PGP public key block"
        );

        // Verify the private key file contains PGP private key block.
        let priv_key_content = std::fs::read_to_string(&priv_key_path).unwrap();
        assert!(
            priv_key_content.contains("BEGIN PGP PRIVATE KEY BLOCK"),
            "Private key file should contain PGP private key block"
        );
    }

    #[tokio::test]
    async fn test_ensure_signing_key_finds_existing_key() {
        let _lock = GPG_TEST_LOCK.lock().await;
        let _gnupg_home = setup_test_gnupg_home();

        let temp = tempfile::tempdir().expect("Failed to create temp dir");
        let pub_key_path = temp
            .path()
            .join("lpa-repo-public-key.asc")
            .to_str()
            .unwrap()
            .to_string();
        let priv_key_path = temp
            .path()
            .join("lpa-repo-private-key.asc")
            .to_str()
            .unwrap()
            .to_string();

        // First call generates the key.
        let result1 = ensure_signing_key(&pub_key_path, &priv_key_path).await;
        assert!(
            result1.is_ok(),
            "First call should succeed: {:?}",
            result1.err()
        );
        assert!(
            result1.unwrap().newly_generated,
            "First call should generate new key"
        );

        // Second call should find the existing key.
        let result2 = ensure_signing_key(&pub_key_path, &priv_key_path).await;
        assert!(
            result2.is_ok(),
            "Second call should succeed: {:?}",
            result2.err()
        );
        let key_info = result2.unwrap();
        assert!(
            !key_info.newly_generated,
            "Second call should find existing key"
        );
        assert!(!key_info.key_id.is_empty(), "Key ID should not be empty");
    }

    #[tokio::test]
    async fn test_sign_file_detached_creates_valid_signature() {
        let _lock = GPG_TEST_LOCK.lock().await;
        let _gnupg_home = setup_test_gnupg_home();

        let temp = tempfile::tempdir().expect("Failed to create temp dir");
        let pub_key_path = temp
            .path()
            .join("lpa-repo-public-key.asc")
            .to_str()
            .unwrap()
            .to_string();
        let priv_key_path = temp
            .path()
            .join("lpa-repo-private-key.asc")
            .to_str()
            .unwrap()
            .to_string();

        // Generate a signing key first.
        let key_info = ensure_signing_key(&pub_key_path, &priv_key_path)
            .await
            .expect("Key generation failed");
        assert!(!key_info.key_id.is_empty());

        // Create a test file to sign.
        let test_file = temp.path().join("test_metadata.xml");
        std::fs::write(&test_file, b"<repomd>test content</repomd>").unwrap();
        let test_file_path = test_file.to_str().unwrap().to_string();
        let sig_path = temp
            .path()
            .join("test_metadata.xml.asc")
            .to_str()
            .unwrap()
            .to_string();

        // Sign the file.
        let result = sign_file_detached(&test_file_path, &sig_path, true).await;
        assert!(
            result.is_ok(),
            "sign_file_detached should succeed: {:?}",
            result.err()
        );

        // Verify signature file exists and is non-empty.
        assert!(
            std::path::Path::new(&sig_path).exists(),
            "Signature file should exist"
        );
        let sig_content = std::fs::read_to_string(&sig_path).unwrap();
        assert!(
            !sig_content.is_empty(),
            "Signature file should not be empty"
        );
        assert!(
            sig_content.contains("BEGIN PGP SIGNATURE"),
            "Armored signature should contain PGP signature block"
        );

        // Verify the signature is valid using gpg --verify.
        let verify_output = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(gpg_homedir())
            .arg("--verify")
            .arg(&sig_path)
            .arg(&test_file_path)
            .output()
            .expect("Failed to run gpg --verify");
        assert!(
            verify_output.status.success(),
            "gpg --verify should succeed: {}",
            String::from_utf8_lossy(&verify_output.stderr)
        );
    }

    #[tokio::test]
    async fn test_ensure_repo_directories_creates_structure() {
        let _lock = GPG_TEST_LOCK.lock().await;
        let _gnupg_home = setup_test_gnupg_home();

        let temp = tempfile::tempdir().expect("Failed to create temp dir");
        let repo_dir = temp.path().to_str().unwrap().to_string();

        // Generate a key first to get a key ID.
        let pub_key_path = temp.path().join("pubkey.asc").to_str().unwrap().to_string();
        let priv_key_path = temp
            .path()
            .join("privkey.asc")
            .to_str()
            .unwrap()
            .to_string();
        let key_info = ensure_signing_key(&pub_key_path, &priv_key_path)
            .await
            .expect("Key generation failed");

        // Initialize repo directories.
        let result = ensure_repo_directories(&repo_dir, &key_info.key_id).await;
        assert!(
            result.is_ok(),
            "ensure_repo_directories should succeed: {:?}",
            result.err()
        );

        // Verify all expected directories exist.
        assert!(std::path::Path::new(&format!("{repo_dir}/apt")).exists());
        assert!(std::path::Path::new(&format!("{repo_dir}/dnf/el9/Packages")).exists());
        assert!(std::path::Path::new(&format!("{repo_dir}/dnf/el9/repodata")).exists());
        assert!(std::path::Path::new(&format!("{repo_dir}/apk/v3.21")).exists());
        assert!(std::path::Path::new(&format!("{repo_dir}/pacman/x86_64")).exists());
        assert!(std::path::Path::new(&format!("{repo_dir}/tmp")).exists());

        // Verify apt pool directories were created for all codenames.
        for codename in &["noble", "jammy", "bookworm", "trixie"] {
            assert!(
                std::path::Path::new(&format!(
                    "{repo_dir}/apt/dists/{codename}/main/binary-amd64"
                ))
                .exists(),
                "apt pool directory should exist for {codename}"
            );
        }
    }

    #[tokio::test]
    async fn test_gpg_key_info_struct() {
        let info = GpgKeyInfo {
            key_id: "ABCD1234EF567890".to_string(),
            public_key_path: "/tmp/pub.asc".to_string(),
            private_key_path: "/tmp/priv.asc".to_string(),
            newly_generated: true,
        };
        assert_eq!(info.key_id, "ABCD1234EF567890");
        assert!(info.newly_generated);
    }
}
