//! AES-256-GCM encryption for sensitive credentials.
//!
//! Two per-install keys are supported:
//! - `KEY_PATH` (health-check.key) protects HTTP basic auth passwords for health check endpoints.
//! - `SECRET_ENCRYPTION_KEY_PATH` (secret-encryption.key) protects OIDC `client_secret`,
//!   SMTP `smtp_password`, and TOTP `totp_secret` at rest in the database.
//!
//! Keys are 32-byte files, auto-generated on first start with 0600 permissions.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use std::fs;
use std::path::Path;

pub const KEY_PATH: &str = "/etc/patch-manager/keys/health-check.key";

/// Path to the encryption key for sensitive app secrets
/// (OIDC client_secret, SMTP password, TOTP secret).
/// Separate from `KEY_PATH` (health-check credentials) for blast-radius isolation:
/// if the health-check key is compromised, app secrets remain protected.
pub const SECRET_ENCRYPTION_KEY_PATH: &str = "/etc/patch-manager/keys/secret-encryption.key";

/// Load or create the per-install encryption key.
/// If the key file doesn't exist, generates a new 256-bit key and saves it.
pub fn load_or_create_key(path: &Path) -> Result<[u8; 32], CryptoError> {
    if path.exists() {
        let key_bytes = fs::read(path).map_err(CryptoError::Io)?;
        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(key_bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    } else {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(CryptoError::Io)?;
        }
        fs::write(path, key).map_err(CryptoError::Io)?;
        // Set permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(CryptoError::Io)?;
        }
        Ok(key)
    }
}

/// Encrypt plaintext with AES-256-GCM. Returns (ciphertext, nonce).
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::KeyInit(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decrypt AES-256-GCM ciphertext with the given nonce.
pub fn decrypt(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::KeyInit(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    String::from_utf8(plaintext).map_err(CryptoError::Utf8)
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("Key init error: {0}")]
    KeyInit(String),
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Create a unique temp directory for test isolation.
    /// Returns a path like `/tmp/pm-crypto-test-<epoch_nanos>-<rand>`.
    /// Cleans up the directory on test teardown (via `temp_dir` guard).
    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = env::temp_dir().join(format!("pm-crypto-test-{}-{}", std::process::id(), nanos));
        fs::create_dir_all(&dir).expect("Failed to create temp dir");
        dir
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [42u8; 32];
        let plaintext = "super-secret-client-credential-12345";
        let (ciphertext, nonce) = encrypt(plaintext, &key).expect("encrypt failed");
        // Ciphertext must differ from plaintext (encryption is non-trivial)
        assert_ne!(ciphertext.as_slice(), plaintext.as_bytes());
        // Nonce is 12 bytes (AES-GCM standard)
        assert_eq!(nonce.len(), 12);
        // Decrypting must return the original plaintext
        let recovered = decrypt(&ciphertext, &nonce, &key).expect("decrypt failed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn load_or_create_key_sets_0600_permissions() {
        let dir = unique_temp_dir();
        let key_path = dir.join("test-0600.key");
        let _key = load_or_create_key(&key_path).expect("load_or_create_key failed");
        // Verify file exists and has exactly 32 bytes
        let metadata = fs::metadata(&key_path).expect("key file not created");
        assert_eq!(metadata.len(), 32, "key file must be 32 bytes");
        // On Unix, verify permissions are 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be 0600, got {:o}", mode);
        }
        // Cleanup
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn load_or_create_key_is_idempotent() {
        let dir = unique_temp_dir();
        let key_path = dir.join("test-idempotent.key");
        // First call creates the key
        let key1 = load_or_create_key(&key_path).expect("first call failed");
        // Second call should return the same key (not regenerate)
        let key2 = load_or_create_key(&key_path).expect("second call failed");
        assert_eq!(key1, key2, "second call must return the same key");
        // Cleanup
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_dir(&dir);
    }
}
