//! AES-256-GCM encryption for sensitive health check credentials.
//!
//! Uses a per-install key stored at `/etc/patch-manager/keys/health-check.key`.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use std::fs;
use std::path::Path;

pub const KEY_PATH: &str = "/etc/patch-manager/keys/health-check.key";

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
