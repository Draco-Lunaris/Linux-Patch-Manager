//! Secret-encryption key loader for pm-worker.
//!
//! Lazily loads the per-install AES-256-GCM key from
//! `/etc/patch-manager/keys/secret-encryption.key` on first use, caches it
//! in process memory, and returns a `&'static [u8; 32]` for all subsequent calls.
//!
//! The pm-worker crate uses the same key file as pm-web (filesystem-shared).
//! See `tasks/secret-encryption-spec.md` section 4.4 for the design rationale.

use pm_core::crypto;
use std::path::Path;
use std::sync::OnceLock;

static SECRET_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Load the secret-encryption key at first call. Subsequent calls return the cached value.
/// Returns `CryptoError` if the key file is missing or invalid.
///
/// Auto-generates the key file on first start (with 0600 permissions) if it doesn't exist.
#[allow(dead_code)]
pub fn get() -> Result<&'static [u8; 32], crypto::CryptoError> {
    if let Some(key) = SECRET_KEY.get() {
        return Ok(key);
    }
    let key = crypto::load_or_create_key(Path::new(crypto::SECRET_ENCRYPTION_KEY_PATH))?;
    // _ = ignore error if another thread won the race (already set by them)
    let _ = SECRET_KEY.set(key);
    Ok(SECRET_KEY.get().expect("key was just set"))
}
