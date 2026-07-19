//! RSA key management for the Alpine apk repository index signing.
//!
//! Alpine's `apk` package manager uses RSA keys (not GPG) to verify the
//! repository index (`APKINDEX.tar.gz`). Each manager instance generates
//! and manages its own RSA keypair, stored alongside the CA material and
//! the GPG signing key in the manager's configuration directory
//! (e.g., `/etc/patch-manager/ca/`).
//!
//! On startup, `ensure_rsa_keypair()` checks for an existing key and
//! auto-generates one if missing. The private key is used to sign
//! `APKINDEX.tar.gz` with a raw detached RSA-SHA256 signature (the format
//! `apk` expects — equivalent to `openssl dgst -sha256 -sign <key>`).
//! The public key is delivered to Alpine agents during enrollment so they
//! can write it to `/etc/apk/keys/lpa-repo.rsa.pub` and verify the index.
//!
//! Added for issue #170 (Alpine apk RSA signing).

use std::path::Path;

use pem::Pem;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

/// RSA key size in bits. 2048 is the minimum recommended for modern security
/// and matches what `abuild-keygen` generates for Alpine package signing.
const RSA_KEY_BITS: usize = 2048;

/// PEM tag for the RSA private key (PKCS#8).
const PRIVATE_KEY_PEM_TAG: &str = "PRIVATE KEY";
/// PEM tag for the RSA public key (PKCS#8 SubjectPublicKeyInfo).
const PUBLIC_KEY_PEM_TAG: &str = "PUBLIC KEY";

/// Result of RSA keypair bootstrap.
#[derive(Debug)]
pub struct RsaKeyInfo {
    /// Path to the PEM-encoded public key file.
    pub public_key_path: String,
    /// Path to the PEM-encoded private key file.
    pub private_key_path: String,
    /// Whether the keypair was newly generated (true) or already existed (false).
    pub newly_generated: bool,
}

/// Error type for RSA operations.
#[derive(Debug, thiserror::Error)]
pub enum RsaError {
    #[error("RSA command failed: {0}")]
    CommandFailed(String),
    #[error("RSA key error: {0}")]
    KeyError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("PEM encode/decode error: {0}")]
    PemError(String),
    #[error("RSA signing error: {0}")]
    SignError(String),
}

impl From<rsa::Error> for RsaError {
    fn from(e: rsa::Error) -> Self {
        RsaError::KeyError(e.to_string())
    }
}

impl From<rsa::pkcs1::Error> for RsaError {
    fn from(e: rsa::pkcs1::Error) -> Self {
        RsaError::KeyError(e.to_string())
    }
}

impl From<rsa::pkcs8::Error> for RsaError {
    fn from(e: rsa::pkcs8::Error) -> Self {
        RsaError::KeyError(e.to_string())
    }
}

impl From<rsa::pkcs8::spki::Error> for RsaError {
    fn from(e: rsa::pkcs8::spki::Error) -> Self {
        RsaError::KeyError(e.to_string())
    }
}

/// Ensure an RSA keypair exists for Alpine apk repo index signing.
///
/// If both the public and private key files already exist, reads them and
/// returns `newly_generated: false`. If either is missing, generates a new
/// 2048-bit RSA keypair, exports the private key as PKCS#8 PEM and the
/// public key as SubjectPublicKeyInfo PEM to the configured paths.
///
/// The private key file is created with 0600 permissions on Unix.
pub fn ensure_rsa_keypair(
    public_key_path: &str,
    private_key_path: &str,
) -> Result<RsaKeyInfo, RsaError> {
    let pub_exists = Path::new(public_key_path).exists();
    let priv_exists = Path::new(private_key_path).exists();

    if pub_exists && priv_exists {
        tracing::info!(
            public_key_path,
            private_key_path,
            "Existing RSA keypair found — reusing for Alpine apk signing"
        );
        return Ok(RsaKeyInfo {
            public_key_path: public_key_path.to_string(),
            private_key_path: private_key_path.to_string(),
            newly_generated: false,
        });
    }

    tracing::info!(
        public_key_path,
        private_key_path,
        "Generating new RSA-{} keypair for Alpine apk signing",
        RSA_KEY_BITS
    );

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).map_err(RsaError::from)?;

    // Export private key as PKCS#8 PEM.
    let priv_pem_der = private_key.to_pkcs8_der().map_err(RsaError::from)?;
    let priv_pem_string = pem::encode(&Pem::new(
        PRIVATE_KEY_PEM_TAG,
        priv_pem_der.as_bytes().to_vec(),
    ));

    // Export public key as SubjectPublicKeyInfo PEM.
    let public_key = RsaPublicKey::from(&private_key);
    let pub_pem_string = pem::encode(&Pem::new(
        PUBLIC_KEY_PEM_TAG,
        public_key
            .to_public_key_der()
            .map_err(RsaError::from)?
            .as_bytes()
            .to_vec(),
    ));

    // Write private key with restrictive permissions (atomic: temp + rename).
    write_private_key(private_key_path, priv_pem_string.as_bytes())?;
    // Write public key (0644 — world-readable is fine, it's a public key).
    write_public_key(public_key_path, pub_pem_string.as_bytes())?;

    tracing::info!(
        public_key_path,
        private_key_path,
        "RSA keypair generated and written for Alpine apk signing"
    );

    Ok(RsaKeyInfo {
        public_key_path: public_key_path.to_string(),
        private_key_path: private_key_path.to_string(),
        newly_generated: true,
    })
}

/// Load an RSA private key from a PEM file (PKCS#8 or PKCS#1).
pub fn load_private_key(path: &str) -> Result<RsaPrivateKey, RsaError> {
    let pem_contents = std::fs::read_to_string(path)?;
    // Try PKCS#8 first, then PKCS#1.
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(&pem_contents) {
        return Ok(key);
    }
    RsaPrivateKey::from_pkcs1_pem(&pem_contents).map_err(RsaError::from)
}

/// Load an RSA public key from a PEM file (SubjectPublicKeyInfo).
pub fn load_public_key(path: &str) -> Result<RsaPublicKey, RsaError> {
    let pem_contents = std::fs::read_to_string(path)?;
    RsaPublicKey::from_public_key_pem(&pem_contents).map_err(RsaError::from)
}

/// Sign a file with a detached RSA-SHA256 signature.
///
/// Produces the raw RSA signature bytes (equivalent to
/// `openssl dgst -sha256 -sign <key> -out <sig> <file>`), which is the
/// format Alpine's `apk` expects for `APKINDEX.tar.gz.sig`.
///
/// The signature is written to `signature_path`.
pub fn sign_file_detached(
    file_path: &str,
    signature_path: &str,
    private_key_path: &str,
) -> Result<(), RsaError> {
    let private_key = load_private_key(private_key_path)?;
    let data = std::fs::read(file_path)?;

    // RSA-PSS is not used by apk; apk expects PKCS#1 v1.5 with SHA-256.
    // Use SigningKey<Sha256> (rsa crate's PKCS#1 v1.5 signing path).
    use rsa::pkcs1v15::SigningKey;
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(&data);

    // Atomic write: temp file + rename.
    let tmp_path = format!("{signature_path}.tmp");
    let sig_bytes = signature.to_bytes();
    std::fs::write(&tmp_path, &sig_bytes)?;
    std::fs::rename(&tmp_path, signature_path)?;
    Ok(())
}

/// Write the private key file with 0600 permissions (atomic: temp + rename).
fn write_private_key(path: &str, contents: &[u8]) -> Result<(), RsaError> {
    let tmp_path = format!("{path}.tmp");
    std::fs::write(&tmp_path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Write the public key file with 0644 permissions (atomic: temp + rename).
fn write_public_key(path: &str, contents: &[u8]) -> Result<(), RsaError> {
    let tmp_path = format!("{path}.tmp");
    std::fs::write(&tmp_path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ensure_rsa_keypair_generates_and_reuses() {
        let dir = tempdir().unwrap();
        let pub_path = dir.path().join("test-rsa.pub");
        let priv_path = dir.path().join("test-rsa.pem");
        let pub_str = pub_path.to_str().unwrap();
        let priv_str = priv_path.to_str().unwrap();

        // First call: generates.
        let info1 = ensure_rsa_keypair(pub_str, priv_str).unwrap();
        assert!(info1.newly_generated);
        assert!(pub_path.exists());
        assert!(priv_path.exists());

        // Second call: reuses.
        let info2 = ensure_rsa_keypair(pub_str, priv_str).unwrap();
        assert!(!info2.newly_generated);

        // Public key should be PEM-encoded.
        let pub_pem = std::fs::read_to_string(pub_str).unwrap();
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pub_pem.contains("-----END PUBLIC KEY-----"));

        // Private key should be PEM-encoded PKCS#8.
        let priv_pem = std::fs::read_to_string(priv_str).unwrap();
        assert!(priv_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(priv_pem.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let dir = tempdir().unwrap();
        let pub_path = dir.path().join("test-rsa.pub");
        let priv_path = dir.path().join("test-rsa.pem");
        ensure_rsa_keypair(pub_path.to_str().unwrap(), priv_path.to_str().unwrap()).unwrap();

        let data_path = dir.path().join("data.bin");
        let sig_path = dir.path().join("data.sig");
        std::fs::write(&data_path, b"hello apk index").unwrap();

        sign_file_detached(
            data_path.to_str().unwrap(),
            sig_path.to_str().unwrap(),
            priv_path.to_str().unwrap(),
        )
        .unwrap();

        // Signature file should exist and be non-empty.
        assert!(sig_path.exists());
        let sig = std::fs::read(&sig_path).unwrap();
        // 2048-bit RSA signature = 256 bytes.
        assert_eq!(sig.len(), 256);

        // Verify with the public key.
        let public_key = load_public_key(pub_path.to_str().unwrap()).unwrap();
        let data = std::fs::read(&data_path).unwrap();
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let signature = rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap();
        verifying_key
            .verify(&data, &signature)
            .expect("signature should verify");
    }

    #[test]
    fn test_load_private_key_handles_pkcs1_and_pkcs8() {
        use rsa::traits::PublicKeyParts;
        let dir = tempdir().unwrap();
        let pub_path = dir.path().join("test-rsa.pub");
        let priv_path = dir.path().join("test-rsa.pem");
        ensure_rsa_keypair(pub_path.to_str().unwrap(), priv_path.to_str().unwrap()).unwrap();

        // Should load as PKCS#8 (our default export format).
        let key = load_private_key(priv_path.to_str().unwrap()).unwrap();
        assert_eq!(key.n().bits(), RSA_KEY_BITS);
    }
}
