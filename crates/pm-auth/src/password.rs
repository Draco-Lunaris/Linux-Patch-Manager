//! Password hashing and verification using Argon2id.
//!
//! Parameters (calibrated per OWASP recommendations):
//! - Algorithm: Argon2id
//! - Memory cost: 65536 KiB (64 MiB)
//! - Time cost: 3 iterations
//! - Parallelism: 1

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use thiserror::Error;

/// Argon2id parameters per spec.
const M_COST: u32 = 65536; // 64 MiB
const T_COST: u32 = 3; // 3 iterations
const P_COST: u32 = 1; // 1 thread

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Failed to hash password: {0}")]
    HashError(String),
    #[error("Failed to verify password: {0}")]
    VerifyError(String),
    #[error("Invalid password hash format")]
    InvalidHash,
}

/// Build an Argon2id instance with calibrated parameters.
fn argon2() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(M_COST, T_COST, P_COST, None)
        .map_err(|e| PasswordError::HashError(e.to_string()))?;
    Ok(Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    ))
}

/// Hash a plaintext password using Argon2id with a random salt.
///
/// Returns the PHC string format hash suitable for storage.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = argon2()?;

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordError::HashError(e.to_string()))?;

    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored Argon2id PHC hash.
///
/// Returns `Ok(true)` if the password matches, `Ok(false)` if not.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHash)?;

    let argon2 = argon2()?;

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::VerifyError(e.to_string())),
    }
}

/// Validate password strength against minimum requirements.
///
/// Requirements:
/// - Minimum 8 characters
/// - At least one uppercase letter
/// - At least one lowercase letter
/// - At least one digit
/// - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("Password must contain at least one uppercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err("Password must contain at least one lowercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".to_string());
    }
    let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    if !password.chars().any(|c| special_chars.contains(c)) {
        return Err(
            "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let password = "super-secret-password-123!";
        let hash = hash_password(password).unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(password, &hash).unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn different_salts_produce_different_hashes() {
        let hash1 = hash_password("same-password").unwrap();
        let hash2 = hash_password("same-password").unwrap();
        assert_ne!(hash1, hash2); // different salts
    }
}
