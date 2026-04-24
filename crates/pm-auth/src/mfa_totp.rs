//! TOTP (Time-based One-Time Password) MFA implementation.
//!
//! Uses TOTP-rs with HMAC-SHA1, 6-digit codes, 30-second window.
//! Compatible with Google Authenticator, Authy, and standard TOTP apps.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};

/// TOTP issuer label shown in authenticator apps.
const ISSUER: &str = "Linux Patch Manager";

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("Failed to create TOTP: {0}")]
    Creation(String),
    #[error("Invalid TOTP secret")]
    InvalidSecret,
    #[error("TOTP code verification failed")]
    VerificationFailed,
}

/// TOTP setup response returned to the user during MFA enrollment.
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpSetup {
    /// Base32-encoded secret for manual entry in authenticator apps.
    pub secret_base32: String,
    /// OTP Auth URI for QR code generation (otpauth://totp/...).
    pub otp_uri: String,
}

/// Generate a new TOTP secret and return setup information.
///
/// The caller should store `secret_base32` in the database after
/// the user verifies the first code.
pub fn generate_setup(username: &str) -> Result<TotpSetup, TotpError> {
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();

    let totp = build_totp(username, &secret_base32)?;
    let otp_uri = totp.get_url();

    Ok(TotpSetup {
        secret_base32,
        otp_uri,
    })
}

/// Verify a TOTP code against the stored secret.
///
/// Accepts codes within a ±1 step window (±30 seconds) to handle clock skew.
pub fn verify_code(username: &str, secret_base32: &str, code: &str) -> Result<bool, TotpError> {
    let totp = build_totp(username, secret_base32)?;
    let valid = totp
        .check_current(code)
        .map_err(|_| TotpError::VerificationFailed)?;
    Ok(valid)
}

/// Build a TOTP instance from a base32 secret.
fn build_totp(username: &str, secret_base32: &str) -> Result<TOTP, TotpError> {
    let secret = Secret::Encoded(secret_base32.to_string());
    let secret_bytes = secret.to_bytes().map_err(|_| TotpError::InvalidSecret)?;

    // With the `otpauth` feature, TOTP::new signature is:
    // new(issuer, account_name, algorithm, digits, skew, step, secret)
    TOTP::new(
        Algorithm::SHA1,
        6,  // digits
        1,  // skew
        30, // step (seconds)
        secret_bytes,
        Some(ISSUER.to_string()),
        username.to_string(),
    )
    .map_err(|e| TotpError::Creation(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_setup_produces_valid_uri() {
        let setup = generate_setup("testuser").unwrap();
        assert!(!setup.secret_base32.is_empty());
        assert!(setup.otp_uri.starts_with("otpauth://totp/"));
    }

    #[test]
    fn verify_with_current_code() {
        let setup = generate_setup("testuser").unwrap();
        let totp = build_totp("testuser", &setup.secret_base32).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_code("testuser", &setup.secret_base32, &code).unwrap());
    }

    #[test]
    fn wrong_code_fails() {
        let setup = generate_setup("testuser").unwrap();
        assert!(!verify_code("testuser", &setup.secret_base32, "000000").unwrap());
    }
}
