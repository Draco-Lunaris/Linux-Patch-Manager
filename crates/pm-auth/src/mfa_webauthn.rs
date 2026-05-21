//! WebAuthn (FIDO2) MFA stub.
//!
//! Full implementation planned for M2 extension or M3.
//! WebAuthn requires stateful registration/authentication ceremonies
//! and a compatible client library (webauthn-rs).
//!
//! For M2, TOTP is the primary MFA method.
//! WebAuthn credentials are stored in the `users.webauthn_credential` JSONB
//! column and will be processed here when implemented.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("WebAuthn not yet implemented")]
    NotImplemented,
}

/// Placeholder for WebAuthn registration options.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationOptions {
    pub message: String,
}

/// Begin WebAuthn registration ceremony (stub).
pub fn begin_registration(_username: &str) -> Result<RegistrationOptions, WebAuthnError> {
    Err(WebAuthnError::NotImplemented)
}

/// Complete WebAuthn registration ceremony (stub).
pub fn complete_registration(
    _username: &str,
    _response: &serde_json::Value,
) -> Result<serde_json::Value, WebAuthnError> {
    Err(WebAuthnError::NotImplemented)
}

/// Begin WebAuthn authentication ceremony (stub).
pub fn begin_authentication(_username: &str) -> Result<serde_json::Value, WebAuthnError> {
    Err(WebAuthnError::NotImplemented)
}

/// Verify WebAuthn authentication response (stub).
pub fn verify_authentication(
    _username: &str,
    _credential: &serde_json::Value,
    _response: &serde_json::Value,
) -> Result<bool, WebAuthnError> {
    Err(WebAuthnError::NotImplemented)
}
