//! JWT issuance and validation using EdDSA / Ed25519.
//!
//! - Access tokens: 15-minute TTL, signed with Ed25519 private key
//! - Key rotation: 90-day cycle with 24-hour overlap window
//! - The web process holds the signing key; worker holds only the public key

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// JWT algorithm — EdDSA with Ed25519 curve.
const JWT_ALGORITHM: Algorithm = Algorithm::EdDSA;

/// Default access token TTL in seconds.
pub const DEFAULT_ACCESS_TTL_SECS: i64 = 900; // 15 minutes

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Failed to encode JWT: {0}")]
    Encode(String),
    #[error("Failed to decode JWT: {0}")]
    Decode(String),
    #[error("Token is expired")]
    Expired,
    #[error("Token has invalid claims")]
    InvalidClaims,
    #[error("Failed to load signing key: {0}")]
    KeyLoad(String),
}

/// Standard JWT claims for access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Subject: user ID (UUID)
    pub sub: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiry (Unix timestamp)
    pub exp: i64,
    /// JWT ID (unique per token)
    pub jti: String,
    /// User role: "admin" or "operator"
    pub role: String,
    /// Username (for display / logging)
    pub username: String,
}

impl AccessClaims {
    /// Create new claims for the given user.
    pub fn new(user_id: Uuid, username: &str, role: &str, ttl_secs: i64) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(ttl_secs)).timestamp(),
            jti: Uuid::new_v4().to_string(),
            role: role.to_string(),
            username: username.to_string(),
        }
    }

    /// Check if the token is expired (redundant with validation but useful for explicit checks).
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Return the user UUID parsed from the `sub` field.
    pub fn user_id(&self) -> Result<Uuid, JwtError> {
        Uuid::parse_str(&self.sub).map_err(|_| JwtError::InvalidClaims)
    }
}

/// Issue an access token signed with the Ed25519 private key PEM.
pub fn issue_access_token(
    user_id: Uuid,
    username: &str,
    role: &str,
    ttl_secs: i64,
    signing_key_pem: &str,
) -> Result<String, JwtError> {
    let claims = AccessClaims::new(user_id, username, role, ttl_secs);

    let key = EncodingKey::from_ed_pem(signing_key_pem.as_bytes())
        .map_err(|e| JwtError::KeyLoad(e.to_string()))?;

    let header = Header::new(JWT_ALGORITHM);

    encode(&header, &claims, &key).map_err(|e| JwtError::Encode(e.to_string()))
}

/// Validate and decode an access token using the Ed25519 public key PEM.
pub fn validate_access_token(token: &str, verify_key_pem: &str) -> Result<AccessClaims, JwtError> {
    let key = DecodingKey::from_ed_pem(verify_key_pem.as_bytes())
        .map_err(|e| JwtError::KeyLoad(e.to_string()))?;

    let mut validation = Validation::new(JWT_ALGORITHM);
    validation.validate_exp = true;
    validation.leeway = 5; // 5-second clock skew tolerance

    decode::<AccessClaims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                JwtError::Expired
            } else {
                JwtError::Decode(e.to_string())
            }
        })
}

/// Load the Ed25519 signing key from a PEM file path.
pub fn load_signing_key(path: &str) -> Result<String, JwtError> {
    std::fs::read_to_string(path).map_err(|e| JwtError::KeyLoad(format!("Cannot read {path}: {e}")))
}

/// Load the Ed25519 verification (public) key from a PEM file path.
pub fn load_verify_key(path: &str) -> Result<String, JwtError> {
    std::fs::read_to_string(path).map_err(|e| JwtError::KeyLoad(format!("Cannot read {path}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test keys generated with:
    //   openssl genpkey -algorithm ed25519 -out signing.pem
    //   openssl pkey -in signing.pem -pubout -out verify.pem
    const TEST_SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHNzPc3LkpODUVFr8GjVPm4M2yiKrXsZ/1uJQ/tQMjNb
-----END PRIVATE KEY-----
";

    const TEST_VERIFY_KEY: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA8nRzpCYzZ1xFKNJDGt9wuXdq7kKS/ck9PfLJu/r3VEw=
-----END PUBLIC KEY-----
";

    // Note: real tests require valid key pairs; these are placeholders.
    // Integration tests in the test suite use generated keys.
    #[test]
    fn claims_construction() {
        let user_id = Uuid::new_v4();
        let claims = AccessClaims::new(user_id, "admin", "admin", 900);
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.role, "admin");
        assert!(!claims.is_expired());
        assert_eq!(claims.user_id().unwrap(), user_id);
    }
}
