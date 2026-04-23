//! pm-auth — Authentication and authorization.
//!
//! Modules:
//! - `password` — Argon2id password hashing (m=65536, t=3, p=1)
//! - `jwt` — EdDSA/Ed25519 JWT issuance and validation (15-min TTL)
//! - `refresh` — Opaque 256-bit refresh tokens (1-hour sliding window)
//! - `mfa_totp` — TOTP setup and verification (Google Authenticator compatible)
//! - `mfa_webauthn` — WebAuthn stub (full implementation pending)
//! - `rbac` — Axum middleware for JWT authentication and role enforcement
//! - `session` — Login flow orchestration (password → MFA → tokens)

pub mod jwt;
pub mod mfa_totp;
pub mod mfa_webauthn;
pub mod password;
pub mod rbac;
pub mod refresh;
pub mod session;

// Commonly re-exported types
pub use jwt::{AccessClaims, JwtError};
pub use password::{hash_password, verify_password, PasswordError};
pub use rbac::{AuthConfig, AuthUser, UserRole};
pub use session::{LoginRequest, LoginResponse, SessionError, SessionUser};
