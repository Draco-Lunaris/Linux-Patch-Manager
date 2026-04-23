//! pm-auth — Authentication and authorization.
//!
//! Modules: password (Argon2id), jwt (EdDSA), refresh tokens,
//! mfa_totp, mfa_webauthn, rbac, session.
//!
//! M1: Stub. Full implementation in M2.
pub mod password;
pub mod jwt;
pub mod rbac;
pub mod session;
