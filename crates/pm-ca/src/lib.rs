//! pm-ca — Internal Certificate Authority.
//!
//! Issues and renews mTLS client certificates for agent communication.
//! Uses rcgen + rustls. CA key stored at /etc/patch-manager/ca/ca.key.
//!
//! M1: Stub. Full implementation in M8.
pub mod ca;
