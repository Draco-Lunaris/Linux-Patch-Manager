//! pm-ca — Internal Certificate Authority.
//!
//! Issues and renews mTLS client certificates for agent communication.
//! Uses rcgen + rustls. CA key stored at /etc/patch-manager/ca/.

pub mod ca;
pub use ca::{CertAuthority, IssuedCert};
