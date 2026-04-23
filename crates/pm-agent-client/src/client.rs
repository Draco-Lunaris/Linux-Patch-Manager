//! Agent HTTP client stub.
//! Full mTLS Rustls-based implementation arrives in M4.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentClientError {
    #[error("Not yet implemented")]
    NotImplemented,
}
