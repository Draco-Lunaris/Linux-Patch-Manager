//! Error types for the pm-agent-client crate.

use thiserror::Error;

/// Top-level error type returned by [`crate::client::AgentClient`] methods.
#[derive(Debug, Error)]
pub enum AgentClientError {
    /// TLS configuration or handshake failure.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Unable to establish a TCP/TLS connection to the agent.
    #[error("Connection error: {0}")]
    Connect(#[source] reqwest::Error),

    /// An HTTP request or response transport error (not a timeout).
    #[error("Request error: {0}")]
    Request(#[source] reqwest::Error),

    /// The request did not complete within the configured timeout.
    #[error("Request timed out")]
    Timeout,

    /// The agent returned a non-2xx HTTP status or `success: false` in the
    /// response envelope.
    #[error("Agent API error [{code}]: {message}")]
    ApiError {
        /// Machine-readable error code supplied by the agent (e.g. `"NOT_FOUND"`).
        code: String,
        /// Human-readable description returned by the agent.
        message: String,
    },

    /// JSON deserialization of the agent response failed.
    #[error("Failed to deserialise agent response: {0}")]
    Deserialize(#[from] serde_json::Error),
}

impl From<reqwest::Error> for AgentClientError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            AgentClientError::Timeout
        } else if err.is_connect() {
            AgentClientError::Connect(err)
        } else {
            AgentClientError::Request(err)
        }
    }
}
