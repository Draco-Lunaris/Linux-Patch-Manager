//! `pm-agent-client` — mTLS HTTP client for Linux Patch API agent communication.
//!
//! This crate provides [`client::AgentClient`], an async HTTP client that
//! establishes mutual-TLS connections (TLS 1.3) to `linux_patch_api` agents
//! running on managed hosts.
//!
//! # Quick start
//!
//! ```no_run
//! use pm_agent_client::AgentClient;
//!
//! # async fn run() -> Result<(), pm_agent_client::AgentClientError> {
//! let client = AgentClient::new(
//!     "10.0.1.5",
//!     12443,
//!     include_bytes!("../certs/client.crt"),
//!     include_bytes!("../certs/client.key"),
//!     include_bytes!("../certs/ca.crt"),
//! )?;
//!
//! let health = client.health().await?;
//! println!("Agent {}: {}", health.status, health.version);
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod error;
pub mod types;

// ── Convenience re-exports ──────────────────────────────────────────────────

/// Primary client — re-exported from [`client::AgentClient`].
pub use client::{AgentClient, DEFAULT_AGENT_PORT};

/// Error type — re-exported from [`error::AgentClientError`].
pub use error::AgentClientError;

/// Response envelope and all data types.
pub use types::{
    AgentEnvelope, AgentErrorBody, HealthData, Package, PackagesData, Patch, PatchesData,
    SystemInfoData,
};
