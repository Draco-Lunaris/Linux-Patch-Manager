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
//! // Load certificates from files (never hardcode or include_bytes! private keys)
//! let client_cert = std::fs::read("/etc/patch-manager/certs/client.crt")?;
//! let client_key = std::fs::read("/etc/patch-manager/certs/client.key")?;
//! let ca_cert = std::fs::read("/etc/patch-manager/ca/ca.crt")?;
//!
//! let client = AgentClient::new(
//!     "10.0.1.5",
//!     12443,
//!     &client_cert,
//!     &client_key,
//!     &ca_cert,
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
pub use client::{reconnect_with_backoff, AgentClient, DEFAULT_AGENT_PORT};

/// Error type — re-exported from [`error::AgentClientError`].
pub use error::AgentClientError;

/// Response envelope and all data types.
pub use types::{
    AgentEnvelope, AgentErrorBody, HealthData, Package, PackagesData, Patch, PatchesData,
    RebootRequest, RebootResponse, RollbackResponse, ServiceStatusData, SystemInfoData,
    UpdatePackageResponse,
};
