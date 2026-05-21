//! Helper for loading mTLS certificate/key material from disk.
//!
//! Reads PEM files referenced in [`SecurityConfig`] and returns the raw bytes
//! needed by [`pm_agent_client::AgentClient`].

use pm_core::config::SecurityConfig;

/// Raw PEM bytes for mTLS client authentication and CA verification.
pub struct AgentCerts {
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
    pub ca_cert: Vec<u8>,
}

/// Load agent mTLS certificates from the paths specified in [`SecurityConfig`].
///
/// Returns an error if any file cannot be read. The caller should handle
/// the error gracefully (log and skip the poll cycle) rather than crashing.
pub fn load_agent_certs(security: &SecurityConfig) -> anyhow::Result<AgentCerts> {
    let client_cert = std::fs::read(&security.agent_client_cert_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read agent client cert '{}': {}",
            security.agent_client_cert_path,
            e
        )
    })?;

    let client_key = std::fs::read(&security.agent_client_key_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read agent client key '{}': {}",
            security.agent_client_key_path,
            e
        )
    })?;

    let ca_cert = std::fs::read(&security.ca_cert_path).map_err(|e| {
        anyhow::anyhow!("Failed to read CA cert '{}': {}", security.ca_cert_path, e)
    })?;

    Ok(AgentCerts {
        client_cert,
        client_key,
        ca_cert,
    })
}
