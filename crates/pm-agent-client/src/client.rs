//! mTLS HTTP client for communicating with Linux Patch API agents.
//!
//! # Example
//!
//! ```no_run
//! use pm_agent_client::client::AgentClient;
//!
//! # async fn example() -> Result<(), pm_agent_client::error::AgentClientError> {
//! // Load certificates from files (never hardcode or include_bytes! private keys)
//! let client_cert = std::fs::read("/etc/patch-manager/certs/client.crt")?;
//! let client_key = std::fs::read("/etc/patch-manager/certs/client.key")?;
//! let ca_cert = std::fs::read("/etc/patch-manager/ca/ca.crt")?;
//!
//! let client = AgentClient::new(
//!     "192.168.1.10",
//!     12443,
//!     &client_cert,
//!     &client_key,
//!     &ca_cert,
//! )?;
//!
//! let health = client.health().await?;
//! println!("Agent status: {}", health.status);
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use reqwest::{tls::Version, Certificate, ClientBuilder, Identity};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, instrument};

use crate::{
    error::AgentClientError,
    types::{
        AgentEnvelope, AgentJobStatus, ApplyPatchesRequest, ApplyPatchesResponse, HealthData,
        PackagesData, PatchesData, RollbackResponse,
        ServiceStatusData, SystemInfoData, UpdatePackageResponse,
    },
};

/// Default TCP port that the Linux Patch API agent listens on.
pub const DEFAULT_AGENT_PORT: u16 = 12443;

/// Request timeout applied to every agent API call.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================
// AgentClient
// ============================================================

/// Async HTTP client that speaks mTLS to a single Linux Patch API agent.
///
/// Construct once via [`AgentClient::new`] and reuse across calls;
/// the underlying [`reqwest::Client`] maintains a connection pool.
#[derive(Debug, Clone)]
pub struct AgentClient {
    /// Underlying HTTP client (configured for mTLS + TLS 1.3).
    inner: reqwest::Client,
    /// Base URL of the agent, e.g. `https://10.0.0.5:12443/api/v1`.
    base_url: String,
}

impl AgentClient {
    /// Create a new [`AgentClient`] configured for mTLS.
    ///
    /// # Arguments
    ///
    /// * `host_ip`        – IP address (or hostname) of the agent.
    /// * `port`           – TCP port the agent listens on (default [`DEFAULT_AGENT_PORT`]).
    /// * `client_cert_pem` – PEM-encoded client certificate presented during the TLS handshake.
    /// * `client_key_pem`  – PEM-encoded private key matching `client_cert_pem`.
    /// * `ca_cert_pem`     – PEM-encoded CA certificate used to verify the agent's server cert.
    ///
    /// # Errors
    ///
    /// Returns [`AgentClientError::Tls`] when certificate parsing fails, or
    /// [`AgentClientError::Request`] when `reqwest` client construction fails.
    pub fn new(
        host_ip: &str,
        port: u16,
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        ca_cert_pem: &[u8],
    ) -> Result<Self, AgentClientError> {
        // Build client identity: reqwest expects cert + key concatenated as PEM.
        let mut identity_pem = Vec::with_capacity(client_cert_pem.len() + client_key_pem.len());
        identity_pem.extend_from_slice(client_cert_pem);
        identity_pem.extend_from_slice(client_key_pem);

        let identity = Identity::from_pem(&identity_pem)
            .map_err(|e| AgentClientError::Tls(format!("invalid client identity PEM: {e}")))?;

        // Parse the CA certificate used to verify the agent's server certificate.
        let ca_cert = Certificate::from_pem(ca_cert_pem)
            .map_err(|e| AgentClientError::Tls(format!("invalid CA certificate PEM: {e}")))?;

        // Build the reqwest client:
        //  - force rustls TLS backend
        //  - disable built-in OS/system trust roots (only trust our internal CA)
        //  - enforce TLS 1.3 minimum
        //  - attach client identity (mTLS)
        //  - add our CA as a trusted root
        //  - apply a global request timeout
        let inner = ClientBuilder::new()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .min_tls_version(Version::TLS_1_3)
            .identity(identity)
            .add_root_certificate(ca_cert)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(AgentClientError::Request)?;

        let clean_ip = host_ip.split('/').next().unwrap_or(host_ip);
        let base_url = format!("https://{}:{}/api/v1", clean_ip, port);

        Ok(Self { inner, base_url })
    }

    // --------------------------------------------------------
    // Public API methods
    // --------------------------------------------------------

    /// `GET /api/v1/health` — check agent liveness and retrieve uptime.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn health(&self) -> Result<HealthData, AgentClientError> {
        self.get("health", &[]).await
    }

    /// `GET /api/v1/system/info` — retrieve host system information.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn system_info(&self) -> Result<SystemInfoData, AgentClientError> {
        self.get("system/info", &[]).await
    }

    /// `GET /api/v1/packages?status=upgradable` — list packages with available upgrades.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn packages_upgradable(&self) -> Result<PackagesData, AgentClientError> {
        self.get("packages", &[("status", "upgradable")]).await
    }

    /// `GET /api/v1/patches` — list available patches with severity and CVE data.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn patches(&self) -> Result<PatchesData, AgentClientError> {
        self.get("patches", &[]).await
    }

    // --------------------------------------------------------
    // Private helpers
    // --------------------------------------------------------

    /// Execute a GET request against `{base_url}/{path}` with optional query
    /// parameters, deserialize the [`AgentEnvelope`], and extract the `data`
    /// field — or propagate an [`AgentClientError::ApiError`].
    async fn get<T>(&self, path: &str, query: &[(&str, &str)]) -> Result<T, AgentClientError>
    where
        T: DeserializeOwned,
    {
        let url = format!("{}/{}", self.base_url, path);
        debug!(url = %url, ?query, "Sending GET request to agent");

        let mut request = self.inner.get(&url);
        if !query.is_empty() {
            request = request.query(query);
        }

        let response = request.send().await?;
        let status = response.status();
        debug!(url = %url, status = %status, "Received response from agent");

        // Capture body text so we can attempt to deserialise the error envelope
        // even for non-2xx responses.
        let body = response.text().await?;

        // Attempt to parse the standard agent envelope regardless of HTTP status.
        // The agent may embed a structured error body on 4xx/5xx responses.
        let envelope: AgentEnvelope<T> = serde_json::from_str(&body)?;

        if !status.is_success() || !envelope.success {
            // Prefer the structured error from the envelope when present.
            if let Some(err) = envelope.error {
                return Err(AgentClientError::ApiError {
                    code: err.code,
                    message: err.message,
                });
            }
            // Fallback: use the HTTP status as the error indicator.
            return Err(AgentClientError::ApiError {
                code: status.as_str().to_string(),
                message: format!("Agent returned HTTP {} for {}", status.as_u16(), url),
            });
        }

        // On success the `data` field must be present.
        envelope.data.ok_or_else(|| AgentClientError::ApiError {
            code: "MISSING_DATA".to_string(),
            message: "Agent response success=true but data field is absent".to_string(),
        })
    }

    // --------------------------------------------------------
    // Patch apply / job management methods
    // --------------------------------------------------------

    /// `POST /api/v1/patches/apply` — trigger patch application on the agent.
    #[instrument(skip(self, req), fields(base_url = %self.base_url))]
    pub async fn apply_patches(
        &self,
        req: &ApplyPatchesRequest,
    ) -> Result<ApplyPatchesResponse, AgentClientError> {
        self.post("patches/apply", req).await
    }

    /// `GET /api/v1/jobs/{id}` — poll an async agent job for status.
    #[instrument(skip(self), fields(base_url = %self.base_url, job_id = %job_id))]
    pub async fn job_status(&self, job_id: &str) -> Result<AgentJobStatus, AgentClientError> {
        self.get(&format!("jobs/{}", job_id), &[]).await
    }

    /// `POST /api/v1/jobs/{id}/rollback` — trigger rollback on the agent.
    #[instrument(skip(self), fields(base_url = %self.base_url, job_id = %job_id))]
    pub async fn rollback_job(&self, job_id: &str) -> Result<RollbackResponse, AgentClientError> {
        let empty: serde_json::Value = serde_json::json!({});
        self.post(&format!("jobs/{}/rollback", job_id), &empty)
            .await
    }

    /// `GET /api/v1/system/services/{name}` — check status of a specific service on the agent.
    #[instrument(skip(self), fields(base_url = %self.base_url, service_name = %service_name))]
    pub async fn service_status(
        &self,
        service_name: &str,
    ) -> Result<ServiceStatusData, AgentClientError> {
        self.get(&format!("system/services/{}", service_name), &[])
            .await
    }

    /// `PUT /api/v1/packages/{name}` — update a specific package on the agent.
    ///
    /// This is the standard package update endpoint. For agent self-upgrades,
    /// call with `"linux-patch-api"` as the package name.
    #[instrument(skip(self), fields(base_url = %self.base_url, package_name = %package_name))]
    pub async fn update_package(
        &self,
        package_name: &str,
    ) -> Result<UpdatePackageResponse, AgentClientError> {
        self.put(&format!("packages/{}", package_name)).await
    }

    // Private PUT helper
    // --------------------------------------------------------

    /// Execute a PUT request against `{base_url}/{path}` with an empty body,
    /// deserialize the [`AgentEnvelope`], and extract the `data` field.
    async fn put<Resp>(&self, path: &str) -> Result<Resp, AgentClientError>
    where
        Resp: DeserializeOwned,
    {
        let url = format!("{}/{}", self.base_url, path);
        debug!(url = %url, "Sending PUT request to agent");

        let response = self.inner.put(&url).send().await?;
        let status = response.status();
        debug!(url = %url, status = %status, "Received PUT response from agent");

        let body_text = response.text().await?;
        let envelope: AgentEnvelope<Resp> = serde_json::from_str(&body_text)?;

        if !status.is_success() || !envelope.success {
            if let Some(err) = envelope.error {
                return Err(AgentClientError::ApiError {
                    code: err.code,
                    message: err.message,
                });
            }
            return Err(AgentClientError::ApiError {
                code: status.as_str().to_string(),
                message: format!("Agent returned HTTP {} for {}", status.as_u16(), url),
            });
        }

        envelope.data.ok_or_else(|| AgentClientError::ApiError {
            code: "MISSING_DATA".to_string(),
            message: "Agent response success=true but data field is absent".to_string(),
        })
    }

    // --------------------------------------------------------
    // Private POST helper
    // --------------------------------------------------------

    /// Execute a POST request against `{base_url}/{path}`, serialize `body` as
    /// JSON, deserialize the [`AgentEnvelope`], and extract the `data` field —
    /// or propagate an [`AgentClientError::ApiError`].
    async fn post<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp, AgentClientError>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let url = format!("{}/{}", self.base_url, path);
        debug!(url = %url, "Sending POST request to agent");

        let response = self.inner.post(&url).json(body).send().await?;
        let status = response.status();
        debug!(url = %url, status = %status, "Received POST response from agent");

        let body_text = response.text().await?;
        let envelope: AgentEnvelope<Resp> = serde_json::from_str(&body_text)?;

        if !status.is_success() || !envelope.success {
            if let Some(err) = envelope.error {
                return Err(AgentClientError::ApiError {
                    code: err.code,
                    message: err.message,
                });
            }
            return Err(AgentClientError::ApiError {
                code: status.as_str().to_string(),
                message: format!("Agent returned HTTP {} for {}", status.as_u16(), url),
            });
        }

        envelope.data.ok_or_else(|| AgentClientError::ApiError {
            code: "MISSING_DATA".to_string(),
            message: "Agent response success=true but data field is absent".to_string(),
        })
    }
}

// ============================================================
// Reconnection helper
// ============================================================

/// Repeatedly call [`AgentClient::system_info`] with exponential backoff
/// until the agent comes back online or `max_wait_secs` is exceeded.
///
/// Uses a fixed backoff sequence of `[5, 10, 20, 40]` seconds, cycling
/// through until the cumulative elapsed time exceeds `max_wait_secs`.
///
/// # Returns
///
/// * `Ok(SystemInfoData)` — the agent responded successfully.
/// * `Err(AgentClientError::ApiError { code: "RECONNECT_TIMEOUT", .. })` —
///   the agent did not come back within the deadline.
/// * `Err(other)` — a non-transient error was encountered.
pub async fn reconnect_with_backoff(
    client: &AgentClient,
    max_wait_secs: u64,
) -> Result<SystemInfoData, AgentClientError> {
    let backoff_sequence: [u64; 4] = [5, 10, 20, 40];
    let mut elapsed: u64 = 0;

    for delay_secs in backoff_sequence.iter().cycle() {
        tokio::time::sleep(Duration::from_secs(*delay_secs)).await;
        elapsed += delay_secs;

        match client.system_info().await {
            Ok(info) => return Ok(info),
            Err(AgentClientError::Connect(_) | AgentClientError::Timeout) => {
                // Agent not back yet — keep retrying.
                tracing::debug!(
                    elapsed_secs = elapsed,
                    next_delay_secs = delay_secs,
                    "Agent not reachable yet, retrying…"
                );
            },
            Err(other) => return Err(other),
        }

        if elapsed >= max_wait_secs {
            break;
        }
    }

    Err(AgentClientError::ApiError {
        code: "RECONNECT_TIMEOUT".to_string(),
        message: format!("Agent did not come back online within {max_wait_secs}s"),
    })
}
