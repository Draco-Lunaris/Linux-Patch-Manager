//! Response and request types for the Linux Patch API agent endpoints.
//!
//! All agent responses are wrapped in [`AgentEnvelope<T>`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================
// Envelope & error
// ============================================================

/// Generic response wrapper returned by every agent endpoint.
///
/// ```json
/// { "success": true, "request_id": "…", "timestamp": "…", "data": {…}, "error": null }
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentEnvelope<T> {
    /// `true` when the request succeeded; `false` on error.
    pub success: bool,
    /// Server-assigned request identifier (UUID v4).
    pub request_id: Uuid,
    /// Server timestamp for the response (ISO-8601 / RFC-3339).
    pub timestamp: DateTime<Utc>,
    /// Response payload — present when `success` is `true`.
    pub data: Option<T>,
    /// Error detail — present when `success` is `false`.
    pub error: Option<AgentErrorBody>,
}

/// Structured error returned inside [`AgentEnvelope::error`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentErrorBody {
    /// Machine-readable error code (e.g. `"INTERNAL_ERROR"`).
    pub code: String,
    /// Human-readable description of what went wrong.
    pub message: String,
    /// Optional free-form extra detail from the agent.
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    /// Whether the caller may safely retry the request.
    #[serde(default)]
    pub retryable: bool,
}

// ============================================================
// PUT /api/v1/packages/{name}
// ============================================================

/// Response from `PUT /api/v1/packages/{name}` — standard package update.
/// Returns an async job ID for status polling.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdatePackageResponse {
    /// Agent-assigned async job ID for status polling.
    pub job_id: String,
    /// Initial status: typically `"pending"` or `"running"`.
    pub status: String,
}

// ============================================================
// GET /api/v1/health
// ============================================================

/// Payload returned by `GET /api/v1/health`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthData {
    /// Agent status string, e.g. `"ok"` or `"degraded"`.
    pub status: String,
    /// Seconds elapsed since the agent process started.
    pub uptime_seconds: u64,
    /// Agent software version string.
    pub version: String,
    /// CRL status reported by the agent: `"valid"`, `"expired"`, `"missing"`, `"invalid"`.
    /// Absent for older agents that do not report CRL status.
    #[serde(default)]
    pub crl_status: Option<String>,
    /// Seconds since the agent's CRL was last refreshed.
    #[serde(default)]
    pub crl_age_seconds: Option<i64>,
    /// When the agent's CRL expires / next update is due (ISO-8601).
    #[serde(default)]
    pub crl_next_update: Option<String>,
    /// GPG key status reported by the agent: valid, expired, missing, revoked.
    /// None if the agent doesn't report GPG key status (pre-v2.0.0 agents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpg_key_status: Option<String>,
    /// When the agent's GPG key expires (ISO 8601 string), if reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpg_key_expires_at: Option<String>,
}

// ============================================================
// GET /api/v1/system/info
// ============================================================

/// Payload returned by `GET /api/v1/system/info`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemInfoData {
    /// Hostname of the managed system.
    pub hostname: String,
    /// OS family / distribution name (e.g. `"Ubuntu"`).
    pub os: String,
    /// OS version string.
    pub os_version: String,
    /// Kernel version string.
    pub kernel: String,
    /// CPU architecture (e.g. `"x86_64"`).
    pub architecture: String,
    /// When the agent last checked for updates (`null` if never).
    pub last_update_check: Option<DateTime<Utc>>,
    /// When updates were last applied (`null` if never).
    pub last_update_apply: Option<DateTime<Utc>>,
    /// Whether the system has a pending reboot.
    pub pending_reboot: bool,
}

// ============================================================
// GET /api/v1/packages?status=upgradable
// ============================================================

/// A single package entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Package {
    /// Package name.
    pub name: String,
    /// Installed version.
    pub version: String,
    /// Package status string (e.g. `"installed"`, `"upgradable"`).
    pub status: String,
    /// Whether a newer version is available.
    pub upgradable: bool,
    /// Latest available version (`null` if not upgradable).
    pub latest_version: Option<String>,
    /// Short package description.
    pub description: String,
    /// CVE identifiers associated with this package.
    #[serde(default)]
    pub cve_ids: Vec<String>,
}

/// Payload returned by `GET /api/v1/packages`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackagesData {
    /// List of packages matching the query filters.
    pub packages: Vec<Package>,
    /// Total count of matching packages.
    pub total: u64,
}

// ============================================================
// GET /api/v1/patches
// ============================================================

/// A single available patch.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Patch {
    /// Package / patch name.
    pub name: String,
    /// Currently installed version.
    pub current_version: String,
    /// Version available after applying this patch.
    pub available_version: String,
    /// Severity level (e.g. `"critical"`, `"high"`, `"medium"`, `"low"`).
    pub severity: String,
    /// Human-readable description of the patch.
    pub description: String,
    /// CVE identifiers addressed by this patch.
    #[serde(default)]
    pub cve_ids: Vec<String>,
    /// Whether applying this patch requires a system reboot.
    pub requires_reboot: bool,
}

/// Payload returned by `GET /api/v1/patches`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PatchesData {
    /// List of available patches.
    pub patches: Vec<Patch>,
    /// Total patch count.
    pub total: u64,
    /// Number of patches classified as security updates.
    pub security_updates: u64,
    /// Whether any patch in the list requires a reboot.
    pub requires_reboot: bool,
}

// ============================================================
// POST /api/v1/patches/apply
// ============================================================

/// Request body for `POST /api/v1/patches/apply`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyPatchesRequest {
    /// Package names to apply. Empty = apply all available patches.
    pub packages: Vec<String>,
    /// If true, allow automatic reboot after patching if required.
    pub allow_reboot: bool,
    /// Delay (in seconds) before the reboot is triggered. Only used
    /// when `allow_reboot` is true and a reboot is actually needed.
    /// 0 = immediate reboot. Defaults to 0 if omitted.
    #[serde(default)]
    pub reboot_delay_seconds: u64,
}

/// Response from `POST /api/v1/patches/apply`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplyPatchesResponse {
    /// Agent-assigned async job ID for status polling.
    pub job_id: String,
    /// Initial status: typically `"running"` or `"queued"`.
    pub status: String,
}

// ============================================================
// GET /api/v1/jobs/{id}
// ============================================================

/// Status of an async agent job returned by `GET /api/v1/jobs/{id}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentJobStatus {
    pub job_id: String,
    /// Current status: `"queued"`, `"running"`, `"succeeded"`, `"completed"`, `"failed"`, or `"cancelled"`.
    pub status: String,
    pub progress_percent: Option<u8>,
    pub output: Option<String>,
    pub error: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

// ============================================================
// GET /api/v1/system/services/{name}
// ============================================================

/// Payload returned by `GET /api/v1/system/services/{name}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceStatusData {
    /// Service name.
    pub name: String,
    /// Human-readable service name.
    pub display_name: String,
    /// Active state (e.g. `"active"`, `"inactive"`, `"failed"`).
    pub active_state: String,
    /// Sub state (e.g. `"running"`, `"dead"`, `"exited"`).
    pub sub_state: String,
    /// Load state (e.g. `"loaded"`, `"not-found"`).
    pub load_state: String,
    /// Enabled state (e.g. `"enabled"`, `"disabled"`).
    pub enabled_state: String,
    /// Main PID of the service process.
    pub main_pid: Option<u32>,
    /// Whether the service is considered healthy.
    pub healthy: bool,
}

// ============================================================
// POST /api/v1/jobs/{id}/rollback
// ============================================================

/// Response from `POST /api/v1/jobs/{id}/rollback`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RollbackResponse {
    pub job_id: String,
    pub status: String,
}

// ============================================================
// POST /api/v1/system/reboot
// ============================================================

/// Request body for `POST /api/v1/system/reboot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebootRequest {
    /// Delay in seconds before triggering the reboot. 0 = immediate.
    #[serde(default)]
    pub delay_seconds: u64,
    /// If true, force reboot even if other users are logged in.
    #[serde(default)]
    pub force: bool,
}

/// Response from `POST /api/v1/system/reboot`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RebootResponse {
    /// Agent-assigned async job ID for status polling.
    pub job_id: String,
    /// Initial status: typically `"running"` or `"queued"`.
    pub status: String,
}
