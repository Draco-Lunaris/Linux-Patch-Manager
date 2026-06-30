//! Shared database model types used across pm-web and pm-worker.
//!
//! These match the database schema defined in migrations/.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ============================================================
// Enumerations (matching PostgreSQL ENUM types)
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "host_health_status", rename_all = "lowercase")]
pub enum HostHealthStatus {
    Pending,
    Healthy,
    Degraded,
    Unreachable,
}

impl std::fmt::Display for HostHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unreachable => write!(f, "unreachable"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Operator,
    Reporter,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Operator => write!(f, "operator"),
            Self::Reporter => write!(f, "reporter"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "auth_provider", rename_all = "snake_case")]
pub enum AuthProvider {
    Local,
    #[sqlx(rename = "azure_sso")]
    AzureSso,
    Keycloak,
    Oidc,
}

impl std::fmt::Display for AuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::AzureSso => write!(f, "azure_sso"),
            Self::Keycloak => write!(f, "keycloak"),
            Self::Oidc => write!(f, "oidc"),
        }
    }
}

// ============================================================
// Host
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Host {
    pub id: Uuid,
    pub fqdn: String,
    pub ip_address: String, // stored as INET, returned as text
    pub display_name: String,
    pub os_family: Option<String>,
    pub os_name: Option<String>,
    pub arch: Option<String>,
    pub agent_version: Option<String>,
    pub health_status: HostHealthStatus,
    pub last_health_at: Option<DateTime<Utc>>,
    pub last_patch_at: Option<DateTime<Utc>>,
    pub agent_port: i32,
    pub notes: String,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// CRL status reported by the agent: valid, expired, missing, invalid, or NULL for older agents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_status: Option<String>,
    /// Seconds since the agent's CRL was last refreshed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_age_seconds: Option<i64>,
    /// When the agent's CRL expires / next update is due.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_next_update: Option<DateTime<Utc>>,
    /// GPG key status reported by the agent: valid, expired, missing, revoked, or NULL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpg_key_status: Option<String>,
    /// When the agent's GPG key expires (if reported).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpg_key_expires_at: Option<DateTime<Utc>>,
}

/// Payload for registering a new host.
#[derive(Debug, Deserialize)]
pub struct CreateHostRequest {
    /// FQDN or IP address of the managed host
    pub fqdn: String,
    pub display_name: Option<String>,
    pub agent_port: Option<i32>,
    pub notes: Option<String>,
    pub group_ids: Option<Vec<Uuid>>,
}

/// Payload for updating an existing host.
#[derive(Debug, Deserialize)]
pub struct UpdateHostRequest {
    pub fqdn: Option<String>,
    pub ip_address: Option<String>,
    pub display_name: Option<String>,
}

/// Host list item (lighter projection for list views)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HostSummary {
    pub id: Uuid,
    pub fqdn: String,
    pub ip_address: String,
    pub display_name: String,
    pub os_family: Option<String>,
    pub os_name: Option<String>,
    pub health_status: HostHealthStatus,
    pub agent_version: Option<String>,
    pub patches_missing: i32,
    pub health_check_status: Option<String>,
    pub registered_at: DateTime<Utc>,
    /// CRL status reported by the agent: valid, expired, missing, invalid, or NULL for older agents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_status: Option<String>,
}

// ============================================================
// Host Enrollment
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EnrollmentRequest {
    pub id: Uuid,
    pub machine_id: String,
    pub fqdn: String,
    pub ip_address: String,
    pub os_details: serde_json::Value,
    pub polling_token: String,
    /// Short hostname provided during enrollment (optional).
    pub hostname: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Payload for initial host enrollment request.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateEnrollmentRequest {
    pub machine_id: String,
    pub fqdn: String,
    pub ip_address: String,
    pub os_details: serde_json::Value,
    /// Short hostname (from /etc/hostname, optional).
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum EnrollmentStatusResponse {
    Pending,
    Approved {
        ca_crt: String,
        ca_chain: String,
        server_crt: String,
        server_key: String,
        crl_pem: String,
    },
    Denied,
    NotFound,
}

/// Configuration for the manager-hosted package repository.
///
/// Delivered to agents during enrollment so they can self-update from a
/// GPG-signed package repo hosted by the manager. The agent provisions the
/// GPG public key and distro-specific sources config to the correct
/// filesystem paths for its package manager (apt/dnf/apk/pacman).
///
/// Added for manager-hosted repo support (issue #116 / self-update v2.0.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfig {
    /// ASCII-armored GPG public key used to sign packages in the repo.
    /// The agent writes this to the distro-specific keyring path.
    pub gpg_public_key: String,
    /// Distro-specific sources configuration string.
    /// For apt: a `deb [signed-by=...] ...` line.
    /// For dnf: a .repo file content.
    /// For apk: a repository URL line.
    /// For pacman: an include file content.
    pub sources_config: String,
    /// Bare distribution identifier with no version suffix (e.g., `ubuntu`,
    /// `debian`, `fedora`, `almalinux`, `alpine`, `arch`). The agent's
    /// `provision_repo_config()` matches this against exact bare strings.
    /// See INTERFACE_CONTRACT.md §2.3.
    pub distro_id: String,
    /// Filesystem path where the GPG public key should be installed
    /// (e.g., `/etc/apt/keyrings/lpa-repo.gpg` for apt,
    /// `/etc/pki/rpm-gpg/lpa-repo.gpg` for dnf).
    pub keyring_path: String,
}

/// Detect distro_id from OS details fields extracted during enrollment.
///
/// Returns a bare distro_id string (no version suffix): `ubuntu`, `debian`,
/// `fedora`, `almalinux`, `alpine`, or `arch`, or `None` if the OS is
/// unrecognized. The agent's `provision_repo_config()` matches distro_id
/// against exact bare strings — version-suffixed values will miss every
/// match arm and bail. See INTERFACE_CONTRACT.md §2.3.
pub fn detect_distro_id(os_family: Option<&str>, os_name: Option<&str>) -> Option<String> {
    let os = os_family.unwrap_or_default().to_ascii_lowercase();
    let name = os_name.unwrap_or_default().to_ascii_lowercase();
    if os.contains("ubuntu") || name.contains("ubuntu") {
        Some("ubuntu".to_string())
    } else if os.contains("debian") || name.contains("debian") {
        Some("debian".to_string())
    } else if os.contains("fedora") || name.contains("fedora") {
        Some("fedora".to_string())
    } else if os.contains("alma") || name.contains("alma") {
        Some("almalinux".to_string())
    } else if os.contains("alpine") || name.contains("alpine") {
        Some("alpine".to_string())
    } else if os.contains("arch") || name.contains("arch") {
        Some("arch".to_string())
    } else {
        None
    }
}

/// Generate distro-specific sources_config and keyring_path for a given distro_id.
///
/// Returns `None` if the distro is not supported.
pub fn generate_distro_config(distro_id: &str, repo_url_base: &str) -> Option<(String, String)> {
    let base = repo_url_base.trim_end_matches('/');
    if distro_id == "ubuntu" || distro_id == "debian" {
        let sources = format!("deb [signed-by=/etc/apt/keyrings/lpa-repo.gpg] {base}/apt/ ./");
        let keyring = "/etc/apt/keyrings/lpa-repo.gpg".to_string();
        Some((sources, keyring))
    } else if distro_id == "fedora" || distro_id == "almalinux" {
        let sources = format!(
            "[lpa-repo]\\nname=Linux Patch API Repo\\nbaseurl={base}/dnf/\\nenabled=1\\ngpgcheck=1\\ngpgkey=file:///etc/pki/rpm-gpg/lpa-repo.gpg\\n"
        );
        let keyring = "/etc/pki/rpm-gpg/lpa-repo.gpg".to_string();
        Some((sources, keyring))
    } else if distro_id == "alpine" {
        let sources = format!("{base}/apk/");
        let keyring = "/etc/apk/keys/lpa-repo.rsa.pub".to_string();
        Some((sources, keyring))
    } else if distro_id == "arch" {
        let sources = format!(
            "[lpa-repo]\\nServer = {base}/pacman/$repo\\nSigLevel = Required DatabaseOptional\\n"
        );
        let keyring = "/etc/pacman.d/gnupg/lpa-repo.gpg".to_string();
        Some((sources, keyring))
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiBundle {
    /// PEM-encoded CA certificate (leaf-most cert in the chain).
    /// For root mode, this is the self-signed root CA.
    /// For sub-CA mode, this is the intermediate CA cert.
    pub ca_crt: String,
    /// PEM-encoded full CA certificate chain (concatenated intermediates + root).
    /// For root mode, this contains just the root CA cert (same as ca_crt).
    /// For sub-CA mode, this contains the intermediate cert followed by the
    /// external root cert, enabling the agent to verify the full chain up to
    /// the trust anchor.
    ///
    /// This field was added for CRL support (issue #7): the agent needs the
    /// full chain to verify CRL signatures that chain up to the root CA.
    #[serde(default)]
    pub ca_chain: String,
    /// PEM-encoded agent server certificate.
    pub server_crt: String,
    /// PEM-encoded agent server private key (PKCS#8).
    pub server_key: String,
    /// PEM-encoded Certificate Revocation List (CRL) signed by the CA.
    /// The agent uses this to reject revoked client certificates during mTLS
    /// handshakes. If CRL generation fails during enrollment, this field will
    /// be an empty string and the agent should fall back to WebPKI-only
    /// verification (degraded mode).
    ///
    /// Added for CRL support (issue #7).
    #[serde(default)]
    pub crl_pem: String,
    /// Manager-hosted package repository configuration for agent self-update.
    ///
    /// When present, the agent provisions the GPG key and sources config
    /// to enable self-updates from the manager-hosted repo. When absent
    /// (agents enrolled before v2.0.0 or when repo is not configured),
    /// the agent falls back to `GET /api/v1/pki/repo-config`.
    ///
    /// Added for manager-hosted repo support (issue #116).
    #[serde(default)]
    pub repo_config: Option<RepoConfig>,
}

/// Time-to-live for approved enrollment PKI bundles (10 minutes).
///
/// After approval, the agent has this duration to retrieve its PKI bundle
/// via the polling endpoint. Once retrieved (single-use) or expired,
/// the bundle is permanently removed from the in-memory cache.
///
/// This TTL balances security (limiting private key exposure in memory)
/// against reliability (giving agents enough time to poll after approval).
pub const ENROLLMENT_BUNDLE_TTL_SECS: u32 = 600; // 10 minutes

/// An approved enrollment PKI bundle awaiting single-use retrieval.
///
/// Stored in the in-memory cache between admin approval and agent pickup.
/// The entry is removed atomically on first retrieval and expires after
/// the configured TTL, whichever comes first.
#[derive(Debug, Clone)]
pub struct ApprovedEntry {
    pub pki: PkiBundle,
    pub approved_at: chrono::DateTime<Utc>,
    pub ttl: chrono::Duration,
}

impl ApprovedEntry {
    /// Create a new entry with the current timestamp and default TTL.
    pub fn new(pki: PkiBundle) -> Self {
        Self {
            pki,
            approved_at: Utc::now(),
            ttl: chrono::Duration::seconds(ENROLLMENT_BUNDLE_TTL_SECS as i64),
        }
    }

    /// Returns true if this entry has exceeded its TTL.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.approved_at + self.ttl
    }
}

// ============================================================
// Health Checks
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HealthCheck {
    pub id: Uuid,
    pub host_id: Uuid,
    pub name: String,
    pub check_type: String, // "service" or "http"
    pub enabled: bool,
    // Service check fields
    pub service_name: Option<String>,
    // HTTP check fields
    pub url: Option<String>,
    pub expected_body: Option<String>,
    pub ignore_cert_errors: bool,
    pub basic_auth_user: Option<String>,
    pub target_host_id: Option<Uuid>,
    // basic_auth_pass_encrypted and nonce NOT exposed in API responses
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckWithResult {
    #[serde(flatten)]
    pub check: HealthCheck,
    pub last_result: Option<HealthCheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HealthCheckResult {
    pub id: Uuid,
    pub check_id: Uuid,
    pub healthy: bool,
    pub detail: Option<String>,
    pub latency_ms: Option<i32>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateHealthCheckRequest {
    pub name: String,
    pub check_type: String, // "service" or "http"
    pub service_name: Option<String>,
    pub url: Option<String>,
    pub expected_body: Option<String>,
    #[serde(default = "default_true")]
    pub ignore_cert_errors: bool,
    pub basic_auth_user: Option<String>,
    pub basic_auth_pass: Option<String>, // plaintext in request, encrypted before storage
    pub target_host_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHealthCheckRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub service_name: Option<String>,
    pub url: Option<String>,
    pub expected_body: Option<String>,
    pub ignore_cert_errors: Option<bool>,
    pub basic_auth_user: Option<String>,
    pub basic_auth_pass: Option<String>, // if provided, re-encrypt
    pub target_host_id: Option<Uuid>,
}

fn default_true() -> bool {
    true
}

// ============================================================
// Group
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

// ============================================================
// User
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub role: UserRole,
    pub auth_provider: AuthProvider,
    pub mfa_enabled: bool,
    pub is_active: bool,
    pub force_password_reset: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User create payload (admin-only)
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: Option<String>,
    pub email: String,
    pub role: String,
    pub password: String,
}

/// User update payload
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
    pub force_password_reset: Option<bool>,
}

/// Self-service password change payload
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Admin password reset payload
#[derive(Debug, Deserialize)]
pub struct AdminResetPasswordRequest {
    pub new_password: String,
    #[serde(default)]
    pub force_password_reset: bool,
}

// ============================================================
// Discovery
// ============================================================

/// Request body for CIDR auto-discovery scan.
#[derive(Debug, Deserialize)]
pub struct DiscoveryCidrRequest {
    /// CIDR range to scan (e.g. "10.0.0.0/24")
    pub cidr: String,
    /// Agent port to probe (default 12443)
    pub agent_port: Option<i32>,
}

/// A single discovered host result.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DiscoveryResult {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub ip_address: String,
    pub fqdn: Option<String>,
    pub agent_version: Option<String>,
    pub os_name: Option<String>,
    pub agent_port: i32,
    pub discovered_at: DateTime<Utc>,
    pub registered: bool,
}

/// Payload for registering a host from a discovery result.
#[derive(Debug, Deserialize)]
pub struct RegisterDiscoveredRequest {
    pub discovery_id: Uuid,
    pub display_name: Option<String>,
    pub group_ids: Option<Vec<Uuid>>,
}

// ============================================================
// Patch Jobs
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "job_status", rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Succeeded => write!(f, "succeeded"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "job_kind", rename_all = "snake_case")]
pub enum JobKind {
    #[sqlx(rename = "patch_apply")]
    PatchApply,
    #[sqlx(rename = "patch_remove")]
    PatchRemove,
    Reboot,
    Rollback,
    #[sqlx(rename = "self_upgrade")]
    SelfUpgrade,
}

/// Full `patch_jobs` row.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PatchJob {
    pub id: Uuid,
    pub kind: JobKind,
    pub status: JobStatus,
    pub created_by_user_id: Option<Uuid>,
    pub parent_job_id: Option<Uuid>,
    pub maintenance_window_id: Option<Uuid>,
    pub immediate: bool,
    pub patch_selection: serde_json::Value,
    pub notes: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Full `patch_job_hosts` row (includes columns added in migration 003).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PatchJobHost {
    pub id: Uuid,
    pub job_id: Uuid,
    pub host_id: Uuid,
    pub status: JobStatus,
    pub agent_job_id: Option<String>,
    pub retry_count: i32,
    pub output: String,
    pub error_message: Option<String>,
    pub retry_next_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Request payload for creating a patch job via `POST /api/v1/jobs`.
#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    /// Host IDs to patch.
    pub host_ids: Vec<Uuid>,
    /// Package names to apply (empty = all available patches).
    pub packages: Vec<String>,
    /// If true: apply immediately. If false: queue for next maintenance window.
    pub immediate: bool,
    /// Optional maintenance window to bind to.
    pub maintenance_window_id: Option<Uuid>,
    /// Allow reboot if required by patches.
    pub allow_reboot: Option<bool>,
    /// Optional operator notes.
    pub notes: Option<String>,
}

/// Summary row for job list view (aggregates per-host counts).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PatchJobSummary {
    pub id: Uuid,
    pub kind: JobKind,
    pub status: JobStatus,
    pub immediate: bool,
    pub host_count: i64,
    /// Display names of hosts targeted by this job (falls back to fqdn).
    #[serde(default)]
    #[sqlx(skip)]
    pub host_names: Vec<String>,
    pub succeeded_count: i64,
    pub failed_count: i64,
    pub notes: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

// ============================================================
// Maintenance Windows
// ============================================================

/// Recurrence type for a maintenance window.
/// Mirrors the `window_recurrence` PostgreSQL ENUM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "window_recurrence", rename_all = "lowercase")]
pub enum WindowRecurrence {
    /// Single one-time window (at `start_at` for `duration_minutes` minutes).
    Once,
    /// Repeats every day at the time portion of `start_at`.
    Daily,
    /// Repeats on the day-of-week in `recurrence_day` (0 = Sunday).
    Weekly,
    /// Repeats on the day-of-month in `recurrence_day` (1-31).
    Monthly,
}

impl std::fmt::Display for WindowRecurrence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Once => write!(f, "once"),
            Self::Daily => write!(f, "daily"),
            Self::Weekly => write!(f, "weekly"),
            Self::Monthly => write!(f, "monthly"),
        }
    }
}

/// Full row from `maintenance_windows`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MaintenanceWindow {
    pub id: Uuid,
    pub host_id: Uuid,
    pub label: String,
    pub recurrence: WindowRecurrence,
    /// Absolute start time (one-time) or time-of-day reference (recurring).
    pub start_at: DateTime<Utc>,
    /// Duration of the window in minutes.
    pub duration_minutes: i32,
    /// Day-of-week (0=Sun, weekly) or day-of-month (1-31, monthly); NULL for once/daily.
    pub recurrence_day: Option<i32>,
    pub enabled: bool,
    pub auto_apply: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Payload for `POST /api/v1/hosts/{id}/maintenance-windows`.
#[derive(Debug, Deserialize)]
pub struct CreateMaintenanceWindowRequest {
    pub label: String,
    pub recurrence: WindowRecurrence,
    /// RFC 3339 / ISO 8601 timestamp (UTC recommended).
    pub start_at: DateTime<Utc>,
    /// How many minutes the window is open (default 60).
    pub duration_minutes: Option<i32>,
    /// Required for `weekly` (0-6) and `monthly` (1-31).
    pub recurrence_day: Option<i32>,
    /// Whether the window is active (default true).
    pub enabled: Option<bool>,
    /// Whether to auto-create a patch_apply job when this window opens and patches are pending (default true).
    pub auto_apply: Option<bool>,
}

/// Payload for `PUT /api/v1/hosts/{id}/maintenance-windows/{window_id}`.
#[derive(Debug, Deserialize)]
pub struct UpdateMaintenanceWindowRequest {
    pub label: Option<String>,
    pub recurrence: Option<WindowRecurrence>,
    pub start_at: Option<DateTime<Utc>>,
    pub duration_minutes: Option<i32>,
    pub recurrence_day: Option<i32>,
    pub enabled: Option<bool>,
    pub auto_apply: Option<bool>,
}

// ============================================================
// Available Versions (cached release info)
// ============================================================

/// A cached release version from GitHub or custom URL.
/// Mirrors the `available_versions` table.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AvailableVersion {
    pub id: Uuid,
    pub version: String,
    pub download_url: String,
    pub checksum: Option<String>,
    pub file_name: String,
    pub source: String,
    pub prerelease: bool,
    pub published_at: Option<DateTime<Utc>>,
    pub fetched_at: DateTime<Utc>,
}

// ============================================================
// OsPackageMapping
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OsPackageMapping {
    pub id: Uuid,
    pub os_name: String,
    pub os_version: String,
    pub package_pattern: String,
    pub display_name: String,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOsPackageMapping {
    pub os_name: String,
    pub os_version: String,
    pub package_pattern: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOsPackageMapping {
    pub package_pattern: Option<String>,
    pub display_name: Option<String>,
}
