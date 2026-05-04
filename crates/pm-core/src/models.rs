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
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Operator => write!(f, "operator"),
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
}

impl std::fmt::Display for AuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::AzureSso => write!(f, "azure_sso"),
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
    pub patches_missing: i64,
    pub registered_at: DateTime<Utc>,
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
}
