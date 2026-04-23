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
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Operator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "auth_provider", rename_all = "snake_case")]
pub enum AuthProvider {
    Local,
    #[sqlx(rename = "azure_sso")]
    AzureSso,
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
