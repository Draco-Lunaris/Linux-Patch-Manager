//! Audit log helper functions.
//!
//! Writes tamper-evident, hash-chained audit events to the `audit_log` table.
//! The hash chain: each row's `row_hash` = SHA-256(prev_row_hash || action || target_id || created_at).

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

/// Audit event categories (must match the `audit_action` PostgreSQL ENUM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    UserLogin,
    UserLogout,
    UserLoginFailed,
    UserCreated,
    UserDeleted,
    UserUpdated,
    HostRegistered,
    HostRemoved,
    GroupCreated,
    GroupDeleted,
    GroupMembershipChanged,
    PatchJobCreated,
    PatchJobCancelled,
    PatchJobRollback,
    MaintenanceWindowCreated,
    MaintenanceWindowUpdated,
    MaintenanceWindowDeleted,
    CertificateIssued,
    CertificateRenewed,
    CertificateRevoked,
    CertificateDownloaded,
    ConfigChanged,
    DiscoveryScanStarted,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserLogin => "user_login",
            Self::UserLogout => "user_logout",
            Self::UserLoginFailed => "user_login_failed",
            Self::UserCreated => "user_created",
            Self::UserDeleted => "user_deleted",
            Self::UserUpdated => "user_updated",
            Self::HostRegistered => "host_registered",
            Self::HostRemoved => "host_removed",
            Self::GroupCreated => "group_created",
            Self::GroupDeleted => "group_deleted",
            Self::GroupMembershipChanged => "group_membership_changed",
            Self::PatchJobCreated => "patch_job_created",
            Self::PatchJobCancelled => "patch_job_cancelled",
            Self::PatchJobRollback => "patch_job_rollback",
            Self::MaintenanceWindowCreated => "maintenance_window_created",
            Self::MaintenanceWindowUpdated => "maintenance_window_updated",
            Self::MaintenanceWindowDeleted => "maintenance_window_deleted",
            Self::CertificateIssued => "certificate_issued",
            Self::CertificateRenewed => "certificate_renewed",
            Self::CertificateRevoked => "certificate_revoked",
            Self::CertificateDownloaded => "certificate_downloaded",
            Self::ConfigChanged => "config_changed",
            Self::DiscoveryScanStarted => "discovery_scan_started",
        }
    }
}

/// Write an audit event to the database.
///
/// Computes a hash chain entry using the previous row's hash.
/// Non-fatal: logs errors but does not propagate them to avoid
/// disrupting the primary operation.
pub async fn log_event(
    pool: &PgPool,
    action: AuditAction,
    actor_user_id: Option<Uuid>,
    actor_username: Option<&str>,
    target_type: Option<&str>,
    target_id: Option<&str>,
    details: serde_json::Value,
    ip_address: Option<IpAddr>,
    request_id: Option<&str>,
) {
    let result = write_audit_row(
        pool, action, actor_user_id, actor_username,
        target_type, target_id, details, ip_address, request_id,
    )
    .await;

    if let Err(e) = result {
        tracing::error!(error = %e, action = action.as_str(), "Failed to write audit log");
    }
}

async fn write_audit_row(
    pool: &PgPool,
    action: AuditAction,
    actor_user_id: Option<Uuid>,
    actor_username: Option<&str>,
    target_type: Option<&str>,
    target_id: Option<&str>,
    details: serde_json::Value,
    ip_address: Option<IpAddr>,
    request_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    // Fetch previous hash for chain
    let prev_hash: Option<String> = sqlx::query_scalar(
        "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    let prev = prev_hash.unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339();
    let action_str = action.as_str();
    let tid = target_id.unwrap_or("");

    // Hash: SHA-256(prev_hash + action + target_id + timestamp)
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(action_str.as_bytes());
    hasher.update(tid.as_bytes());
    hasher.update(now.as_bytes());
    let row_hash = hex::encode(hasher.finalize());

    let ip_str = ip_address.map(|ip| ip.to_string());

    sqlx::query(
        r#"
        INSERT INTO audit_log
            (action, actor_user_id, actor_username, target_type, target_id,
             details, ip_address, request_id, row_hash)
        VALUES
            ($1::audit_action, $2, $3, $4, $5, $6, $7::inet, $8, $9)
        "#,
    )
    .bind(action_str)
    .bind(actor_user_id)
    .bind(actor_username)
    .bind(target_type)
    .bind(target_id)
    .bind(details)
    .bind(ip_str)
    .bind(request_id)
    .bind(&row_hash)
    .execute(pool)
    .await?;

    Ok(())
}
