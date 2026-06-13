//! Audit log helper functions.
//!
//! Writes tamper-evident, hash-chained audit events to the `audit_log` table.
//! The hash chain: each row's `row_hash` = SHA-256(
//!   prev_hash || action || actor_user_id || actor_username ||
//!   target_type || target_id || details_json || ip_address ||
//!   request_id || created_at
//! ).
//!
//! The `prev_hash` column stores the previous row's `row_hash` for chain
//! verification.  The first row has `prev_hash = ''`.

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
    // M11 additions
    AuditIntegrityVerified,
    EmailNotificationSent,
    PatchJobCompleted,
    PatchJobFailed,
    MaintenanceWindowReminder,
    HealthCheckCreated,
    HealthCheckUpdated,
    HealthCheckDeleted,
    CertificateReissued,
    // Issue #5: Manager-wide auth-config mutations (Admin-only)
    OidcConfigUpdated,
    SmtpConfigUpdated,
    IpWhitelistUpdated,
    TrustedProxiesUpdated,
    OidcTestPerformed,
    OidcDiscoverPerformed,
    // CRL health aggregation events (system-initiated)
    CrlStatusChanged,
    CrlStaleDetected,
    CrlInvalid,
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
            Self::AuditIntegrityVerified => "audit_integrity_verified",
            Self::EmailNotificationSent => "email_notification_sent",
            Self::PatchJobCompleted => "patch_job_completed",
            Self::PatchJobFailed => "patch_job_failed",
            Self::MaintenanceWindowReminder => "maintenance_window_reminder",
            Self::HealthCheckCreated => "health_check_created",
            Self::HealthCheckUpdated => "health_check_updated",
            Self::HealthCheckDeleted => "health_check_deleted",
            Self::CertificateReissued => "certificate_reissued",
            // Issue #5: Manager-wide auth-config mutations (Admin-only)
            Self::OidcConfigUpdated => "oidc_config_updated",
            Self::SmtpConfigUpdated => "smtp_config_updated",
            Self::IpWhitelistUpdated => "ip_whitelist_updated",
            Self::TrustedProxiesUpdated => "trusted_proxies_updated",
            Self::OidcTestPerformed => "oidc_test_performed",
            Self::OidcDiscoverPerformed => "oidc_discover_performed",
            // CRL health aggregation events
            Self::CrlStatusChanged => "crl_status_changed",
            Self::CrlStaleDetected => "crl_stale_detected",
            Self::CrlInvalid => "crl_invalid",
        }
    }
}

/// Write an audit event to the database.
///
/// Computes a hash chain entry using the previous row's hash.
/// Non-fatal: logs errors but does not propagate them to avoid
/// disrupting the primary operation.
#[allow(clippy::too_many_arguments)]
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
        pool,
        action,
        actor_user_id,
        actor_username,
        target_type,
        target_id,
        details,
        ip_address,
        request_id,
    )
    .await;

    if let Err(e) = result {
        tracing::error!(error = %e, action = action.as_str(), "Failed to write audit log");
    }
}

#[allow(clippy::too_many_arguments)]
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
    let prev_hash: Option<String> =
        sqlx::query_scalar("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;

    let prev = prev_hash.unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let action_str = action.as_str();
    let uid_str = actor_user_id.map(|u| u.to_string()).unwrap_or_default();
    let uname = actor_username.unwrap_or("");
    let ttype = target_type.unwrap_or("");
    let tid = target_id.unwrap_or("");
    let details_str = serde_json::to_string(&details).unwrap_or_default();
    let ip_str = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    let rid = request_id.unwrap_or("");

    // Hash: SHA-256(prev_hash + action + actor_user_id + actor_username +
    //              target_type + target_id + details_json + ip_address +
    //              request_id + created_at)
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(action_str.as_bytes());
    hasher.update(uid_str.as_bytes());
    hasher.update(uname.as_bytes());
    hasher.update(ttype.as_bytes());
    hasher.update(tid.as_bytes());
    hasher.update(details_str.as_bytes());
    hasher.update(ip_str.as_bytes());
    hasher.update(rid.as_bytes());
    hasher.update(now.as_bytes());
    let row_hash = hex::encode(hasher.finalize());

    let ip_for_db = ip_address.map(|ip| ip.to_string());

    sqlx::query(
        r#"
        INSERT INTO audit_log
            (action, actor_user_id, actor_username, target_type, target_id,
             details, ip_address, request_id, created_at, row_hash, prev_hash)
        VALUES
            ($1::audit_action, $2, $3, $4, $5, $6, $7::inet, $8, $9::timestamptz, $10, $11)
        "#,
    )
    .bind(action_str)
    .bind(actor_user_id)
    .bind(actor_username)
    .bind(target_type)
    .bind(target_id)
    .bind(details)
    .bind(ip_for_db)
    .bind(request_id)
    .bind(&now)
    .bind(&row_hash)
    .bind(&prev)
    .execute(pool)
    .await?;

    Ok(())
}

/// Result of an audit integrity verification pass.
#[derive(Debug, serde::Serialize)]
pub struct IntegrityResult {
    /// Whether the chain is intact (no tampering detected).
    pub intact: bool,
    /// Total number of rows checked.
    pub rows_checked: i64,
    /// List of errors found (row id, expected hash, actual hash).
    pub errors: Vec<IntegrityError>,
}

/// A single integrity error detected in the audit chain.
#[derive(Debug, serde::Serialize)]
pub struct IntegrityError {
    pub row_id: i64,
    pub expected_hash: String,
    pub actual_hash: String,
}

/// Row read from audit_log for integrity verification.
#[derive(Debug, sqlx::FromRow)]
struct AuditRow {
    id: i64,
    action: String,
    actor_user_id: Option<uuid::Uuid>,
    actor_username: Option<String>,
    target_type: Option<String>,
    target_id: Option<String>,
    details: Option<serde_json::Value>,
    ip_address: Option<String>,
    request_id: Option<String>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    row_hash: String,
    prev_hash: String,
}

/// Walk the audit_log rows ordered by id and verify each row_hash matches
/// the recomputed hash. Returns an [`IntegrityResult`] describing any
/// tampering detected.
pub async fn verify_integrity(pool: &PgPool) -> IntegrityResult {
    let rows: Vec<AuditRow> = match sqlx::query_as(
        r#"
        SELECT id, action::text AS action, actor_user_id, actor_username,
               target_type, target_id, details,
               host(ip_address) AS ip_address,
               request_id, created_at, row_hash, prev_hash
        FROM audit_log
        ORDER BY id ASC
        "#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "verify_integrity: failed to fetch audit rows");
            return IntegrityResult {
                intact: false,
                rows_checked: 0,
                errors: vec![],
            };
        },
    };

    let mut errors = Vec::new();
    let mut expected_prev_hash = String::new();

    for row in &rows {
        // Verify prev_hash linkage
        if row.prev_hash != expected_prev_hash {
            errors.push(IntegrityError {
                row_id: row.id,
                expected_hash: expected_prev_hash.clone(),
                actual_hash: row.prev_hash.clone(),
            });
        }

        // Recompute the row hash from all fields
        let uid_str = row.actor_user_id.map(|u| u.to_string()).unwrap_or_default();
        let uname = row.actor_username.as_deref().unwrap_or("");
        let ttype = row.target_type.as_deref().unwrap_or("");
        let tid = row.target_id.as_deref().unwrap_or("");
        let details_str = row
            .details
            .as_ref()
            .and_then(|v| serde_json::to_string(v).ok())
            .unwrap_or_default();
        let ip_str = row.ip_address.as_deref().unwrap_or("");
        let rid = row.request_id.as_deref().unwrap_or("");
        let created_str = row
            .created_at
            .map(|c| c.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
            .unwrap_or_default();

        let mut hasher = Sha256::new();
        hasher.update(row.prev_hash.as_bytes());
        hasher.update(row.action.as_bytes());
        hasher.update(uid_str.as_bytes());
        hasher.update(uname.as_bytes());
        hasher.update(ttype.as_bytes());
        hasher.update(tid.as_bytes());
        hasher.update(details_str.as_bytes());
        hasher.update(ip_str.as_bytes());
        hasher.update(rid.as_bytes());
        hasher.update(created_str.as_bytes());
        let computed_hash = hex::encode(hasher.finalize());

        if row.row_hash != computed_hash {
            errors.push(IntegrityError {
                row_id: row.id,
                expected_hash: computed_hash,
                actual_hash: row.row_hash.clone(),
            });
        }

        // Next row should have this row's hash as prev_hash
        expected_prev_hash = row.row_hash.clone();
    }

    let intact = errors.is_empty();
    let rows_checked = rows.len() as i64;

    IntegrityResult {
        intact,
        rows_checked,
        errors,
    }
}
