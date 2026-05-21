//! Periodic audit log integrity verification.
//!
//! Runs every 24 hours, walks the audit_log rows ordered by id,
//! verifies each row_hash matches the recomputed hash, and logs the
//! result as an `AuditIntegrityVerified` event. If tampering is
//! detected, logs an error and creates an alert.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

use pm_core::audit::{log_event, verify_integrity, AuditAction};
use pm_core::config::AppConfig;

/// Run the audit integrity verifier every 24 hours.
pub async fn run_audit_verifier(pool: PgPool, _config: Arc<AppConfig>) {
    tracing::info!("Audit integrity verifier started");

    // Run immediately on startup
    verify_once(&pool).await;

    let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    loop {
        interval.tick().await;
        tracing::info!("Running scheduled audit integrity verification");
        verify_once(&pool).await;
    }
}

/// Run a single integrity verification pass.
async fn verify_once(pool: &PgPool) {
    let result = verify_integrity(pool).await;

    if result.intact {
        tracing::info!(
            rows_checked = result.rows_checked,
            "Audit integrity verification passed"
        );
    } else {
        tracing::error!(
            rows_checked = result.rows_checked,
            error_count = result.errors.len(),
            "Audit integrity verification FAILED — tampering detected!"
        );

        for err in &result.errors {
            tracing::error!(
                row_id = err.row_id,
                expected_hash = %err.expected_hash,
                actual_hash = %err.actual_hash,
                "Audit chain integrity error"
            );
        }
    }

    // Log the verification event
    log_event(
        pool,
        AuditAction::AuditIntegrityVerified,
        None,
        None,
        Some("audit_log"),
        None,
        serde_json::json!({
            "intact": result.intact,
            "rows_checked": result.rows_checked,
            "error_count": result.errors.len(),
            "errors": result.errors.iter().take(10).map(|e| serde_json::json!({
                "row_id": e.row_id,
                "expected_hash": e.expected_hash,
                "actual_hash": e.actual_hash,
            })).collect::<Vec<_>>(),
        }),
        None,
        None,
    )
    .await;

    // Update last verified timestamp
    let _ = sqlx::query(
        "UPDATE system_config SET value = NOW()::text, updated_at = NOW() WHERE key = 'audit_integrity_last_verified'",
    )
    .execute(pool)
    .await;
}
