//! Fleet status routes.
//!
//! GET /api/v1/status/fleet — aggregate health and patch summary across all hosts.

use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use serde::Serialize;
use serde_json::{json, Value};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/fleet", get(fleet_status))
}

// ── Response type ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FleetStatus {
    pub total_hosts: i64,
    pub healthy: i64,
    pub degraded: i64,
    pub unreachable: i64,
    pub pending: i64,
    pub total_pending_patches: i64,
    pub hosts_requiring_reboot: i64,
    pub compliance_pct: f64,
    /// Hosts with CRL status 'valid'.
    pub crl_valid: i64,
    /// Hosts with CRL status 'expired'.
    pub crl_expired: i64,
    /// Hosts with CRL status 'missing' (agent reports missing CRL).
    pub crl_missing: i64,
    /// Hosts with CRL status 'invalid' (security event — needs immediate attention).
    pub crl_invalid: i64,
    /// Hosts not reporting CRL status (older agents or no data yet).
    pub crl_not_reporting: i64,
    /// Health checks currently in a failed state (latest result is unhealthy).
    pub failed_health_checks: i64,
}

// ── GET /api/v1/status/fleet ──────────────────────────────────────────────────

pub async fn fleet_status(
    State(state): State<AppState>,
) -> Result<Json<FleetStatus>, (StatusCode, Json<Value>)> {
    // ── 1. Host health aggregates ─────────────────────────────────────────
    let health_row: (i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*)                                                     AS total_hosts,
            COUNT(*) FILTER (WHERE health_status = 'healthy')            AS healthy,
            COUNT(*) FILTER (WHERE health_status = 'degraded')           AS degraded,
            COUNT(*) FILTER (WHERE health_status = 'unreachable')        AS unreachable,
            COUNT(*) FILTER (WHERE health_status = 'pending')            AS pending
        FROM hosts
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "fleet_status: failed to query host health aggregates");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let (total_hosts, healthy, degraded, unreachable, pending) = health_row;

    // ── 2. Total pending patches across fleet (latest row per host) ───────
    let total_pending_patches: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(patch_count), 0)
        FROM (
            SELECT DISTINCT ON (host_id) patch_count
            FROM host_patch_data
            ORDER BY host_id, polled_at DESC
        ) latest
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "fleet_status: failed to query total pending patches");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    // ── 3. Hosts requiring a reboot (from system info pending_reboot flag) ──
    let hosts_requiring_reboot: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM hosts WHERE pending_reboot = true
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "fleet_status: failed to query reboot-required hosts");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    // ── 4. Compliance: hosts with zero pending patches / hosts with patch data
    // Hosts that have been polled and have patch_count == 0 are considered
    // compliant. Hosts with no patch data at all are excluded from the
    // compliance calculation (neither compliant nor non-compliant).
    let (compliant_hosts, polled_hosts): (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE patch_count = 0) AS compliant,
            COUNT(*)                                          AS polled
        FROM (
            SELECT DISTINCT ON (host_id) patch_count
            FROM host_patch_data
            ORDER BY host_id, polled_at DESC
        ) latest
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "fleet_status: failed to query compliant hosts");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let compliance_pct = if polled_hosts == 0 {
        100.0_f64
    } else {
        (compliant_hosts as f64 / polled_hosts as f64) * 100.0
    };

    // Round to one decimal place.
    let compliance_pct = (compliance_pct * 10.0).round() / 10.0;

    // ── 5. CRL status counts ────────────────────────────────────────────────
    let (crl_valid, crl_expired, crl_missing, crl_invalid, crl_not_reporting): (
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        r#"
            SELECT
                COALESCE(SUM(CASE WHEN crl_status = 'valid' THEN 1 END), 0),
                COALESCE(SUM(CASE WHEN crl_status = 'expired' THEN 1 END), 0),
                COALESCE(SUM(CASE WHEN crl_status = 'missing' THEN 1 END), 0),
                COALESCE(SUM(CASE WHEN crl_status = 'invalid' THEN 1 END), 0),
                COALESCE(SUM(CASE WHEN crl_status IS NULL THEN 1 END), 0)
            FROM hosts
            "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "fleet_status: failed to query CRL status counts");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    // ── 6. Failed health checks (latest result is unhealthy) ─────────────────
    let failed_health_checks: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM host_health_checks hc
        JOIN LATERAL (
            SELECT healthy
            FROM host_health_check_results r
            WHERE r.check_id = hc.id
            ORDER BY r.checked_at DESC
            LIMIT 1
        ) lr ON TRUE
        WHERE hc.enabled = TRUE AND lr.healthy = FALSE
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "fleet_status: failed to query failed health checks");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    Ok(Json(FleetStatus {
        total_hosts,
        healthy,
        degraded,
        unreachable,
        pending,
        total_pending_patches,
        hosts_requiring_reboot,
        compliance_pct,
        crl_valid,
        crl_expired,
        crl_missing,
        crl_invalid,
        crl_not_reporting,
        failed_health_checks,
    }))
}
