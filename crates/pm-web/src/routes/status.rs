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

    // ── 3. Hosts requiring a reboot (latest patch row per host) ───────────
    let hosts_requiring_reboot: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM (
            SELECT DISTINCT ON (host_id) available_patches
            FROM host_patch_data
            ORDER BY host_id, polled_at DESC
        ) latest
        WHERE available_patches @> '[{"requires_reboot": true}]'
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

    // ── 4. Compliance: hosts with zero pending patches / total hosts ───────
    // Hosts that have been polled and have patch_count == 0 are considered
    // compliant. Hosts with no patch data at all are excluded from the
    // compliance calculation.
    let compliant_hosts: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM (
            SELECT DISTINCT ON (host_id) patch_count
            FROM host_patch_data
            ORDER BY host_id, polled_at DESC
        ) latest
        WHERE patch_count = 0
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

    let compliance_pct = if total_hosts == 0 {
        100.0_f64
    } else {
        (compliant_hosts as f64 / total_hosts as f64) * 100.0
    };

    // Round to one decimal place.
    let compliance_pct = (compliance_pct * 10.0).round() / 10.0;

    Ok(Json(FleetStatus {
        total_hosts,
        healthy,
        degraded,
        unreachable,
        pending,
        total_pending_patches,
        hosts_requiring_reboot,
        compliance_pct,
    }))
}
