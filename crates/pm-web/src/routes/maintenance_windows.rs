//! Maintenance window management routes.
//!
//! GET    /api/v1/hosts/{id}/maintenance-windows           — list windows for host
//! POST   /api/v1/hosts/{id}/maintenance-windows           — create window for host
//! PUT    /api/v1/hosts/{id}/maintenance-windows/{win_id}  — update window
//! DELETE /api/v1/hosts/{id}/maintenance-windows/{win_id}  — delete window

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, put},
    Router,
};
use pm_auth::rbac::AuthUser;
use pm_core::{
    audit::{log_event, AuditAction},
    models::{CreateMaintenanceWindowRequest, MaintenanceWindow, UpdateMaintenanceWindowRequest},
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

// ── Router ────────────────────────────────────────────────────────────────────

/// Mount as a nested router under `/hosts/{host_id}/maintenance-windows`.
/// Axum will merge the `{host_id}` path segment from the parent nest.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_windows).post(create_window))
        .route("/{win_id}", put(update_window).delete(delete_window))
}

// ── Error helper ──────────────────────────────────────────────────────────────

#[inline]
fn err(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
}

// ── GET /api/v1/hosts/:host_id/maintenance-windows ────────────────────────────

async fn list_windows(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(host_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Verify host exists.
    let host_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM hosts WHERE id = $1)")
        .bind(host_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %host_id, "list_windows: host existence check failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Database error",
            )
        })?;

    if !host_exists {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "Host not found"));
    }

    let windows: Vec<MaintenanceWindow> = sqlx::query_as(
        r#"
        SELECT id, host_id, label, recurrence, start_at, duration_minutes,
               recurrence_day, enabled, auto_apply, created_at, updated_at
        FROM   maintenance_windows
        WHERE  host_id = $1
        ORDER  BY created_at ASC
        "#,
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %host_id, "list_windows: query failed");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    Ok(Json(json!({ "windows": windows })))
}

// ── POST /api/v1/hosts/:host_id/maintenance-windows ───────────────────────────

async fn create_window(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(host_id): Path<Uuid>,
    Json(req): Json<CreateMaintenanceWindowRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Validate: weekly requires recurrence_day 0-6
    if req.recurrence == pm_core::models::WindowRecurrence::Weekly {
        match req.recurrence_day {
            Some(d) if (0..=6).contains(&d) => {},
            _ => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "Weekly recurrence requires recurrence_day 0-6 (0=Sunday)",
                ));
            },
        }
    }

    // Validate: monthly requires recurrence_day 1-31
    if req.recurrence == pm_core::models::WindowRecurrence::Monthly {
        match req.recurrence_day {
            Some(d) if (1..=31).contains(&d) => {},
            _ => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "Monthly recurrence requires recurrence_day 1-31",
                ));
            },
        }
    }

    // Verify host exists.
    let host_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM hosts WHERE id = $1)")
        .bind(host_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %host_id, "create_window: host existence check failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Database error",
            )
        })?;

    if !host_exists {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "Host not found"));
    }

    let duration = req.duration_minutes.unwrap_or(60);
    let enabled = req.enabled.unwrap_or(true);
    let auto_apply = req.auto_apply.unwrap_or(true);

    let window: MaintenanceWindow = sqlx::query_as(
        r#"
        INSERT INTO maintenance_windows
            (host_id, label, recurrence, start_at, duration_minutes, recurrence_day, enabled, auto_apply)
        VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, host_id, label, recurrence, start_at, duration_minutes,
                  recurrence_day, enabled, auto_apply, created_at, updated_at
        "#,
    )
    .bind(host_id)
    .bind(&req.label)
    .bind(&req.recurrence)
    .bind(req.start_at)
    .bind(duration)
    .bind(req.recurrence_day)
    .bind(enabled)
    .bind(auto_apply)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %host_id, "create_window: insert failed");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    log_event(
        &state.db,
        AuditAction::MaintenanceWindowCreated,
        Some(auth.user_id),
        Some(&auth.username),
        Some("maintenance_window"),
        Some(&window.id.to_string()),
        json!({
            "host_id": host_id,
            "label": window.label,
            "recurrence": window.recurrence.to_string(),
        }),
        None,
        None,
    )
    .await;

    tracing::info!(
        window_id = %window.id,
        %host_id,
        recurrence = %window.recurrence,
        user = %auth.username,
        "Maintenance window created"
    );

    Ok(Json(json!(window)))
}

// ── PUT /api/v1/hosts/:host_id/maintenance-windows/:win_id ───────────────────

async fn update_window(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((host_id, win_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateMaintenanceWindowRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Fetch existing record (verify ownership and existence).
    let existing: Option<MaintenanceWindow> = sqlx::query_as(
        r#"
        SELECT id, host_id, label, recurrence, start_at, duration_minutes,
               recurrence_day, enabled, auto_apply, created_at, updated_at
        FROM   maintenance_windows
        WHERE  id = $1 AND host_id = $2
        "#,
    )
    .bind(win_id)
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %win_id, "update_window: fetch failed");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    let existing = existing.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "not_found",
            "Maintenance window not found",
        )
    })?;

    // Apply partial updates using existing values as defaults.
    let new_label = req.label.unwrap_or(existing.label);
    let new_recurrence = req.recurrence.unwrap_or(existing.recurrence);
    let new_start_at = req.start_at.unwrap_or(existing.start_at);
    let new_duration = req.duration_minutes.unwrap_or(existing.duration_minutes);
    let new_rec_day = req.recurrence_day.or(existing.recurrence_day);
    let new_enabled = req.enabled.unwrap_or(existing.enabled);
    let new_auto_apply = req.auto_apply.unwrap_or(existing.auto_apply);

    // Validate recurrence_day for the final recurrence type.
    if new_recurrence == pm_core::models::WindowRecurrence::Weekly {
        match new_rec_day {
            Some(d) if (0..=6).contains(&d) => {},
            _ => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "Weekly recurrence requires recurrence_day 0-6",
                ));
            },
        }
    }
    if new_recurrence == pm_core::models::WindowRecurrence::Monthly {
        match new_rec_day {
            Some(d) if (1..=31).contains(&d) => {},
            _ => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "Monthly recurrence requires recurrence_day 1-31",
                ));
            },
        }
    }

    let updated: MaintenanceWindow = sqlx::query_as(
        r#"
        UPDATE maintenance_windows
        SET    label          = $3,
               recurrence     = $4,
               start_at       = $5,
               duration_minutes = $6,
               recurrence_day = $7,
               enabled        = $8,
               auto_apply     = $9,
               updated_at     = NOW()
        WHERE  id = $1 AND host_id = $2
        RETURNING id, host_id, label, recurrence, start_at, duration_minutes,
                  recurrence_day, enabled, auto_apply, created_at, updated_at
        "#,
    )
    .bind(win_id)
    .bind(host_id)
    .bind(&new_label)
    .bind(&new_recurrence)
    .bind(new_start_at)
    .bind(new_duration)
    .bind(new_rec_day)
    .bind(new_enabled)
    .bind(new_auto_apply)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %win_id, "update_window: update failed");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    log_event(
        &state.db,
        AuditAction::MaintenanceWindowUpdated,
        Some(auth.user_id),
        Some(&auth.username),
        Some("maintenance_window"),
        Some(&win_id.to_string()),
        json!({ "host_id": host_id }),
        None,
        None,
    )
    .await;

    tracing::info!(
        window_id = %win_id,
        %host_id,
        user = %auth.username,
        "Maintenance window updated"
    );

    Ok(Json(json!(updated)))
}

// ── DELETE /api/v1/hosts/:host_id/maintenance-windows/:win_id ────────────────

async fn delete_window(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((host_id, win_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = sqlx::query("DELETE FROM maintenance_windows WHERE id = $1 AND host_id = $2")
        .bind(win_id)
        .bind(host_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %win_id, "delete_window: delete failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Database error",
            )
        })?;

    if result.rows_affected() == 0 {
        return Err(err(
            StatusCode::NOT_FOUND,
            "not_found",
            "Maintenance window not found",
        ));
    }

    log_event(
        &state.db,
        AuditAction::MaintenanceWindowDeleted,
        Some(auth.user_id),
        Some(&auth.username),
        Some("maintenance_window"),
        Some(&win_id.to_string()),
        json!({ "host_id": host_id }),
        None,
        None,
    )
    .await;

    tracing::info!(
        window_id = %win_id,
        %host_id,
        user = %auth.username,
        "Maintenance window deleted"
    );

    Ok(Json(json!({ "message": "Maintenance window deleted" })))
}
