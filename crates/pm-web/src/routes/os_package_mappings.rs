//! OS package mapping management routes.
//!
//! GET    /api/v1/settings/os-package-mappings     — list all mappings (admin only)
//! POST   /api/v1/settings/os-package-mappings     — create a mapping (admin only)
//! PUT    /api/v1/settings/os-package-mappings/:id  — update a mapping (admin only)
//! DELETE /api/v1/settings/os-package-mappings/:id  — delete a mapping (admin only)

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
    models::{CreateOsPackageMapping, OsPackageMapping, UpdateOsPackageMapping},
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

// ============================================================
// Router
// ============================================================

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_mappings).post(create_mapping))
        .route("/{id}", put(update_mapping).delete(delete_mapping))
}

// ============================================================
// Helpers
// ============================================================

fn admin_required(auth: &AuthUser) -> Result<(), (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({ "error": { "code": "forbidden_role", "message": "Admin role required" } }),
            ),
        ));
    }
    Ok(())
}

fn db_error(e: &sqlx::Error) -> (StatusCode, Json<Value>) {
    tracing::error!(error = %e, "Database error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
    )
}

// ============================================================
// Handlers
// ============================================================

async fn list_mappings(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    let mappings: Vec<OsPackageMapping> =
        sqlx::query_as("SELECT id, os_name, os_version, package_pattern, display_name, is_default, created_at, updated_at FROM os_package_mappings ORDER BY os_name, os_version")
            .fetch_all(&state.db)
            .await
            .map_err(|e| db_error(&e))?;

    Ok(Json(serde_json::to_value(&mappings).unwrap_or(json!([]))))
}

async fn create_mapping(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateOsPackageMapping>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    let mapping: OsPackageMapping = sqlx::query_as(
        "INSERT INTO os_package_mappings (os_name, os_version, package_pattern, display_name) VALUES ($1, $2, $3, $4) RETURNING id, os_name, os_version, package_pattern, display_name, is_default, created_at, updated_at"
    )
    .bind(&req.os_name)
    .bind(&req.os_version)
    .bind(&req.package_pattern)
    .bind(&req.display_name)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.constraint() == Some("os_package_mappings_os_name_os_version_key") {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": { "code": "conflict", "message": "A mapping for this OS name and version already exists" } })),
                );
            }
        }
        db_error(&e)
    })?;

    log_event(
        &state.db,
        AuditAction::OsPackageMappingCreated,
        Some(auth.user_id),
        Some(&auth.username),
        Some("os_package_mapping"),
        Some(&mapping.id.to_string()),
        json!({ "os_name": req.os_name, "os_version": req.os_version }),
        None,
        None,
    )
    .await;

    Ok(Json(serde_json::to_value(&mapping).unwrap_or(json!({}))))
}

async fn update_mapping(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateOsPackageMapping>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    let mapping: Option<OsPackageMapping> = sqlx::query_as(
        "UPDATE os_package_mappings SET package_pattern = COALESCE($1, package_pattern), display_name = COALESCE($2, display_name), updated_at = NOW() WHERE id = $3 RETURNING id, os_name, os_version, package_pattern, display_name, is_default, created_at, updated_at"
    )
    .bind(&req.package_pattern)
    .bind(&req.display_name)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| db_error(&e))?;

    let mapping = mapping.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "error": { "code": "not_found", "message": "OS package mapping not found" } }),
            ),
        )
    })?;

    log_event(
        &state.db,
        AuditAction::OsPackageMappingUpdated,
        Some(auth.user_id),
        Some(&auth.username),
        Some("os_package_mapping"),
        Some(&id.to_string()),
        json!({ "package_pattern": req.package_pattern, "display_name": req.display_name }),
        None,
        None,
    )
    .await;

    Ok(Json(serde_json::to_value(&mapping).unwrap_or(json!({}))))
}

async fn delete_mapping(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    // Check if mapping exists and is not a default
    let mapping: Option<OsPackageMapping> = sqlx::query_as(
        "SELECT id, os_name, os_version, package_pattern, display_name, is_default, created_at, updated_at FROM os_package_mappings WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| db_error(&e))?;

    let mapping = mapping.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "OS package mapping not found" } })),
        )
    })?;

    if mapping.is_default {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({ "error": { "code": "forbidden", "message": "Default OS package mappings cannot be deleted" } }),
            ),
        ));
    }

    sqlx::query("DELETE FROM os_package_mappings WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| db_error(&e))?;

    log_event(
        &state.db,
        AuditAction::OsPackageMappingDeleted,
        Some(auth.user_id),
        Some(&auth.username),
        Some("os_package_mapping"),
        Some(&id.to_string()),
        json!({ "os_name": mapping.os_name, "os_version": mapping.os_version }),
        None,
        None,
    )
    .await;

    Ok(Json(json!({ "message": "Mapping deleted" })))
}
