//! Health check management routes.
//!
//! GET    /api/v1/hosts/{host_id}/health-checks              — list health checks
//! POST   /api/v1/hosts/{host_id}/health-checks              — create health check
//! GET    /api/v1/hosts/{host_id}/health-checks/{check_id}   — get health check detail
//! PUT    /api/v1/hosts/{host_id}/health-checks/{check_id}   — update health check
//! DELETE /api/v1/hosts/{host_id}/health-checks/{check_id}   — delete health check
//! POST   /api/v1/hosts/{host_id}/health-checks/{check_id}/test — run check immediately

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use pm_auth::rbac::AuthUser;
use pm_core::{
    audit::{log_event, AuditAction},
    crypto,
    models::{
        CreateHealthCheckRequest, HealthCheck, HealthCheckResult, HealthCheckWithResult,
        UpdateHealthCheckRequest,
    },
};
use reqwest::tls::Version;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_health_checks).post(create_health_check))
        .route(
            "/{check_id}",
            get(get_health_check)
                .put(update_health_check)
                .delete(delete_health_check),
        )
        .route("/{check_id}/test", post(test_health_check))
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct HealthCheckListResponse {
    checks: Vec<HealthCheckWithResult>,
    total: i64,
}

#[derive(Debug, Serialize)]
struct HealthCheckTestResponse {
    healthy: bool,
    detail: String,
    latency_ms: Option<i32>,
}

// ── RBAC helper ──────────────────────────────────────────────────────────────

async fn operator_can_access_host(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    host_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let in_group: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM host_groups hg
            JOIN user_groups ug ON ug.group_id = hg.group_id
            WHERE hg.host_id = $1 AND ug.user_id = $2
        )
        "#,
    )
    .bind(host_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(false);

    if in_group {
        return Ok(true);
    }

    // Also allow if host has no groups (ungrouped)
    let has_groups: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM host_groups WHERE host_id = $1)")
            .bind(host_id)
            .fetch_one(pool)
            .await
            .unwrap_or(true);

    Ok(!has_groups)
}

// ── GET /api/v1/hosts/{host_id}/health-checks ────────────────────────────────

async fn list_health_checks(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(host_id): Path<Uuid>,
) -> Result<Json<HealthCheckListResponse>, (StatusCode, Json<Value>)> {
    // RBAC check for operators
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, host_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "RBAC check failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                )
            })?;
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    json!({ "error": { "code": "forbidden", "message": "Not authorized for this host" } }),
                ),
            ));
        }
    }

    // Verify host exists
    let host_exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM hosts WHERE id = $1)")
        .bind(host_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check host");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

    if !host_exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Host not found" } })),
        ));
    }

    // Fetch health checks with latest results
    let checks: Vec<HealthCheck> = sqlx::query_as::<_, HealthCheck>(
        r#"
        SELECT id, host_id, name, check_type, enabled,
               service_name, url, expected_body, ignore_cert_errors, basic_auth_user,
               target_host_id,
               created_at, updated_at
        FROM host_health_checks
        WHERE host_id = $1
        ORDER BY created_at
        "#,
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to list health checks");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let total = checks.len() as i64;

    // Fetch latest result for each check
    let mut checks_with_results = Vec::with_capacity(checks.len());
    for check in checks {
        let last_result: Option<HealthCheckResult> = sqlx::query_as::<_, HealthCheckResult>(
            r#"
            SELECT id, check_id, healthy, detail, latency_ms, checked_at
            FROM host_health_check_results
            WHERE check_id = $1
            ORDER BY checked_at DESC
            LIMIT 1
            "#,
        )
        .bind(check.id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get latest result");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        checks_with_results.push(HealthCheckWithResult { check, last_result });
    }

    Ok(Json(HealthCheckListResponse {
        checks: checks_with_results,
        total,
    }))
}

// ── POST /api/v1/hosts/{host_id}/health-checks ───────────────────────────────

async fn create_health_check(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(host_id): Path<Uuid>,
    Json(req): Json<CreateHealthCheckRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // RBAC check for operators
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, host_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "RBAC check failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                )
            })?;
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    json!({ "error": { "code": "forbidden", "message": "Not authorized for this host" } }),
                ),
            ));
        }
    }

    // Validate check_type
    if req.check_type != "service" && req.check_type != "http" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "invalid_check_type", "message": "check_type must be 'service' or 'http'" } }),
            ),
        ));
    }

    // Validate fields based on check_type
    if req.check_type == "service" && req.service_name.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "validation_error", "message": "service_name is required for service checks" } }),
            ),
        ));
    }
    if req.check_type == "http" && (req.url.is_none() || req.expected_body.is_none()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "validation_error", "message": "url and expected_body are required for http checks" } }),
            ),
        ));
    }

    // Validate target_host_id if provided
    if let Some(tid) = req.target_host_id {
        let target_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM hosts WHERE id = $1)",
        )
        .bind(tid)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check target host");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        if !target_exists {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": { "code": "invalid_target_host", "message": "Target host does not exist" } }),
                ),
            ));
        }

        let target_healthy: bool = sqlx::query_scalar(
            "SELECT health_status = 'healthy' FROM hosts WHERE id = $1",
        )
        .bind(tid)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check target host health");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        if !target_healthy {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": { "code": "invalid_target_host", "message": "Target host is not currently healthy" } }),
                ),
            ));
        }
    }

    // Enforce max 5 per host
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM host_health_checks WHERE host_id = $1",
    )
    .bind(host_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to count health checks");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    if count >= 5 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "limit_exceeded", "message": "Maximum 5 health checks per host" } }),
            ),
        ));
    }

    // Encrypt basic_auth_pass if provided
    let (pass_encrypted, pass_nonce) = if let Some(ref pass) = req.basic_auth_pass {
        let key_path = PathBuf::from(crypto::KEY_PATH);
        let key = crypto::load_or_create_key(&key_path).map_err(|e| {
            tracing::error!(error = %e, "Failed to load encryption key");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Encryption key error" } })),
            )
        })?;
        let (enc, nonce) = crypto::encrypt(pass, &key).map_err(|e| {
            tracing::error!(error = %e, "Failed to encrypt password");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "error": { "code": "internal_error", "message": "Encryption error" } }),
                ),
            )
        })?;
        (Some(enc), Some(nonce))
    } else {
        (None, None)
    };

    // Insert health check
    let check_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO host_health_checks (
            host_id, name, check_type, enabled,
            service_name, url, expected_body, ignore_cert_errors,
            basic_auth_user, basic_auth_pass_encrypted, basic_auth_pass_nonce,
            target_host_id
        ) VALUES ($1, $2, $3, true, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id
        "#,
    )
    .bind(host_id)
    .bind(&req.name)
    .bind(&req.check_type)
    .bind(&req.service_name)
    .bind(&req.url)
    .bind(&req.expected_body)
    .bind(req.ignore_cert_errors)
    .bind(&req.basic_auth_user)
    .bind(pass_encrypted)
    .bind(pass_nonce)
    .bind(req.target_host_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to create health check");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    // Audit log
    log_event(
        &state.db,
        AuditAction::HealthCheckCreated,
        Some(auth.user_id),
        None,
        Some("host"),
        Some(&host_id.to_string()),
        json!({
            "check_id": check_id,
            "name": req.name,
            "check_type": req.check_type,
            "target_host_id": req.target_host_id,
        }),
        None,
        None,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": check_id,
            "host_id": host_id,
            "name": req.name,
            "check_type": req.check_type,
            "enabled": true,
            "target_host_id": req.target_host_id,
        })),
    ))
}

// ── GET /api/v1/hosts/{host_id}/health-checks/{check_id} ──────────────────────

async fn get_health_check(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((host_id, check_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<HealthCheckWithResult>, (StatusCode, Json<Value>)> {
    // RBAC check for operators
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, host_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "RBAC check failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                )
            })?;
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    json!({ "error": { "code": "forbidden", "message": "Not authorized for this host" } }),
                ),
            ));
        }
    }

    let check: HealthCheck = sqlx::query_as::<_, HealthCheck>(
        r#"
        SELECT id, host_id, name, check_type, enabled,
               service_name, url, expected_body, ignore_cert_errors, basic_auth_user,
               target_host_id,
               created_at, updated_at
        FROM host_health_checks
        WHERE id = $1 AND host_id = $2
        "#,
    )
    .bind(check_id)
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to get health check");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Health check not found" } })),
        )
    })?;

    let last_result: Option<HealthCheckResult> = sqlx::query_as::<_, HealthCheckResult>(
        r#"
        SELECT id, check_id, healthy, detail, latency_ms, checked_at
        FROM host_health_check_results
        WHERE check_id = $1
        ORDER BY checked_at DESC
        LIMIT 1
        "#,
    )
    .bind(check_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to get latest result");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    Ok(Json(HealthCheckWithResult { check, last_result }))
}

// ── PUT /api/v1/hosts/{host_id}/health-checks/{check_id} ──────────────────────

async fn update_health_check(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((host_id, check_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateHealthCheckRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // RBAC check for operators
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, host_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "RBAC check failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                )
            })?;
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    json!({ "error": { "code": "forbidden", "message": "Not authorized for this host" } }),
                ),
            ));
        }
    }

    // Verify check exists and belongs to host
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM host_health_checks WHERE id = $1 AND host_id = $2)",
    )
    .bind(check_id)
    .bind(host_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to check health check");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Health check not found" } })),
        ));
    }

    // Validate target_host_id if provided
    if let Some(tid) = req.target_host_id {
        let target_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM hosts WHERE id = $1)",
        )
        .bind(tid)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check target host");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        if !target_exists {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": { "code": "invalid_target_host", "message": "Target host does not exist" } }),
                ),
            ));
        }

        let target_healthy: bool = sqlx::query_scalar(
            "SELECT health_status = 'healthy' FROM hosts WHERE id = $1",
        )
        .bind(tid)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check target host health");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        if !target_healthy {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": { "code": "invalid_target_host", "message": "Target host is not currently healthy" } }),
                ),
            ));
        }
    }

    // Handle basic_auth_pass encryption if provided
    let (pass_encrypted, pass_nonce) = if let Some(ref pass) = req.basic_auth_pass {
        let key_path = PathBuf::from(crypto::KEY_PATH);
        let key = crypto::load_or_create_key(&key_path).map_err(|e| {
            tracing::error!(error = %e, "Failed to load encryption key");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Encryption key error" } })),
            )
        })?;
        let (enc, nonce) = crypto::encrypt(pass, &key).map_err(|e| {
            tracing::error!(error = %e, "Failed to encrypt password");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "error": { "code": "internal_error", "message": "Encryption error" } }),
                ),
            )
        })?;
        (Some(enc), Some(nonce))
    } else {
        (None, None)
    };

    // Build dynamic UPDATE query
    let mut set_clauses = Vec::new();
    let mut param_idx = 1u32;

    if req.name.is_some() {
        set_clauses.push(format!("name = ${}", param_idx));
        param_idx += 1;
    }
    if req.enabled.is_some() {
        set_clauses.push(format!("enabled = ${}", param_idx));
        param_idx += 1;
    }
    if req.service_name.is_some() {
        set_clauses.push(format!("service_name = ${}", param_idx));
        param_idx += 1;
    }
    if req.url.is_some() {
        set_clauses.push(format!("url = ${}", param_idx));
        param_idx += 1;
    }
    if req.expected_body.is_some() {
        set_clauses.push(format!("expected_body = ${}", param_idx));
        param_idx += 1;
    }
    if req.ignore_cert_errors.is_some() {
        set_clauses.push(format!("ignore_cert_errors = ${}", param_idx));
        param_idx += 1;
    }
    if req.basic_auth_user.is_some() {
        set_clauses.push(format!("basic_auth_user = ${}", param_idx));
        param_idx += 1;
    }
    if pass_encrypted.is_some() {
        set_clauses.push(format!("basic_auth_pass_encrypted = ${}", param_idx));
        param_idx += 1;
        set_clauses.push(format!("basic_auth_pass_nonce = ${}", param_idx));
        param_idx += 1;
    }

    if set_clauses.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "validation_error", "message": "No fields to update" } }),
            ),
        ));
    }

    // Always update updated_at
    set_clauses.push(format!("updated_at = NOW()"));

    // Use a simpler approach: query the current row, apply changes, update
    // This avoids complex dynamic SQL binding issues
    let updated = sqlx::query(
        r#"
        UPDATE host_health_checks
        SET name        = COALESCE($3, name),
            enabled     = COALESCE($4, enabled),
            service_name = COALESCE($5, service_name),
            url         = COALESCE($6, url),
            expected_body = COALESCE($7, expected_body),
            ignore_cert_errors = COALESCE($8, ignore_cert_errors),
            basic_auth_user = COALESCE($9, basic_auth_user),
            basic_auth_pass_encrypted = COALESCE($10, basic_auth_pass_encrypted),
            basic_auth_pass_nonce = COALESCE($11, basic_auth_pass_nonce),
            target_host_id = COALESCE($12, target_host_id),
            updated_at  = NOW()
        WHERE id = $1 AND host_id = $2
    "#,
    )
    .bind(check_id)
    .bind(host_id)
    .bind(&req.name)
    .bind(req.enabled)
    .bind(&req.service_name)
    .bind(&req.url)
    .bind(&req.expected_body)
    .bind(req.ignore_cert_errors)
    .bind(&req.basic_auth_user)
    .bind(pass_encrypted)
    .bind(pass_nonce)
    .bind(req.target_host_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to update health check");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    if updated.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Health check not found" } })),
        ));
    }

    // Audit log
    log_event(
        &state.db,
        AuditAction::HealthCheckUpdated,
        Some(auth.user_id),
        None,
        Some("host"),
        Some(&host_id.to_string()),
        json!({ "check_id": check_id, "target_host_id": req.target_host_id }),
        None,
        None,
    )
    .await;

    Ok(Json(json!({ "id": check_id, "updated": true })))
}

// ── DELETE /api/v1/hosts/{host_id}/health-checks/{check_id} ───────────────────

async fn delete_health_check(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((host_id, check_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, Json<Value>)> {
    // RBAC check for operators
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, host_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "RBAC check failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                )
            })?;
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    json!({ "error": { "code": "forbidden", "message": "Not authorized for this host" } }),
                ),
            ));
        }
    }

    let deleted = sqlx::query("DELETE FROM host_health_checks WHERE id = $1 AND host_id = $2")
        .bind(check_id)
        .bind(host_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to delete health check");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

    if deleted.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Health check not found" } })),
        ));
    }

    // Audit log
    log_event(
        &state.db,
        AuditAction::HealthCheckDeleted,
        Some(auth.user_id),
        None,
        Some("host"),
        Some(&host_id.to_string()),
        json!({ "check_id": check_id }),
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /api/v1/hosts/{host_id}/health-checks/{check_id}/test ───────────────

async fn test_health_check(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((host_id, check_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<HealthCheckTestResponse>, (StatusCode, Json<Value>)> {
    // RBAC check for operators
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, host_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "RBAC check failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                )
            })?;
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    json!({ "error": { "code": "forbidden", "message": "Not authorized for this host" } }),
                ),
            ));
        }
    }

    // Get the health check
    let check: HealthCheck = sqlx::query_as::<_, HealthCheck>(
        r#"
        SELECT id, host_id, name, check_type, enabled,
               service_name, url, expected_body, ignore_cert_errors, basic_auth_user,
               target_host_id,
               created_at, updated_at
        FROM host_health_checks
        WHERE id = $1 AND host_id = $2
        "#,
    )
    .bind(check_id)
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to get health check");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Health check not found" } })),
        )
    })?;

    // Run the check
    let result = run_health_check(&check, &state).await;

    // Store the result
    sqlx::query(
        r#"
        INSERT INTO host_health_check_results (check_id, healthy, detail, latency_ms)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(check_id)
    .bind(result.healthy)
    .bind(&result.detail)
    .bind(result.latency_ms)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to store test result");
        // Don't fail the response, just log
    })
    .ok();

    Ok(Json(HealthCheckTestResponse {
        healthy: result.healthy,
        detail: result.detail,
        latency_ms: result.latency_ms,
    }))
}

// ── Health check execution ───────────────────────────────────────────────────

struct CheckResult {
    healthy: bool,
    detail: String,
    latency_ms: Option<i32>,
}

async fn run_health_check(check: &HealthCheck, state: &AppState) -> CheckResult {
    match check.check_type.as_str() {
        "service" => run_service_check(check, state).await,
        "http" => run_http_check(check, state).await,
        _ => CheckResult {
            healthy: false,
            detail: format!("Unknown check type: {}", check.check_type),
            latency_ms: None,
        },
    }
}

async fn run_service_check(check: &HealthCheck, state: &AppState) -> CheckResult {
    let service_name = match &check.service_name {
        Some(name) => name.clone(),
        None => {
            return CheckResult {
                healthy: false,
                detail: "No service_name configured".to_string(),
                latency_ms: None,
            }
        },
    };

    // Get host info for agent connection — use target_host_id if set, otherwise own host
    let effective_host_id = check.target_host_id.unwrap_or(check.host_id);
    let host_info: Option<(String, i32)> = sqlx::query_as::<_, (String, i32)>(
        "SELECT host(ip_address)::text, agent_port FROM hosts WHERE id = $1",
    )
    .bind(effective_host_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let (ip, agent_port) = match host_info {
        Some(info) => info,
        None => {
            return CheckResult {
                healthy: false,
                detail: "Host not found".to_string(),
                latency_ms: None,
            }
        },
    };

    // Build agent URL
    let agent_url = format!(
        "https://{}:{}/api/v1/system/services/{}",
        ip, agent_port, service_name
    );

    let start = std::time::Instant::now();

    // Make mTLS request to agent using reqwest with client certs
    let client = match build_agent_http_client(state) {
        Ok(c) => c,
        Err(e) => {
            return CheckResult {
                healthy: false,
                detail: format!("Failed to build HTTP client: {}", e),
                latency_ms: None,
            }
        },
    };

    match client
        .get(&agent_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            let latency = start.elapsed().as_millis() as i32;
            let status = resp.status();

            if status.is_success() {
                // Parse response to check healthy field
                match resp.text().await {
                    Ok(body) => {
                        // Try to parse as ApiResponse<ServiceStatusData>
                        if let Ok(api_resp) = serde_json::from_str::<serde_json::Value>(&body) {
                            if let Some(data) = api_resp.get("data") {
                                if let Some(healthy) = data.get("healthy").and_then(|v| v.as_bool())
                                {
                                    let active_state = data
                                        .get("active_state")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");
                                    let sub_state = data
                                        .get("sub_state")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    return CheckResult {
                                        healthy,
                                        detail: format!("{} ({})", active_state, sub_state),
                                        latency_ms: Some(latency),
                                    };
                                }
                            }
                        }
                        CheckResult {
                            healthy: false,
                            detail: format!("Failed to parse agent response"),
                            latency_ms: Some(latency),
                        }
                    },
                    Err(e) => CheckResult {
                        healthy: false,
                        detail: format!("Failed to read response: {}", e),
                        latency_ms: Some(latency),
                    },
                }
            } else {
                CheckResult {
                    healthy: false,
                    detail: format!("Agent returned HTTP {}", status),
                    latency_ms: Some(latency),
                }
            }
        },
        Err(e) => {
            let latency = start.elapsed().as_millis() as i32;
            if e.is_timeout() {
                CheckResult {
                    healthy: false,
                    detail: "Timeout (10s)".to_string(),
                    latency_ms: Some(latency),
                }
            } else {
                CheckResult {
                    healthy: false,
                    detail: format!("Connection failed: {}", e),
                    latency_ms: Some(latency),
                }
            }
        },
    }
}

async fn run_http_check(check: &HealthCheck, state: &AppState) -> CheckResult {
    let url = match &check.url {
        Some(u) => u.clone(),
        None => {
            return CheckResult {
                healthy: false,
                detail: "No URL configured".to_string(),
                latency_ms: None,
            }
        },
    };

    let expected = match &check.expected_body {
        Some(e) => e.clone(),
        None => {
            return CheckResult {
                healthy: false,
                detail: "No expected_body configured".to_string(),
                latency_ms: None,
            }
        },
    };

    // Build HTTP client
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(check.ignore_cert_errors)
        .build()
        .unwrap_or_default();

    // Build request with optional basic auth
    let mut request = client.get(&url);

    // Decrypt basic_auth_pass if user is set
    if let Some(ref user) = check.basic_auth_user {
        // Get encrypted password from DB
        let pass_data: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            "SELECT basic_auth_pass_encrypted, basic_auth_pass_nonce FROM host_health_checks WHERE id = $1",
        )
        .bind(check.id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        if let Some((enc, nonce)) = pass_data {
            let key_path = PathBuf::from(crypto::KEY_PATH);
            if let Ok(key) = crypto::load_or_create_key(&key_path) {
                if let Ok(password) = crypto::decrypt(&enc, &nonce, &key) {
                    request = request.basic_auth(user, Some(password));
                }
            }
        }
    }

    let start = std::time::Instant::now();

    match request.send().await {
        Ok(resp) => {
            let latency = start.elapsed().as_millis() as i32;
            let status = resp.status();

            if !status.is_success() {
                return CheckResult {
                    healthy: false,
                    detail: format!("HTTP {}", status),
                    latency_ms: Some(latency),
                };
            }

            match resp.text().await {
                Ok(body) => {
                    let matched = body.contains(&expected);
                    CheckResult {
                        healthy: matched,
                        detail: if matched {
                            format!("HTTP {} — body matched", status)
                        } else {
                            format!("HTTP {} — body did not contain expected substring", status)
                        },
                        latency_ms: Some(latency),
                    }
                },
                Err(e) => CheckResult {
                    healthy: false,
                    detail: format!("Failed to read response: {}", e),
                    latency_ms: Some(latency),
                },
            }
        },
        Err(e) => {
            let latency = start.elapsed().as_millis() as i32;
            if e.is_timeout() {
                CheckResult {
                    healthy: false,
                    detail: "Timeout (10s)".to_string(),
                    latency_ms: Some(latency),
                }
            } else {
                CheckResult {
                    healthy: false,
                    detail: format!("Request failed: {}", e),
                    latency_ms: Some(latency),
                }
            }
        },
    }
}

fn build_agent_http_client(state: &AppState) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(std::time::Duration::from_secs(10))
        .tls_built_in_root_certs(false) // Only trust internal CA
        .min_tls_version(Version::TLS_1_3);

    // Load mTLS client certificates
    let ca_cert_path = &state.config.security.ca_cert_path;
    let client_cert_path = &state.config.security.agent_client_cert_path;
    let client_key_path = &state.config.security.agent_client_key_path;

    tracing::info!(
        ca_cert_path = %ca_cert_path,
        client_cert_path = %client_cert_path,
        client_key_path = %client_key_path,
        "Building agent HTTP client"
    );

    // Add CA cert (mandatory since we disabled built-in root certs)
    let ca_pem =
        std::fs::read(ca_cert_path).map_err(|e| format!("Read CA cert {}: {}", ca_cert_path, e))?;
    tracing::info!(ca_pem_len = ca_pem.len(), "CA cert read");
    let ca =
        reqwest::Certificate::from_pem(&ca_pem).map_err(|e| format!("Parse CA cert: {}", e))?;
    builder = builder.add_root_certificate(ca);

    // Add client cert + key for mTLS
    let client_cert_exists = std::path::Path::new(client_cert_path).exists();
    let client_key_exists = std::path::Path::new(client_key_path).exists();
    tracing::info!(
        client_cert_exists,
        client_key_exists,
        "Checking client cert files"
    );

    if client_cert_exists && client_key_exists {
        let client_pem =
            std::fs::read(client_cert_path).map_err(|e| format!("Read client cert: {}", e))?;
        let key_pem =
            std::fs::read(client_key_path).map_err(|e| format!("Read client key: {}", e))?;
        tracing::info!(
            cert_len = client_pem.len(),
            key_len = key_pem.len(),
            "Client cert/key read"
        );
        let mut combined = Vec::new();
        combined.extend_from_slice(&client_pem);
        combined.extend_from_slice(&key_pem);
        let identity = reqwest::Identity::from_pem(&combined)
            .map_err(|e| format!("Parse client identity: {}", e))?;
        builder = builder.identity(identity);
        tracing::info!("Client identity added to builder");
    }

    tracing::info!("Building reqwest client...");
    match builder.build() {
        Ok(client) => {
            tracing::info!("reqwest client built successfully");
            Ok(client)
        },
        Err(e) => {
            tracing::error!(error = %e, "Failed to build reqwest client");
            Err(format!("Build client: {}", e))
        },
    }
}
