//! Group management routes.
//!
//! GET    /api/v1/groups            — list all groups
//! POST   /api/v1/groups            — create group (admin)
//! GET    /api/v1/groups/:id        — get group detail + members
//! PUT    /api/v1/groups/:id        — update group (admin)
//! DELETE /api/v1/groups/:id        — delete group (admin)
//! POST   /api/v1/groups/:id/users/:user_id  — add user to group (admin)
//! DELETE /api/v1/groups/:id/users/:user_id  — remove user from group (admin)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use pm_core::{
    audit::{log_event, AuditAction},
    models::{Group, CreateGroupRequest, UpdateGroupRequest},
};
use pm_auth::rbac::AuthUser;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_groups).post(create_group))
        .route("/:id", get(get_group).put(update_group).delete(delete_group))
        .route("/:id/users/:user_id", post(add_user_to_group).delete(remove_user_from_group))
}

async fn list_groups(
    State(state): State<AppState>,
    _auth: AuthUser,
) -> Result<Json<Vec<Group>>, (StatusCode, Json<Value>)> {
    sqlx::query_as::<_, Group>(
        "SELECT id, name, description, created_at, updated_at FROM groups ORDER BY name"
    )
    .fetch_all(&state.db)
    .await
    .map(Json)
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to list groups");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })))
    })
}

async fn create_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } }))));
    }

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (name, description) VALUES ($1, $2) RETURNING id"
    )
    .bind(&req.name)
    .bind(req.description.as_deref().unwrap_or(""))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = if e.to_string().contains("unique") { "Group name already exists".to_string() } else { "Database error".to_string() };
        (StatusCode::CONFLICT, Json(json!({ "error": { "code": "conflict", "message": msg } })))
    })?;

    log_event(&state.db, AuditAction::GroupCreated, Some(auth.user_id), Some(&auth.username),
        Some("group"), Some(&id.to_string()), json!({ "name": req.name }), None, None).await;

    Ok(Json(json!({ "id": id, "message": "Group created" })))
}

async fn get_group(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let group: Option<Group> = sqlx::query_as(
        "SELECT id, name, description, created_at, updated_at FROM groups WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e); (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })))
    })?;

    let group = group.ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": { "code": "not_found", "message": "Group not found" } }))))?;

    // Fetch member counts
    let host_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM host_groups WHERE group_id = $1")
        .bind(id).fetch_one(&state.db).await.unwrap_or(0);
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_groups WHERE group_id = $1")
        .bind(id).fetch_one(&state.db).await.unwrap_or(0);

    Ok(Json(json!({ "group": group, "host_count": host_count, "user_count": user_count })))
}

async fn update_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } }))));
    }

    let rows = sqlx::query(
        "UPDATE groups SET name = COALESCE($1, name), description = COALESCE($2, description), updated_at = NOW() WHERE id = $3"
    )
    .bind(req.name.as_deref())
    .bind(req.description.as_deref())
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } }))))?
    .rows_affected();

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, Json(json!({ "error": { "code": "not_found", "message": "Group not found" } }))));
    }

    Ok(Json(json!({ "message": "Group updated" })))
}

async fn delete_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } }))));
    }

    let rows = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(id).execute(&state.db).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } }))))?
        .rows_affected();

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, Json(json!({ "error": { "code": "not_found", "message": "Group not found" } }))));
    }

    log_event(&state.db, AuditAction::GroupDeleted, Some(auth.user_id), Some(&auth.username),
        Some("group"), Some(&id.to_string()), json!({}), None, None).await;

    Ok(Json(json!({ "message": "Group deleted" })))
}

async fn add_user_to_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } }))));
    }

    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(user_id).bind(id)
        .execute(&state.db).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } }))))?;

    log_event(&state.db, AuditAction::GroupMembershipChanged, Some(auth.user_id), Some(&auth.username),
        Some("user_group"), Some(&id.to_string()), json!({ "user_id": user_id, "action": "added" }), None, None).await;

    Ok(Json(json!({ "message": "User added to group" })))
}

async fn remove_user_from_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } }))));
    }

    sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2")
        .bind(user_id).bind(id)
        .execute(&state.db).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } }))))?;

    log_event(&state.db, AuditAction::GroupMembershipChanged, Some(auth.user_id), Some(&auth.username),
        Some("user_group"), Some(&id.to_string()), json!({ "user_id": user_id, "action": "removed" }), None, None).await;

    Ok(Json(json!({ "message": "User removed from group" })))
}
