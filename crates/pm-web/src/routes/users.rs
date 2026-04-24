//! User management routes.
//!
//! GET    /api/v1/users             — list users (admin only)
//! POST   /api/v1/users             — create user (admin only)
//! GET    /api/v1/users/:id         — get user detail
//! PUT    /api/v1/users/:id         — update user
//! DELETE /api/v1/users/:id         — delete user (admin only)
//! GET    /api/v1/users/me          — current user profile
//! POST   /api/v1/users/:id/revoke  — revoke all sessions (admin only)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use pm_auth::{hash_password, rbac::AuthUser, session::force_logout};
use pm_core::{
    audit::{log_event, AuditAction},
    models::{CreateUserRequest, UpdateUserRequest, User},
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/me", get(get_current_user))
        .route("/:id", get(get_user).put(update_user).delete(delete_user))
        .route("/:id/revoke", post(revoke_user_sessions))
}

async fn list_users(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<User>>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } })),
        ));
    }

    sqlx::query_as::<_, User>(
        r#"SELECT id, username, display_name, email, role, auth_provider,
                  mfa_enabled, is_active, force_password_reset, last_login_at,
                  created_at, updated_at
           FROM users ORDER BY username"#,
    )
    .fetch_all(&state.db)
    .await
    .map(Json)
    .map_err(|e| {
        tracing::error!(error = %e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })
}

async fn create_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } })),
        ));
    }

    let hash = hash_password(&req.password).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
        )
    })?;

    let role = if req.role == "admin" {
        "admin"
    } else {
        "operator"
    };

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO users (username, display_name, email, role, auth_provider, password_hash)
           VALUES ($1, $2, $3, $4::user_role, 'local', $5)
           RETURNING id"#,
    )
    .bind(&req.username)
    .bind(req.display_name.as_deref().unwrap_or(&req.username))
    .bind(&req.email)
    .bind(role)
    .bind(&hash)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = if e.to_string().contains("unique") {
            "Username or email already exists".to_string()
        } else {
            "Database error".to_string()
        };
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": { "code": "conflict", "message": msg } })),
        )
    })?;

    log_event(
        &state.db,
        AuditAction::UserCreated,
        Some(auth.user_id),
        Some(&auth.username),
        Some("user"),
        Some(&id.to_string()),
        json!({ "username": req.username }),
        None,
        None,
    )
    .await;

    Ok(Json(json!({ "id": id, "message": "User created" })))
}

async fn get_current_user(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<User>, (StatusCode, Json<Value>)> {
    fetch_user(&state.db, auth.user_id).await
}

async fn get_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<User>, (StatusCode, Json<Value>)> {
    // Users can see themselves; admin can see anyone
    if !auth.role.is_admin() && auth.user_id != id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Access denied" } })),
        ));
    }
    fetch_user(&state.db, id).await
}

async fn fetch_user(
    pool: &sqlx::PgPool,
    id: Uuid,
) -> Result<Json<User>, (StatusCode, Json<Value>)> {
    let user: Option<User> = sqlx::query_as(
        r#"SELECT id, username, display_name, email, role, auth_provider,
                  mfa_enabled, is_active, force_password_reset, last_login_at,
                  created_at, updated_at
           FROM users WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    user.map(Json).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "User not found" } })),
        )
    })
}

async fn update_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() && auth.user_id != id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Access denied" } })),
        ));
    }
    // Only admins can change role or active status
    if (req.role.is_some() || req.is_active.is_some()) && !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({ "error": { "code": "forbidden", "message": "Admin role required to change role or status" } }),
            ),
        ));
    }

    let role_str = req
        .role
        .as_deref()
        .map(|r| if r == "admin" { "admin" } else { "operator" });

    let rows = sqlx::query(
        r#"UPDATE users SET
               display_name = COALESCE($1, display_name),
               email = COALESCE($2, email),
               role = COALESCE($3::user_role, role),
               is_active = COALESCE($4, is_active),
               updated_at = NOW()
           WHERE id = $5"#,
    )
    .bind(req.display_name.as_deref())
    .bind(req.email.as_deref())
    .bind(role_str)
    .bind(req.is_active)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
        )
    })?
    .rows_affected();

    if rows == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "User not found" } })),
        ));
    }

    log_event(
        &state.db,
        AuditAction::UserUpdated,
        Some(auth.user_id),
        Some(&auth.username),
        Some("user"),
        Some(&id.to_string()),
        json!({}),
        None,
        None,
    )
    .await;

    Ok(Json(json!({ "message": "User updated" })))
}

async fn delete_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } })),
        ));
    }
    if auth.user_id == id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "bad_request", "message": "Cannot delete your own account" } }),
            ),
        ));
    }

    let rows = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
            )
        })?
        .rows_affected();

    if rows == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "User not found" } })),
        ));
    }

    log_event(
        &state.db,
        AuditAction::UserDeleted,
        Some(auth.user_id),
        Some(&auth.username),
        Some("user"),
        Some(&id.to_string()),
        json!({}),
        None,
        None,
    )
    .await;

    Ok(Json(json!({ "message": "User deleted" })))
}

async fn revoke_user_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } })),
        ));
    }

    let count = force_logout(&state.db, id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
        )
    })?;

    Ok(Json(
        json!({ "message": "Sessions revoked", "count": count }),
    ))
}
