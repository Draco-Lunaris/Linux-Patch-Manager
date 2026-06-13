//! Host management routes.
//!
//! GET    /api/v1/hosts            — list hosts (RBAC scoped)
//! POST   /api/v1/hosts            — register new host (admin only)
//! GET    /api/v1/hosts/{id}       — get host detail
//! DELETE /api/v1/hosts/{id}       — remove host (admin only)
//! PUT    /api/v1/hosts/{id}       — update host (write access)
//! GET    /api/v1/hosts/{id}/groups — list groups for host
//! POST   /api/v1/hosts/{id}/groups — assign host to group
//! DELETE /api/v1/hosts/{id}/groups/{group_id} — remove host from group
//! POST   /api/v1/hosts/{id}/refresh           — queue on-demand refresh (write access)
//! POST   /api/v1/hosts/{id}/upgrade            — trigger self-upgrade on host (admin/operator)
//! POST   /api/v1/hosts/batch-upgrade            — trigger batch upgrade on hosts (admin)
//! GET    /api/v1/hosts/{id}/upgrade-status      — get upgrade status for host

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use pm_auth::rbac::AuthUser;
use pm_core::{
    audit::{log_event, AuditAction},
    models::{CreateHostRequest, Group, HostSummary, UpdateHostRequest},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_hosts).post(register_host))
        .route("/{id}", get(get_host).put(update_host).delete(remove_host))
        .route(
            "/{id}/groups",
            get(list_host_groups).post(add_host_to_group),
        )
        .route("/{id}/groups/{group_id}", delete(remove_host_from_group))
        .route("/{id}/refresh", post(refresh_host))
        .route("/{id}/upgrade", post(trigger_upgrade))
        .route("/{id}/upgrade-status", get(get_upgrade_status))
        .route("/batch-upgrade", post(batch_upgrade))
}

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct HostListQuery {
    pub group_id: Option<Uuid>,
    pub health_status: Option<String>,
    pub os_family: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct HostListResponse {
    hosts: Vec<HostSummary>,
    total: i64,
    limit: i64,
    offset: i64,
}

// ── Helper: check if operator can access a host ───────────────────────────────

async fn operator_can_access_host(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    host_id: Uuid,
) -> Result<bool, sqlx::Error> {
    // Admins can access all; operators can access hosts in their groups
    // OR ungrouped hosts (no group memberships)
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
    .await?;

    if in_group {
        return Ok(true);
    }

    // Ungrouped hosts are accessible to any operator
    let ungrouped: bool =
        sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM host_groups WHERE host_id = $1)")
            .bind(host_id)
            .fetch_one(pool)
            .await?;

    Ok(ungrouped)
}

// ── GET /api/v1/hosts ─────────────────────────────────────────────────────────

async fn list_hosts(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<HostListQuery>,
) -> Result<Json<HostListResponse>, (StatusCode, Json<Value>)> {
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);

    // For operators: only show hosts in their groups (or ungrouped)
    let hosts: Vec<HostSummary> = if auth.role.is_admin() {
        sqlx::query_as(
            r#"
            SELECT h.id, h.fqdn, host(h.ip_address)::text AS ip_address, h.display_name,
                   h.os_family, h.os_name, h.health_status, h.agent_version,
                   COALESCE(hpd.patch_count, 0) AS patches_missing,
                   CASE
                   WHEN NOT EXISTS (SELECT 1 FROM host_health_checks hc WHERE hc.host_id = h.id AND hc.enabled = TRUE)
                     THEN NULL
                   WHEN EXISTS (
                     SELECT 1 FROM host_health_checks hc
                     LEFT JOIN LATERAL (
                       SELECT healthy FROM host_health_check_results r
                       WHERE r.check_id = hc.id ORDER BY r.checked_at DESC LIMIT 1
                     ) lr ON TRUE
                     WHERE hc.host_id = h.id AND hc.enabled = TRUE
                       AND (lr.healthy IS NULL OR lr.healthy = FALSE)
                   )
                     THEN 'some_unhealthy'
                   ELSE 'all_healthy'
                 END AS health_check_status,
                   h.registered_at,
                   h.crl_status
            FROM hosts h
            LEFT JOIN host_patch_data hpd ON hpd.host_id = h.id
            ORDER BY h.fqdn
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as(
            r#"
            SELECT DISTINCT h.id, h.fqdn, host(h.ip_address)::text AS ip_address,
                   h.display_name, h.os_family, h.os_name,
                   h.health_status, h.agent_version,
                   COALESCE(hpd.patch_count, 0) AS patches_missing,
                   CASE
                   WHEN NOT EXISTS (SELECT 1 FROM host_health_checks hc WHERE hc.host_id = h.id AND hc.enabled = TRUE)
                     THEN NULL
                   WHEN EXISTS (
                     SELECT 1 FROM host_health_checks hc
                     LEFT JOIN LATERAL (
                       SELECT healthy FROM host_health_check_results r
                       WHERE r.check_id = hc.id ORDER BY r.checked_at DESC LIMIT 1
                     ) lr ON TRUE
                     WHERE hc.host_id = h.id AND hc.enabled = TRUE
                       AND (lr.healthy IS NULL OR lr.healthy = FALSE)
                   )
                     THEN 'some_unhealthy'
                   ELSE 'all_healthy'
                 END AS health_check_status,
                   h.registered_at,
                   h.crl_status
            FROM hosts h
            LEFT JOIN host_patch_data hpd ON hpd.host_id = h.id
            WHERE
                -- Hosts in operator's groups
                EXISTS (
                    SELECT 1 FROM host_groups hg
                    JOIN user_groups ug ON ug.group_id = hg.group_id
                    WHERE hg.host_id = h.id AND ug.user_id = $3
                )
                -- OR ungrouped hosts
                OR NOT EXISTS (SELECT 1 FROM host_groups WHERE host_id = h.id)
            ORDER BY h.fqdn
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .bind(auth.user_id)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to list hosts");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    Ok(Json(HostListResponse {
        hosts,
        total,
        limit,
        offset,
    }))
}

// ── POST /api/v1/hosts ────────────────────────────────────────────────────────

async fn register_host(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateHostRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Admin only
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }

    // Resolve FQDN to IP address
    let ip_address = resolve_fqdn(&req.fqdn).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "fqdn_resolution_failed", "message": e } })),
        )
    })?;

    let display_name = req.display_name.clone().unwrap_or_else(|| req.fqdn.clone());
    let agent_port = req.agent_port.unwrap_or(12443);
    let notes = req.notes.clone().unwrap_or_default();

    // Insert host
    let host_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO hosts (fqdn, ip_address, display_name, agent_port, notes)
        VALUES ($1, $2::inet, $3, $4, $5)
        RETURNING id
        "#,
    )
    .bind(&req.fqdn)
    .bind(&ip_address)
    .bind(&display_name)
    .bind(agent_port)
    .bind(&notes)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = if e.to_string().contains("unique") {
            "Host with this FQDN and IP already exists".to_string()
        } else {
            "Database error".to_string()
        };
        tracing::error!(error = %e, "Failed to register host");
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": { "code": "conflict", "message": msg } })),
        )
    })?;

    // Assign to groups if specified
    if let Some(group_ids) = &req.group_ids {
        for gid in group_ids {
            let _ = sqlx::query(
                "INSERT INTO host_groups (host_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(host_id)
            .bind(gid)
            .execute(&state.db)
            .await;
        }
    }

    // Audit log
    log_event(
        &state.db,
        AuditAction::HostRegistered,
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&host_id.to_string()),
        json!({ "fqdn": req.fqdn, "ip": ip_address }),
        None,
        None,
    )
    .await;

    tracing::info!(host_id = %host_id, fqdn = %req.fqdn, "Host registered");
    Ok(Json(json!({ "id": host_id, "message": "Host registered" })))
}

// ── GET /api/v1/hosts/:id ─────────────────────────────────────────────────────

async fn get_host(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, id)
            .await
            .unwrap_or(false);
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": { "code": "forbidden", "message": "Access denied" } })),
            ));
        }
    }

    let host: Option<Value> = sqlx::query_scalar(
        r#"
        SELECT row_to_json(h) FROM (
            SELECT id, fqdn, host(ip_address)::text AS ip_address, display_name,
                   os_family, os_name, arch, agent_version, health_status,
                   last_health_at, last_patch_at, agent_port, notes,
                   registered_at, updated_at,
                   crl_status, crl_age_seconds, crl_next_update
            FROM hosts WHERE id = $1
        ) h
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to get host");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    host.map(Json).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Host not found" } })),
        )
    })
}

// ── DELETE /api/v1/hosts/:id ──────────────────────────────────────────────────

async fn remove_host(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }

    // Fetch FQDN for audit before deletion
    let fqdn: Option<String> = sqlx::query_scalar("SELECT fqdn FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let result = sqlx::query("DELETE FROM hosts WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to remove host");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Host not found" } })),
        ));
    }

    log_event(
        &state.db,
        AuditAction::HostRemoved,
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&id.to_string()),
        json!({ "fqdn": fqdn }),
        None,
        None,
    )
    .await;

    tracing::info!(host_id = %id, "Host removed");
    Ok(Json(json!({ "message": "Host removed" })))
}

// ── PUT /api/v1/hosts/:id ─────────────────────────────────────────────────────

async fn update_host(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateHostRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }

    // Update only fields that were provided; COALESCE preserves existing values.
    let host = sqlx::query_scalar(
        r#"
        WITH updated AS (
            UPDATE hosts SET
                fqdn         = COALESCE($1, fqdn),
                ip_address   = COALESCE($2::inet, ip_address),
                display_name = COALESCE($3, display_name),
                updated_at   = NOW()
            WHERE id = $4
            RETURNING id
        )
        SELECT row_to_json(h) FROM (
            SELECT id, fqdn, host(ip_address)::text AS ip_address, display_name,
                   os_family, os_name, arch, agent_version, health_status,
                   last_health_at, last_patch_at, agent_port, notes,
                   registered_at, updated_at, crl_status, crl_age_seconds, crl_next_update
            FROM hosts WHERE id = (SELECT id FROM updated)
        ) h
        "#,
    )
    .bind(&req.fqdn)
    .bind(&req.ip_address)
    .bind(&req.display_name)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, host_id = %id, "Failed to update host");
        let msg = if e.to_string().contains("unique") {
            "A host with this FQDN and IP already exists".to_string()
        } else {
            "Database error".to_string()
        };
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": { "code": "conflict", "message": msg } })),
        )
    })?;

    host.map(Json).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Host not found" } })),
        )
    })
}

// ── GET /api/v1/hosts/:id/groups ──────────────────────────────────────────────

async fn list_host_groups(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Group>>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, id)
            .await
            .unwrap_or(false);
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": { "code": "forbidden", "message": "Access denied" } })),
            ));
        }
    }

    let groups: Vec<Group> = sqlx::query_as(
        r#"SELECT g.id, g.name, g.description, g.created_at, g.updated_at
           FROM groups g
           JOIN host_groups hg ON hg.group_id = g.id
           WHERE hg.host_id = $1
           ORDER BY g.name"#,
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to list host groups");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    Ok(Json(groups))
}

// ── POST /api/v1/hosts/:id/groups ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AddToGroupRequest {
    group_id: Uuid,
}

async fn add_host_to_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<AddToGroupRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }

    sqlx::query(
        "INSERT INTO host_groups (host_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(req.group_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to add host to group");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    log_event(
        &state.db,
        AuditAction::GroupMembershipChanged,
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&id.to_string()),
        json!({ "group_id": req.group_id, "action": "added" }),
        None,
        None,
    )
    .await;

    Ok(Json(json!({ "message": "Host added to group" })))
}

// ── DELETE /api/v1/hosts/:id/groups/:group_id ─────────────────────────────────

async fn remove_host_from_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((id, group_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }

    sqlx::query("DELETE FROM host_groups WHERE host_id = $1 AND group_id = $2")
        .bind(id)
        .bind(group_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to remove host from group");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

    log_event(
        &state.db,
        AuditAction::GroupMembershipChanged,
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&id.to_string()),
        json!({ "group_id": group_id, "action": "removed" }),
        None,
        None,
    )
    .await;

    Ok(Json(json!({ "message": "Host removed from group" })))
}

// ── FQDN resolution ───────────────────────────────────────────────────────────

/// Resolve an FQDN (or IP) to its primary IP address.
/// If the input is already a valid IP, returns it as-is.
async fn resolve_fqdn(fqdn: &str) -> Result<String, String> {
    use std::net::ToSocketAddrs;
    // Try direct IP parse first
    if fqdn.parse::<std::net::IpAddr>().is_ok() {
        return Ok(fqdn.to_string());
    }
    // DNS resolution
    let addr = format!("{fqdn}:0");
    match tokio::task::spawn_blocking(move || addr.to_socket_addrs()).await {
        Ok(Ok(mut addrs)) => addrs
            .next()
            .map(|a| a.ip().to_string())
            .ok_or_else(|| format!("No addresses found for {fqdn}")),
        _ => Err(format!("Failed to resolve FQDN: {fqdn}")),
    }
}

// ── POST /api/v1/hosts/:id/refresh ───────────────────────────────────────────

/// Queue an on-demand health + patch refresh for a single host.
///
/// Sends a PostgreSQL NOTIFY on the `refresh_requested` channel; the
/// pm-worker refresh listener picks this up and polls the host immediately.
/// Requires Operator or Admin role (any authenticated user).
async fn refresh_host(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }
    // Verify the host exists.
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM hosts WHERE id = $1)")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %id, "refresh_host: db error checking host existence");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Host not found" } })),
        ));
    }

    // NOTIFY the worker's refresh listener.
    sqlx::query("SELECT pg_notify('refresh_requested', $1)")
        .bind(id.to_string())
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %id, "refresh_host: pg_notify failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Failed to queue refresh" } })),
            )
        })?;

    tracing::info!(%id, "On-demand refresh queued");

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "message": "Refresh queued" })),
    ))
}

// ── Request types for upgrade routes ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TriggerUpgradeRequest {
    pub upgrade_url: String,
    pub upgrade_checksum: Option<String>,
    pub upgrade_version: String,
}

#[derive(Debug, Deserialize)]
pub struct BatchUpgradeRequest {
    pub host_ids: Vec<Uuid>,
    pub upgrade_url: String,
    pub upgrade_checksum: Option<String>,
    pub upgrade_version: String,
}

// ── POST /api/v1/hosts/{id}/upgrade ───────────────────────────────────────────

/// Trigger a self-upgrade job on a single host.
/// Requires admin or operator role.
async fn trigger_upgrade(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<TriggerUpgradeRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }

    // Verify the host exists.
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM hosts WHERE id = $1)")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %id, "trigger_upgrade: db error checking host existence");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "Host not found" } })),
        ));
    }

    // Create the self_upgrade job.
    let job_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO patch_jobs
            (kind, status, created_by_user_id, immediate, patch_selection, notes)
        VALUES
            ('self_upgrade'::job_kind, 'queued'::job_status, $1, TRUE, '[]'::jsonb, $2)
        RETURNING id
        "#,
    )
    .bind(auth.user_id)
    .bind(format!("Self-upgrade to v{}", req.upgrade_version))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "trigger_upgrade: insert patch_jobs failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    // Insert the patch_job_hosts row with upgrade fields.
    sqlx::query(
        r#"
        INSERT INTO patch_job_hosts
            (job_id, host_id, status, upgrade_url, upgrade_checksum, upgrade_version)
        VALUES
            ($1, $2, 'queued'::job_status, $3, $4, $5)
        ON CONFLICT (job_id, host_id) DO NOTHING
        "#,
    )
    .bind(job_id)
    .bind(id)
    .bind(&req.upgrade_url)
    .bind(&req.upgrade_checksum)
    .bind(&req.upgrade_version)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %job_id, %id, "trigger_upgrade: insert patch_job_hosts failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    log_event(
        &state.db,
        AuditAction::UpgradeTriggered,
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&id.to_string()),
        json!({
            "job_id": job_id,
            "upgrade_url": req.upgrade_url,
            "upgrade_version": req.upgrade_version,
        }),
        None,
        None,
    )
    .await;

    tracing::info!(
        job_id = %job_id,
        host_id = %id,
        upgrade_version = %req.upgrade_version,
        user = %auth.username,
        "Self-upgrade job triggered"
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "job_id": job_id,
            "host_id": id,
            "status": "queued",
            "message": "Upgrade job created"
        })),
    ))
}

// ── POST /api/v1/hosts/batch-upgrade ──────────────────────────────────────────

/// Trigger a batch self-upgrade job on multiple hosts.
/// Requires admin role.
async fn batch_upgrade(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<BatchUpgradeRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // Admin-only
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Admin access required" } })),
        ));
    }

    if req.host_ids.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "bad_request", "message": "host_ids must not be empty" } }),
            ),
        ));
    }

    // Create the self_upgrade job.
    let job_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO patch_jobs
            (kind, status, created_by_user_id, immediate, patch_selection, notes)
        VALUES
            ('self_upgrade'::job_kind, 'queued'::job_status, $1, TRUE, '[]'::jsonb, $2)
        RETURNING id
        "#,
    )
    .bind(auth.user_id)
    .bind(format!("Batch self-upgrade to v{}", req.upgrade_version))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "batch_upgrade: insert patch_jobs failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    // Insert patch_job_hosts rows with upgrade fields.
    for host_id in &req.host_ids {
        sqlx::query(
            r#"
            INSERT INTO patch_job_hosts
                (job_id, host_id, status, upgrade_url, upgrade_checksum, upgrade_version)
            VALUES
                ($1, $2, 'queued'::job_status, $3, $4, $5)
            ON CONFLICT (job_id, host_id) DO NOTHING
            "#,
        )
        .bind(job_id)
        .bind(host_id)
        .bind(&req.upgrade_url)
        .bind(&req.upgrade_checksum)
        .bind(&req.upgrade_version)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e, %job_id, %host_id,
                "batch_upgrade: insert patch_job_hosts failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;
    }

    log_event(
        &state.db,
        AuditAction::BatchUpgradeTriggered,
        Some(auth.user_id),
        Some(&auth.username),
        Some("job"),
        Some(&job_id.to_string()),
        json!({
            "host_count": req.host_ids.len(),
            "upgrade_url": req.upgrade_url,
            "upgrade_version": req.upgrade_version,
        }),
        None,
        None,
    )
    .await;

    tracing::info!(
        job_id = %job_id,
        host_count = req.host_ids.len(),
        upgrade_version = %req.upgrade_version,
        user = %auth.username,
        "Batch self-upgrade job triggered"
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "job_id": job_id,
            "host_count": req.host_ids.len(),
            "status": "queued",
            "message": "Batch upgrade job created"
        })),
    ))
}

// ── GET /api/v1/hosts/{id}/upgrade-status ─────────────────────────────────────

/// Get the upgrade status for a host (latest self_upgrade job).
async fn get_upgrade_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        let can_access = operator_can_access_host(&state.db, auth.user_id, id)
            .await
            .unwrap_or(false);
        if !can_access {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": { "code": "forbidden", "message": "Access denied" } })),
            ));
        }
    }

    // Fetch the latest self_upgrade job for this host.
    let row: Option<Value> = sqlx::query_scalar(
        r#"
        SELECT row_to_json(t) FROM (
            SELECT
                pj.id AS job_id,
                pj.status::text AS job_status,
                pj.created_at,
                pj.started_at,
                pj.completed_at,
                pjh.status::text AS host_status,
                pjh.upgrade_url,
                pjh.upgrade_checksum,
                pjh.upgrade_version,
                pjh.output,
                pjh.error_message,
                pjh.started_at AS host_started_at,
                pjh.completed_at AS host_completed_at
            FROM patch_job_hosts pjh
            JOIN patch_jobs pj ON pj.id = pjh.job_id
            WHERE pjh.host_id = $1
              AND pj.kind = 'self_upgrade'::job_kind
            ORDER BY pj.created_at DESC
            LIMIT 1
        ) t
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %id, "get_upgrade_status: query failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    row.map(Json).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "message": "No upgrade job found for this host" } })),
        )
    })
}
