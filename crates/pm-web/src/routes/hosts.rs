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
    pub sort_by: Option<String>,
    pub order: Option<String>,
    /// Filter by patches missing: "missing" (>0) or "uptodate" (0).
    pub patches_missing: Option<String>,
}

/// Maps a frontend sort key to a validated SQL ORDER BY fragment.
/// Returns None for unknown columns to prevent SQL injection.
fn resolve_sort_fragment(sort_by: &str, order: &str) -> Option<String> {
    let column = match sort_by {
        "fqdn" => "h.fqdn",
        "display_name" => "h.display_name",
        "ip_address" => "host(h.ip_address)",
        "os" => "h.os_name",
        "health_status" => "h.health_status",
        "health_check_status" => "health_check_status",
        "crl_status" => "h.crl_status",
        "agent_version" => "h.agent_version",
        "patches_missing" => "patches_missing",
        _ => return None,
    };
    let dir = if order.eq_ignore_ascii_case("desc") {
        "DESC"
    } else {
        "ASC"
    };
    Some(format!("{column} {dir}"))
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

/// A filter condition: SQL template (with `${p}` placeholder) and its bind value.
struct HostFilter {
    sql: String,
    bind: String,
}

async fn list_hosts(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<HostListQuery>,
) -> Result<Json<HostListResponse>, (StatusCode, Json<Value>)> {
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);

    // Resolve sort: validated whitelist prevents SQL injection. Falls back to fqdn ASC.
    let order_by = match (&q.sort_by, &q.order) {
        (Some(field), Some(dir)) => resolve_sort_fragment(field, dir),
        (Some(field), None) => resolve_sort_fragment(field, "asc"),
        _ => None,
    }
    .unwrap_or_else(|| "h.fqdn ASC".to_string());

    // ── Build dynamic filter conditions ──────────────────────────────────────
    let mut filters: Vec<HostFilter> = Vec::new();

    if let Some(ref search) = q.search {
        if !search.is_empty() {
            filters.push(HostFilter {
                sql: "(h.fqdn ILIKE ${p} OR h.display_name ILIKE ${p})".to_string(),
                bind: format!("%{search}%"),
            });
        }
    }
    if let Some(ref hs) = q.health_status {
        if !hs.is_empty() {
            filters.push(HostFilter {
                sql: "h.health_status = ${p}".to_string(),
                bind: hs.clone(),
            });
        }
    }
    if let Some(ref pm) = q.patches_missing {
        match pm.as_str() {
            "missing" => filters.push(HostFilter {
                sql: "COALESCE(hpd.patch_count, 0) > 0".to_string(),
                bind: String::new(),
            }),
            "uptodate" => filters.push(HostFilter {
                sql: "COALESCE(hpd.patch_count, 0) = 0".to_string(),
                bind: String::new(),
            }),
            _ => {}
        }
    }

    let is_admin = auth.role.is_admin();

    // Helper: assign placeholder numbers to filter SQL templates, starting at `start`.
    // Returns (joined SQL fragment, number of placeholders used).
    let assign_placeholders = |filters: &[HostFilter], start: usize| -> (String, usize) {
        let mut idx = start;
        let parts: Vec<String> = filters
            .iter()
            .map(|f| {
                let s = f.sql.replace("${p}", &format!("${idx}"));
                if f.sql.contains("${p}") {
                    idx += 1;
                }
                s
            })
            .collect();
        if parts.is_empty() {
            (String::new(), 0)
        } else {
            (format!(" AND {}", parts.join(" AND ")), idx - start)
        }
    };

    // ── Data query ───────────────────────────────────────────────────────────
    let (filter_clause, n_filter_params) = assign_placeholders(&filters, 1);

    let hosts: Vec<HostSummary> = if is_admin {
        let limit_idx = 1 + n_filter_params;
        let offset_idx = 2 + n_filter_params;
        let sql = format!(
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
            WHERE 1=1{filter_clause}
            ORDER BY {order_by}
            LIMIT ${limit_idx} OFFSET ${offset_idx}
            "#
        );
        let mut query = sqlx::query_as::<_, HostSummary>(&sql);
        for f in &filters {
            if f.sql.contains("${p}") {
                query = query.bind(&f.bind);
            }
        }
        query = query.bind(limit).bind(offset);
        query.fetch_all(&state.db).await
    } else {
        // Operator: user_id is the last param (after filters + limit + offset)
        let user_idx = 3 + n_filter_params;
        let limit_idx = 1 + n_filter_params;
        let offset_idx = 2 + n_filter_params;
        let sql = format!(
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
                    WHERE hg.host_id = h.id AND ug.user_id = ${user_idx}
                )
                -- OR ungrouped hosts
                OR NOT EXISTS (SELECT 1 FROM host_groups WHERE host_id = h.id){filter_clause}
            ORDER BY {order_by}
            LIMIT ${limit_idx} OFFSET ${offset_idx}
            "#
        );
        let mut query = sqlx::query_as::<_, HostSummary>(&sql);
        for f in &filters {
            if f.sql.contains("${p}") {
                query = query.bind(&f.bind);
            }
        }
        query = query.bind(limit).bind(offset).bind(auth.user_id);
        query.fetch_all(&state.db).await
    }
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to list hosts");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    // ── Total count with the same filters ────────────────────────────────────
    // Re-assign placeholders independently for the count query.
    let total: i64 = if is_admin {
        let (count_filter, n_count_params) = assign_placeholders(&filters, 1);
        let sql = format!(
            "SELECT COUNT(*) FROM hosts h LEFT JOIN host_patch_data hpd ON hpd.host_id = h.id WHERE 1=1{count_filter}"
        );
        let mut query = sqlx::query_scalar::<_, i64>(&sql);
        for f in &filters {
            if f.sql.contains("${p}") {
                query = query.bind(&f.bind);
            }
        }
        let _ = n_count_params;
        query.fetch_one(&state.db).await.unwrap_or(0)
    } else {
        // Operator count: user_id is $1, filters start at $2
        let (count_filter, _) = assign_placeholders(&filters, 2);
        let sql = format!(
            "SELECT COUNT(*) FROM hosts h LEFT JOIN host_patch_data hpd ON hpd.host_id = h.id \
             WHERE (EXISTS (SELECT 1 FROM host_groups hg JOIN user_groups ug ON ug.group_id = hg.group_id \
             WHERE hg.host_id = h.id AND ug.user_id = $1) \
             OR NOT EXISTS (SELECT 1 FROM host_groups WHERE host_id = h.id)){count_filter}"
        );
        let mut query = sqlx::query_scalar::<_, i64>(&sql);
        query = query.bind(auth.user_id);
        for f in &filters {
            if f.sql.contains("${p}") {
                query = query.bind(&f.bind);
            }
        }
        query.fetch_one(&state.db).await.unwrap_or(0)
    };

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
                   crl_status, crl_age_seconds, crl_next_update,
                   gpg_key_status, gpg_key_expires_at
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
                   registered_at, updated_at, crl_status, crl_age_seconds, crl_next_update,
                   gpg_key_status, gpg_key_expires_at
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
