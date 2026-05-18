//! Patch job management routes.
//!
//! POST   /api/v1/jobs               — create a new patch job (operator+)
//! GET    /api/v1/jobs               — list jobs with pagination (RBAC scoped)
//! GET    /api/v1/jobs/{id}          — get job detail + per-host status
//! POST   /api/v1/jobs/{id}/cancel   — cancel a queued/pending job (admin or creator)
//! POST   /api/v1/jobs/{id}/rollback — create a rollback job (admin only)

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use pm_auth::rbac::AuthUser;
use pm_core::{
    audit::{log_event, AuditAction},
    models::{CreateJobRequest, PatchJobSummary},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_jobs).post(create_job))
        .route("/{id}", get(get_job))
        .route("/{id}/cancel", post(cancel_job))
        .route("/{id}/rollback", post(rollback_job))
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JobListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct JobListResponse {
    jobs: Vec<PatchJobSummary>,
    total: i64,
    limit: i64,
    offset: i64,
}

/// Per-host row included in `GET /api/v1/jobs/{id}` response.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
struct JobHostRow {
    pub id: Uuid,
    pub host_id: Uuid,
    pub display_name: String,
    pub status: String,
    pub agent_job_id: Option<String>,
    pub retry_count: i32,
    pub output: String,
    pub error_message: Option<String>,
    pub last_error: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
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

// ── RBAC helper ───────────────────────────────────────────────────────────────

/// Returns `true` when the operator's groups contain at least one host that
/// belongs to the given job. Admins always pass this check at the call site.
async fn operator_can_access_job(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    job_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM patch_job_hosts pjh
            JOIN host_groups     hg  ON hg.host_id  = pjh.host_id
            JOIN user_groups     ug  ON ug.group_id = hg.group_id
            WHERE pjh.job_id = $1
              AND ug.user_id = $2
        )
        "#,
    )
    .bind(job_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
}

// ── POST /api/v1/jobs ─────────────────────────────────────────────────────────

async fn create_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateJobRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Write access required",
        ));
    }
    if req.host_ids.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "host_ids must not be empty",
        ));
    }

    // Encode package list as JSONB.
    let patch_selection = serde_json::to_value(&req.packages).unwrap_or(json!([]));
    let notes = req.notes.clone().unwrap_or_default();

    // Insert the parent job row; the DB NOTIFY trigger fires automatically
    // when immediate = TRUE (see migration 003_jobs_scheduling.sql).
    let job_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO patch_jobs
            (kind, status, created_by_user_id, maintenance_window_id,
             immediate, patch_selection, notes)
        VALUES
            ('patch_apply'::job_kind, 'queued'::job_status, $1, $2, $3, $4, $5)
        RETURNING id
        "#,
    )
    .bind(auth.user_id)
    .bind(req.maintenance_window_id)
    .bind(req.immediate)
    .bind(&patch_selection)
    .bind(&notes)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create_job: insert patch_jobs failed");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    // Insert one patch_job_hosts row per requested host.
    for host_id in &req.host_ids {
        sqlx::query(
            r#"
            INSERT INTO patch_job_hosts (job_id, host_id, status)
            VALUES ($1, $2, 'queued'::job_status)
            ON CONFLICT (job_id, host_id) DO NOTHING
            "#,
        )
        .bind(job_id)
        .bind(host_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e, %job_id, %host_id,
                "create_job: insert patch_job_hosts failed"
            );
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Database error",
            )
        })?;
    }

    log_event(
        &state.db,
        AuditAction::PatchJobCreated,
        Some(auth.user_id),
        Some(&auth.username),
        Some("job"),
        Some(&job_id.to_string()),
        json!({
            "kind": "patch_apply",
            "immediate": req.immediate,
            "host_count": req.host_ids.len(),
            "packages": req.packages,
            "notes": notes,
        }),
        None,
        None,
    )
    .await;

    tracing::info!(
        job_id = %job_id,
        host_count = req.host_ids.len(),
        immediate = req.immediate,
        user = %auth.username,
        "Patch job created"
    );

    Ok(Json(json!({ "id": job_id, "message": "Job created" })))
}

// ── GET /api/v1/jobs ──────────────────────────────────────────────────────────

async fn list_jobs(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<JobListQuery>,
) -> Result<Json<JobListResponse>, (StatusCode, Json<Value>)> {
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);

    let jobs: Vec<PatchJobSummary> = if auth.role.is_admin() {
        // Admins see every job.
        sqlx::query_as(
            r#"
            SELECT
                pj.id,
                pj.kind,
                pj.status,
                pj.immediate,
                pj.notes,
                pj.created_at,
                pj.started_at,
                pj.completed_at,
                COUNT(pjh.id)                                                     AS host_count,
                COUNT(pjh.id) FILTER (WHERE pjh.status = 'succeeded'::job_status) AS succeeded_count,
                COUNT(pjh.id) FILTER (WHERE pjh.status = 'failed'::job_status)    AS failed_count
            FROM patch_jobs pj
            LEFT JOIN patch_job_hosts pjh ON pjh.job_id = pj.id
            GROUP BY pj.id
            ORDER BY pj.created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    } else {
        // Operators: only jobs where at least one host is in their groups.
        sqlx::query_as(
            r#"
            SELECT
                pj.id,
                pj.kind,
                pj.status,
                pj.immediate,
                pj.notes,
                pj.created_at,
                pj.started_at,
                pj.completed_at,
                COUNT(pjh.id)                                                     AS host_count,
                COUNT(pjh.id) FILTER (WHERE pjh.status = 'succeeded'::job_status) AS succeeded_count,
                COUNT(pjh.id) FILTER (WHERE pjh.status = 'failed'::job_status)    AS failed_count
            FROM patch_jobs pj
            LEFT JOIN patch_job_hosts pjh ON pjh.job_id = pj.id
            WHERE EXISTS (
                SELECT 1
                FROM patch_job_hosts  pjh2
                JOIN host_groups      hg  ON hg.host_id  = pjh2.host_id
                JOIN user_groups      ug  ON ug.group_id = hg.group_id
                WHERE pjh2.job_id = pj.id
                  AND ug.user_id  = $3
            )
            GROUP BY pj.id
            ORDER BY pj.created_at DESC
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
        tracing::error!(error = %e, "list_jobs: query failed");
        err(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "Database error")
    })?;

    // Total count for pagination metadata.
    let total: i64 = if auth.role.is_admin() {
        sqlx::query_scalar("SELECT COUNT(*) FROM patch_jobs")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0)
    } else {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(DISTINCT pj.id)
            FROM patch_jobs pj
            WHERE EXISTS (
                SELECT 1
                FROM patch_job_hosts pjh
                JOIN host_groups     hg  ON hg.host_id  = pjh.host_id
                JOIN user_groups     ug  ON ug.group_id = hg.group_id
                WHERE pjh.job_id = pj.id
                  AND ug.user_id = $1
            )
            "#,
        )
        .bind(auth.user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0)
    };

    Ok(Json(JobListResponse {
        jobs,
        total,
        limit,
        offset,
    }))
}
// ── GET /api/v1/jobs/:id ─────────────────────────────────────────────────────

async fn get_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // RBAC: operators may only view jobs touching their group's hosts.
    if !auth.role.is_admin() {
        let allowed = operator_can_access_job(&state.db, auth.user_id, id)
            .await
            .unwrap_or(false);
        if !allowed {
            return Err(err(StatusCode::FORBIDDEN, "forbidden", "Access denied"));
        }
    }

    // Fetch the job header row as JSON.
    let job: Option<Value> = sqlx::query_scalar(
        r#"
        SELECT row_to_json(j) FROM (
            SELECT id, kind, status, created_by_user_id, parent_job_id,
                   maintenance_window_id, immediate, patch_selection, notes,
                   created_at, started_at, completed_at
            FROM patch_jobs
            WHERE id = $1
        ) j
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %id, "get_job: failed to fetch job");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    let job = job.ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "Job not found"))?;

    // Fetch per-host status rows joined to the host display name.
    let hosts: Vec<JobHostRow> = sqlx::query_as(
        r#"
        SELECT
            pjh.id,
            pjh.host_id,
            COALESCE(h.display_name, h.fqdn) AS display_name,
            pjh.status::text                 AS status,
            pjh.agent_job_id,
            pjh.retry_count,
            pjh.output,
            pjh.error_message,
            pjh.last_error,
            pjh.started_at,
            pjh.completed_at
        FROM patch_job_hosts pjh
        JOIN hosts h ON h.id = pjh.host_id
        WHERE pjh.job_id = $1
        ORDER BY h.display_name
        "#,
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %id, "get_job: failed to fetch host rows");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    Ok(Json(json!({ "job": job, "hosts": hosts })))
}

// ── POST /api/v1/jobs/:id/cancel ─────────────────────────────────────────────

async fn cancel_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Fetch the job to verify it exists and check ownership.
    let row: Option<(String, Option<Uuid>)> =
        sqlx::query_as("SELECT status::text, created_by_user_id FROM patch_jobs WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, %id, "cancel_job: db fetch failed");
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Database error",
                )
            })?;

    let (status_str, creator_id) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "Job not found"))?;

    // Only admin or the job creator may cancel.
    if !auth.role.can_write() {
        let is_creator = creator_id == Some(auth.user_id);
        if !is_creator {
            return Err(err(
                StatusCode::FORBIDDEN,
                "forbidden",
                "Write access required",
            ));
        }
    }

    // Only queued or pending jobs can be cancelled.
    if status_str != "queued" && status_str != "pending" {
        return Err(err(
            StatusCode::CONFLICT,
            "invalid_state",
            format!(
                "Cannot cancel a job in '{}' state; only queued or pending jobs may be cancelled",
                status_str
            ),
        ));
    }

    // Cancel the parent job.
    sqlx::query("UPDATE patch_jobs SET status = 'cancelled'::job_status WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %id, "cancel_job: update patch_jobs failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Database error",
            )
        })?;

    // Cancel all queued/pending host rows for this job.
    sqlx::query(
        r#"
        UPDATE patch_job_hosts
        SET status = 'cancelled'::job_status
        WHERE job_id = $1
          AND status IN ('queued'::job_status, 'pending'::job_status)
        "#,
    )
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %id, "cancel_job: update patch_job_hosts failed");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    // Fire job-level pg_notify so the frontend can update the job row.
    let notify_payload = json!({
        "event_type": "job",
        "job_id": id.to_string(),
        "host_id": "",
        "status": "cancelled",
        "succeeded_count": 0,
        "failed_count": 0,
        "host_count": 0,
    });
    if let Ok(payload_str) = serde_json::to_string(&notify_payload) {
        if let Err(e) = sqlx::query("SELECT pg_notify('job_update', $1)")
            .bind(&payload_str)
            .execute(&state.db)
            .await
        {
            tracing::error!(error = %e, %id, "cancel_job: job-level pg_notify failed");
        } else {
            tracing::info!(%id, "cancel_job: job-level pg_notify sent");
        }
    }

    log_event(
        &state.db,
        AuditAction::PatchJobCancelled,
        Some(auth.user_id),
        Some(&auth.username),
        Some("job"),
        Some(&id.to_string()),
        json!({ "previous_status": status_str }),
        None,
        None,
    )
    .await;

    tracing::info!(job_id = %id, user = %auth.username, "Patch job cancelled");
    Ok(Json(json!({ "message": "Job cancelled" })))
}

// ── POST /api/v1/jobs/:id/rollback ────────────────────────────────────────────

async fn rollback_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Admin-only operation.
    if !auth.role.can_write() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Write access required",
        ));
    }

    // Verify the original job exists.
    let original_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM patch_jobs WHERE id = $1)")
            .bind(id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, %id, "rollback_job: existence check failed");
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Database error",
                )
            })?;

    if !original_exists {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "Job not found"));
    }

    // Gather the host IDs from the original job.
    let host_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT host_id FROM patch_job_hosts WHERE job_id = $1")
            .bind(id)
            .fetch_all(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, %id, "rollback_job: host fetch failed");
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Database error",
                )
            })?;

    if host_ids.is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no_hosts",
            "Original job has no host entries to roll back",
        ));
    }

    // Create the rollback job row (immediate = true so the worker picks it up
    // right away and the NOTIFY trigger fires).
    let rollback_job_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO patch_jobs
            (kind, status, created_by_user_id, parent_job_id, immediate,
             patch_selection, notes)
        VALUES
            ('rollback'::job_kind, 'queued'::job_status, $1, $2, TRUE,
             '[]'::jsonb, $3)
        RETURNING id
        "#,
    )
    .bind(auth.user_id)
    .bind(id)
    .bind(format!("Rollback of job {}", id))
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, parent_job_id = %id, "rollback_job: insert failed");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database error",
        )
    })?;

    // Replicate host list into the rollback job.
    for host_id in &host_ids {
        sqlx::query(
            r#"
            INSERT INTO patch_job_hosts (job_id, host_id, status)
            VALUES ($1, $2, 'queued'::job_status)
            ON CONFLICT (job_id, host_id) DO NOTHING
            "#,
        )
        .bind(rollback_job_id)
        .bind(host_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e, %rollback_job_id, %host_id,
                "rollback_job: insert patch_job_hosts failed"
            );
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Database error",
            )
        })?;
    }

    log_event(
        &state.db,
        AuditAction::PatchJobRollback,
        Some(auth.user_id),
        Some(&auth.username),
        Some("job"),
        Some(&rollback_job_id.to_string()),
        json!({
            "original_job_id": id,
            "rollback_job_id": rollback_job_id,
            "host_count": host_ids.len(),
        }),
        None,
        None,
    )
    .await;

    tracing::info!(
        rollback_job_id = %rollback_job_id,
        original_job_id = %id,
        user = %auth.username,
        "Rollback job created"
    );

    Ok(Json(json!({
        "id": rollback_job_id,
        "parent_job_id": id,
        "message": "Rollback job created"
    })))
}
