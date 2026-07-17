//! Upgrade management routes.
//!
//! GET  /api/v1/upgrades/available-versions  — list versions from repo_packages (host-filtered)
//! POST /api/v1/upgrades/trigger             — create a self-upgrade job (operator+)
//!
//! The legacy `refresh_versions` endpoint and `available_versions` /
//! `os_package_mappings` tables have been removed. The manager-hosted
//! package repository (`repo_packages`) is the single source of truth.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use pm_auth::rbac::AuthUser;
use pm_core::audit::{log_event, AuditAction};
use pm_core::models::RepoAvailableVersion;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::AppState;

/// Public (unauthenticated) routes: available-versions listing.
pub fn public_router() -> Router<AppState> {
    Router::new().route("/available-versions", get(list_available_versions))
}

/// Protected (authenticated) routes: trigger (operator+).
pub fn router() -> Router<AppState> {
    Router::new().route("/trigger", post(trigger_upgrade))
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AvailableVersionsQuery {
    /// Required: filter versions by this host's OS → (distro, codename).
    pub host_id: Uuid,
}

// ── Trigger upgrade request/response types ───────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TriggerUpgradeRequest {
    pub host_ids: Vec<Uuid>,
    pub target_version: Option<String>,
    #[serde(default)]
    pub immediate: bool,
    pub maintenance_window_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct SkippedHost {
    host_id: Uuid,
    reason: String,
}

#[derive(Debug, Serialize)]
pub struct TriggerUpgradeResponse {
    job_id: Uuid,
    host_count: usize,
    skipped: Vec<SkippedHost>,
}

// ── OS → (distro, codename) mapping ──────────────────────────────────────────

/// Map a host's `os_name` to `(distro, suite)` for `repo_packages` filtering.
///
/// The suite is the filename token (e.g. `u2404`, `debian12`) used directly
/// as the `dists/<suite>/` directory name. No codename intermediary.
pub(crate) fn map_os_to_distro(os_name: &str) -> Option<(&'static str, Option<&'static str>)> {
    let lower = os_name.to_ascii_lowercase();
    if lower.starts_with("ubuntu") {
        let suite = if lower.contains("24.04") {
            "u2404"
        } else if lower.contains("22.04") {
            "u2204"
        } else if lower.contains("26.04") {
            "u2604"
        } else {
            return Some(("apt", None));
        };
        Some(("apt", Some(suite)))
    } else if lower.starts_with("debian") {
        let suite = if lower.contains("12") || lower.contains("bookworm") {
            "debian12"
        } else if lower.contains("13") || lower.contains("trixie") {
            "debian13"
        } else {
            return Some(("apt", None));
        };
        Some(("apt", Some(suite)))
    } else if lower.starts_with("fedora") || lower.starts_with("almalinux") {
        Some(("dnf", Some("el9")))
    } else if lower.starts_with("alpine") {
        Some(("apk", Some("v3.21")))
    } else if lower.starts_with("arch") {
        Some(("pacman", Some("x86_64")))
    } else {
        None
    }
}

/// Resolve a host's `(distro, codename)` by looking up its `os_name`.
pub(crate) async fn resolve_host_distro(
    pool: &sqlx::PgPool,
    host_id: Uuid,
) -> Result<Option<(String, Option<String>)>, (StatusCode, Json<Value>)> {
    let os_name: Option<String> = sqlx::query_scalar("SELECT os_name FROM hosts WHERE id = $1")
        .bind(host_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %host_id, "Failed to query host OS");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?
        .flatten();

    let os_name = match os_name {
        Some(n) => n,
        None => {
            tracing::debug!(%host_id, "Host has no os_name, cannot resolve distro");
            return Ok(None);
        },
    };

    Ok(map_os_to_distro(&os_name).map(|(d, c)| (d.to_string(), c.map(String::from))))
}

// ── GET /api/v1/upgrades/available-versions ────────────────────────────────────

/// List available agent versions from `repo_packages`, filtered by the
/// host's OS → (distro, codename). Only packages the host can actually
/// install are returned.
async fn list_available_versions(
    State(state): State<AppState>,
    Query(q): Query<AvailableVersionsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (distro, codename) = match resolve_host_distro(&state.db, q.host_id).await? {
        Some(d) => d,
        None => {
            return Ok(Json(json!([])));
        },
    };

    let versions: Vec<RepoAvailableVersion> = sqlx::query_as(
        r#"
        SELECT DISTINCT ON (version)
               version,
               distro,
               distro_codename,
               filename AS file_name,
               published_at
        FROM repo_packages
        WHERE distro = $1
          AND (distro_codename = $2 OR distro_codename IS NULL)
        ORDER BY version DESC, published_at DESC NULLS LAST
        "#,
    )
    .bind(&distro)
    .bind(&codename)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to query repo_packages");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    Ok(Json(serde_json::to_value(&versions).unwrap_or(json!([]))))
}

// ── POST /api/v1/upgrades/trigger ─────────────────────────────────────────────

async fn trigger_upgrade(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<TriggerUpgradeRequest>,
) -> Result<Json<TriggerUpgradeResponse>, (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({ "error": { "code": "forbidden", "message": "Operator or Admin access required" } }),
            ),
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

    let mut skipped: Vec<SkippedHost> = Vec::new();
    let mut valid_hosts: Vec<(Uuid, String)> = Vec::new();

    for host_id in &req.host_ids {
        let host_row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT os_name, agent_version FROM hosts WHERE id = $1",
        )
        .bind(host_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %host_id, "Failed to query host");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        let (os_name, agent_version) = match host_row {
            Some(row) => row,
            None => {
                skipped.push(SkippedHost {
                    host_id: *host_id,
                    reason: "Host not found".to_string(),
                });
                continue;
            },
        };

        let os_name = match os_name {
            Some(n) => n,
            None => {
                skipped.push(SkippedHost {
                    host_id: *host_id,
                    reason: "Host has no OS information".to_string(),
                });
                continue;
            },
        };

        let (distro, codename) = match map_os_to_distro(&os_name) {
            Some(d) => (d.0.to_string(), d.1.map(String::from)),
            None => {
                skipped.push(SkippedHost {
                    host_id: *host_id,
                    reason: format!("Unsupported OS: {os_name}"),
                });
                continue;
            },
        };

        // Fetch available versions for this host's distro+codename from repo_packages.
        let versions: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT version
            FROM repo_packages
            WHERE distro = $1
              AND (distro_codename = $2 OR distro_codename IS NULL)
            ORDER BY version DESC
            "#,
        )
        .bind(&distro)
        .bind(&codename)
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query repo_packages for host");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        let available_versions: Vec<String> = versions.into_iter().map(|r| r.0).collect();

        if available_versions.is_empty() {
            skipped.push(SkippedHost {
                host_id: *host_id,
                reason: "No packages available for this host's OS in the repo".to_string(),
            });
            continue;
        }

        // Resolve target version.
        let resolved_version = match &req.target_version {
            Some(tv) => {
                if !available_versions.iter().any(|v| v == tv) {
                    skipped.push(SkippedHost {
                        host_id: *host_id,
                        reason: format!("Version '{tv}' not available for this host's OS"),
                    });
                    continue;
                }
                tv.clone()
            },
            None => {
                // Latest = first entry (ORDER BY version DESC).
                available_versions[0].clone()
            },
        };

        // Check if host is already at the target version (normalize: strip -N suffix).
        if let Some(ref current) = agent_version {
            let current_norm = current.split('-').next().unwrap_or(current);
            let target_norm = resolved_version
                .split('-')
                .next()
                .unwrap_or(&resolved_version);
            if current_norm == target_norm {
                skipped.push(SkippedHost {
                    host_id: *host_id,
                    reason: format!("Host is already at version {resolved_version}"),
                });
                continue;
            }
        }

        valid_hosts.push((*host_id, resolved_version));
    }

    if valid_hosts.is_empty() {
        return Ok(Json(TriggerUpgradeResponse {
            job_id: Uuid::nil(),
            host_count: 0,
            skipped,
        }));
    }

    // Group valid hosts by resolved version.
    let mut groups: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
    for (host_id, version) in &valid_hosts {
        groups.entry(version.clone()).or_default().push(*host_id);
    }

    let mut first_job_id = Uuid::nil();
    let mut total_host_count = 0usize;

    for (version, host_ids) in &groups {
        let patch_selection = json!({
            "target_version": version,
            "restart": true,
            "restart_delay_seconds": 5
        });

        let job_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO patch_jobs
                (kind, status, created_by_user_id, maintenance_window_id,
                 immediate, patch_selection, notes)
            VALUES
                ('self_upgrade'::job_kind, 'queued'::job_status, $1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(auth.user_id)
        .bind(req.maintenance_window_id)
        .bind(req.immediate)
        .bind(&patch_selection)
        .bind("")
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "trigger_upgrade: insert patch_jobs failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        if first_job_id == Uuid::nil() {
            first_job_id = job_id;
        }

        for host_id in host_ids {
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
                tracing::error!(error = %e, %job_id, %host_id, "trigger_upgrade: insert patch_job_hosts failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                )
            })?;
        }

        total_host_count += host_ids.len();
    }

    let action = if valid_hosts.len() > 1 {
        AuditAction::BatchUpgradeTriggered
    } else {
        AuditAction::UpgradeTriggered
    };

    log_event(
        &state.db,
        action,
        Some(auth.user_id),
        Some(&auth.username),
        Some("upgrade"),
        Some(&first_job_id.to_string()),
        json!({
            "target_versions": groups.keys().collect::<Vec<_>>(),
            "host_count": total_host_count,
            "skipped_count": skipped.len(),
            "immediate": req.immediate,
        }),
        None,
        None,
    )
    .await;

    tracing::info!(
        job_id = %first_job_id,
        host_count = total_host_count,
        skipped_count = skipped.len(),
        immediate = req.immediate,
        user = %auth.username,
        "Self-upgrade job triggered"
    );

    Ok(Json(TriggerUpgradeResponse {
        job_id: first_job_id,
        host_count: total_host_count,
        skipped,
    }))
}
