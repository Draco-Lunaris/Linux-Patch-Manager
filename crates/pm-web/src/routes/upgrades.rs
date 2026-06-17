//! Upgrade management routes.
//!
//! GET  /api/v1/upgrades/available-versions  — list cached versions (no auth)
//! POST /api/v1/upgrades/refresh-versions   — refresh version cache from GitHub (admin)
//! POST /api/v1/upgrades/trigger             — create a self-upgrade job (operator+)

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use pm_auth::rbac::AuthUser;
use pm_core::audit::{log_event, AuditAction};
use pm_core::models::AvailableVersion;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::AppState;

/// Public (unauthenticated) routes: available-versions listing.
pub fn public_router() -> Router<AppState> {
    Router::new().route("/available-versions", get(list_available_versions))
}

/// Protected (authenticated) routes: version refresh (admin) and trigger (operator+).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/refresh-versions", post(refresh_versions))
        .route("/trigger", post(trigger_upgrade))
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AvailableVersionsQuery {
    pub source: Option<String>,
    pub host_id: Option<Uuid>,
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

// ── GET /api/v1/upgrades/available-versions ────────────────────────────────────

async fn list_available_versions(
    State(state): State<AppState>,
    Query(q): Query<AvailableVersionsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut versions: Vec<AvailableVersion> = if let Some(source) = &q.source {
        sqlx::query_as(
            r#"
            SELECT id, version, download_url, checksum, file_name,
                   source, prerelease, published_at, fetched_at
            FROM available_versions
            WHERE source = $1
            ORDER BY published_at DESC
            "#,
        )
        .bind(source)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as(
            r#"
            SELECT id, version, download_url, checksum, file_name,
                   source, prerelease, published_at, fetched_at
            FROM available_versions
            ORDER BY published_at DESC
            "#,
        )
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to list available versions");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    // If host_id is provided, filter versions by OS package mapping
    if let Some(host_id) = q.host_id {
        if let Some(pattern) = lookup_package_pattern(&state, host_id).await? {
            match Regex::new(&pattern) {
                Ok(re) => {
                    versions.retain(|v| re.is_match(&v.file_name));
                },
                Err(e) => {
                    tracing::warn!(pattern = %pattern, error = %e, "Invalid regex in OS package mapping, skipping filter");
                },
            }
        }
        // If no mapping found, return all versions (fallback)
    }

    Ok(Json(serde_json::to_value(&versions).unwrap_or(json!([]))))
}

/// Look up the package pattern for a host's OS.
///
/// Parses the host's `os_name` (e.g. "Ubuntu 24.04") into name and version,
/// then finds the matching `os_package_mapping` entry.
pub(crate) async fn lookup_package_pattern(
    state: &AppState,
    host_id: Uuid,
) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    // Look up the host's os_name
    let os_name: Option<String> = sqlx::query_scalar("SELECT os_name FROM hosts WHERE id = $1")
        .bind(host_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, host_id = %host_id, "Failed to query host OS");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?
        .flatten();

    let os_name = match os_name {
        Some(name) => name,
        None => {
            tracing::debug!(host_id = %host_id, "Host has no os_name, skipping OS filter");
            return Ok(None);
        },
    };

    // Parse os_name into (name, version) using OS-family-aware extraction.
    // Complex OS names like "Debian GNU/Linux 12 (bookworm)" or
    // "Fedora Linux 43 (Container Image) 43" require smarter parsing
    // than a simple space-split.
    let (parsed_name, parsed_version) = {
        // Step 1: Extract OS family name from known prefixes
        let name: &str = if os_name.starts_with("Ubuntu") {
            "Ubuntu"
        } else if os_name.starts_with("Debian") {
            "Debian"
        } else if os_name.starts_with("Fedora") {
            "Fedora"
        } else if os_name.starts_with("AlmaLinux") {
            "AlmaLinux"
        } else if os_name.starts_with("Alpine") {
            "Alpine"
        } else if os_name.starts_with("Arch") {
            "Arch"
        } else {
            // Fallback: take first word as name
            os_name.split_whitespace().next().unwrap_or(&os_name)
        };

        // Step 2: Extract version using OS-family-specific patterns
        let version = if name == "Alpine" || name == "Arch" {
            // Rolling/irrelevant versions → wildcard
            "*".to_string()
        } else if name == "Ubuntu" {
            // Extract first major.minor, e.g. "24.04" from "24.04.4 LTS"
            Regex::new(r"(\d+\.\d+)")
                .ok()
                .and_then(|re| re.captures(&os_name))
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "*".to_string())
        } else if name == "Debian" {
            // Extract version after "GNU/Linux", e.g. "12" from "GNU/Linux 12"
            Regex::new(r"GNU/Linux\s+(\d+)")
                .ok()
                .and_then(|re| re.captures(&os_name))
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "*".to_string())
        } else if name == "Fedora" {
            // Extract version after "Fedora", e.g. "43" from "Fedora Linux 43"
            Regex::new(r"Fedora\s+(?:Linux\s+)?(\d+)")
                .ok()
                .and_then(|re| re.captures(&os_name))
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "*".to_string())
        } else if name == "AlmaLinux" {
            // Extract major version, e.g. "10" from "AlmaLinux 10.2"
            let rest = os_name[name.len()..].trim_start();
            Regex::new(r"(\d+)")
                .ok()
                .and_then(|re| re.captures(rest))
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "*".to_string())
        } else {
            // Fallback: extract first version-like pattern from the string
            Regex::new(r"(\d+(?:\.\d+)?)")
                .ok()
                .and_then(|re| re.captures(&os_name))
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "*".to_string())
        };

        tracing::debug!(
            os_name = %os_name,
            parsed_name = %name,
            parsed_version = %version,
            "Parsed OS name and version"
        );

        (name.to_string(), version)
    };

    // Find matching OS package mapping:
    // - os_name must match exactly
    // - os_version must match exactly OR be '*'
    let pattern: Option<String> = sqlx::query_scalar(
        r#"
        SELECT package_pattern FROM os_package_mappings
        WHERE os_name = $1 AND (os_version = $2 OR os_version = '*')
        ORDER BY os_version = $2 DESC, os_version = '*' DESC
        LIMIT 1
        "#,
    )
    .bind(&parsed_name)
    .bind(&parsed_version)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to query OS package mapping");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?
    .flatten();

    Ok(pattern)
}

// ── POST /api/v1/upgrades/refresh-versions ─────────────────────────────────────

async fn refresh_versions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Admin-only
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Admin access required" } })),
        ));
    }

    // Fetch releases from GitHub API
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.github.com/repos/Draco-Lunaris/Linux-Patch-Api/releases")
        .header("User-Agent", "pm-web")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch GitHub releases");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": { "code": "upstream_error", "message": "Failed to fetch releases from GitHub" } })),
            )
        })?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        tracing::error!(status, body = %body, "GitHub API returned error");
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(
                json!({ "error": { "code": "upstream_error", "message": format!("GitHub API returned {}", status) } }),
            ),
        ));
    }

    let releases: Vec<serde_json::Value> = response.json().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to parse GitHub releases response");
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": { "code": "upstream_error", "message": "Failed to parse releases" } })),
        )
    })?;

    let mut upserted = 0i64;

    for release in &releases {
        let tag_name = release["tag_name"].as_str().unwrap_or("");
        // Strip leading 'v' from tag to get version
        let version = tag_name.strip_prefix('v').unwrap_or(tag_name);
        // Semver pre-release identifiers contain a hyphen (e.g. "1.5.0-beta.1")
        let prerelease = release["prerelease"].as_bool().unwrap_or(false) || version.contains('-');
        let published_at = release["published_at"].as_str();

        let assets = match release["assets"].as_array() {
            Some(a) => a,
            None => continue,
        };

        for asset in assets {
            let file_name = asset["name"].as_str().unwrap_or("");
            let download_url = asset["browser_download_url"].as_str().unwrap_or("");

            // Determine package type from extension
            let pkg_type = if file_name.ends_with(".deb") {
                "deb"
            } else if file_name.ends_with(".rpm") {
                "rpm"
            } else if file_name.ends_with(".apk") {
                "apk"
            } else if file_name.ends_with(".tar.zst") {
                "tar.zst"
            } else {
                continue; // skip non-package assets
            };

            let source = format!("github-{}", pkg_type);

            let result = sqlx::query(
                r#"
                INSERT INTO available_versions
                    (version, download_url, checksum, file_name, source, prerelease, published_at)
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7::timestamptz)
                ON CONFLICT (version, source) DO UPDATE SET
                    download_url = EXCLUDED.download_url,
                    checksum = EXCLUDED.checksum,
                    file_name = EXCLUDED.file_name,
                    prerelease = EXCLUDED.prerelease,
                    published_at = EXCLUDED.published_at,
                    fetched_at = NOW()
                "#,
            )
            .bind(version)
            .bind(download_url)
            .bind(None::<String>) // checksum not available from GitHub release metadata
            .bind(file_name)
            .bind(&source)
            .bind(prerelease)
            .bind(published_at)
            .execute(&state.db)
            .await;

            match result {
                Ok(r) => upserted += r.rows_affected() as i64,
                Err(e) => {
                    tracing::warn!(error = %e, version, source = %source, "Failed to upsert version");
                },
            }
        }
    }

    // Update fetched_at for all github-sourced rows to now
    let _ = sqlx::query(
        "UPDATE available_versions SET fetched_at = NOW() WHERE source LIKE 'github-%'",
    )
    .execute(&state.db)
    .await;

    log_event(
        &state.db,
        AuditAction::UpgradeVersionRefreshed,
        Some(auth.user_id),
        Some(&auth.username),
        Some("upgrade"),
        None,
        json!({ "upserted": upserted }),
        None,
        None,
    )
    .await;

    tracing::info!(upserted, user = %auth.username, "Available versions refreshed");

    Ok(Json(
        json!({ "upserted": upserted, "message": "Versions refreshed" }),
    ))
}

// ── POST /api/v1/upgrades/trigger ─────────────────────────────────────────────

async fn trigger_upgrade(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<TriggerUpgradeRequest>,
) -> Result<Json<TriggerUpgradeResponse>, (StatusCode, Json<Value>)> {
    // RBAC: Operator or Admin only (reject Reporter)
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

    // If target_version is specified, verify it exists in available_versions at all
    if let Some(ref tv) = req.target_version {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM available_versions WHERE version = $1)",
        )
        .bind(tv)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check version existence");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        if !exists {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {
                        "code": "bad_request",
                        "message": format!("Version '{}' not found in available versions", tv)
                    }
                })),
            ));
        }
    }

    let mut skipped: Vec<SkippedHost> = Vec::new();
    let mut valid_hosts: Vec<(Uuid, String)> = Vec::new();

    for host_id in &req.host_ids {
        // Look up host's os_name and agent_version
        let host_row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT os_name, agent_version FROM hosts WHERE id = $1",
        )
        .bind(host_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, host_id = %host_id, "Failed to query host");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

        let (_os_name, agent_version) = match host_row {
            Some(row) => row,
            None => {
                skipped.push(SkippedHost {
                    host_id: *host_id,
                    reason: "Host not found".to_string(),
                });
                continue;
            },
        };

        // Get available versions filtered by host's OS package pattern
        let mut versions = list_host_versions(&state, *host_id).await?;

        // Resolve target version
        let resolved_version = match &req.target_version {
            Some(tv) => {
                // Validate that this version is available for this host's OS
                if !versions.iter().any(|v| &v.version == tv) {
                    skipped.push(SkippedHost {
                        host_id: *host_id,
                        reason: format!("Version '{}' not available for this host's OS", tv),
                    });
                    continue;
                }
                tv.clone()
            },
            None => {
                // Resolve to latest non-prerelease version
                versions.retain(|v| !v.prerelease);
                match versions
                    .iter()
                    .max_by(|a, b| a.published_at.cmp(&b.published_at))
                {
                    Some(v) => v.version.clone(),
                    None => {
                        skipped.push(SkippedHost {
                            host_id: *host_id,
                            reason: "No non-prerelease versions available for this host's OS"
                                .to_string(),
                        });
                        continue;
                    },
                }
            },
        };

        // Check if host is already at the target version
        if let Some(ref current) = agent_version {
            if current == &resolved_version {
                skipped.push(SkippedHost {
                    host_id: *host_id,
                    reason: format!("Host is already at version {}", resolved_version),
                });
                continue;
            }
        }

        valid_hosts.push((*host_id, resolved_version));
    }

    // If no valid hosts remain, return early without creating a job
    if valid_hosts.is_empty() {
        return Ok(Json(TriggerUpgradeResponse {
            job_id: Uuid::nil(),
            host_count: 0,
            skipped,
        }));
    }

    // Group valid hosts by resolved version (different OSes may resolve to different versions)
    let mut groups: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
    for (host_id, version) in &valid_hosts {
        groups.entry(version.clone()).or_default().push(*host_id);
    }

    // Create one job per version group
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
                tracing::error!(
                    error = %e, %job_id, %host_id,
                    "trigger_upgrade: insert patch_job_hosts failed"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                )
            })?;
        }

        total_host_count += host_ids.len();
    }

    // Audit logging
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

/// Fetch available versions filtered by a host's OS package pattern.
async fn list_host_versions(
    state: &AppState,
    host_id: Uuid,
) -> Result<Vec<AvailableVersion>, (StatusCode, Json<Value>)> {
    let mut versions: Vec<AvailableVersion> = sqlx::query_as(
        r#"
        SELECT id, version, download_url, checksum, file_name,
               source, prerelease, published_at, fetched_at
        FROM available_versions
        ORDER BY published_at DESC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to query available versions");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    if let Some(pattern) = lookup_package_pattern(state, host_id).await? {
        match Regex::new(&pattern) {
            Ok(re) => {
                versions.retain(|v| re.is_match(&v.file_name));
            },
            Err(e) => {
                tracing::warn!(pattern = %pattern, error = %e, "Invalid regex in OS package mapping, skipping filter");
            },
        }
    }

    Ok(versions)
}
