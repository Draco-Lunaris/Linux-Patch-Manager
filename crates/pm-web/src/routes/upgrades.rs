//! Upgrade management routes.
//!
//! GET  /api/v1/upgrades/available-versions  — list cached versions (no auth)
//! POST /api/v1/upgrades/refresh-versions   — refresh version cache from GitHub (admin)

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
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

/// Public (unauthenticated) routes: available-versions listing.
pub fn public_router() -> Router<AppState> {
    Router::new().route("/available-versions", get(list_available_versions))
}

/// Protected (authenticated) routes: version refresh (admin).
pub fn router() -> Router<AppState> {
    Router::new().route("/refresh-versions", post(refresh_versions))
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AvailableVersionsQuery {
    pub source: Option<String>,
    pub host_id: Option<Uuid>,
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

    Ok(Json(json!({ "versions": versions })))
}

/// Look up the package pattern for a host's OS.
///
/// Parses the host's `os_name` (e.g. "Ubuntu 24.04") into name and version,
/// then finds the matching `os_package_mapping` entry.
async fn lookup_package_pattern(
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

    // Parse os_name into (name, version), e.g. "Ubuntu 24.04" -> ("Ubuntu", "24.04")
    let (parsed_name, parsed_version) = match os_name.split_once(' ') {
        Some((n, v)) => (n.to_string(), v.to_string()),
        None => {
            // os_name is a single word (e.g. "Alpine"), use it as-is with wildcard version
            tracing::debug!(os_name = %os_name, "os_name has no version part, using as name only");
            (os_name, String::from("*"))
        },
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
