use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::Utc;
use pm_auth::AuthUser;
use pm_core::{
    db,
    models::{
        CreateEnrollmentRequest, EnrollmentRequest, EnrollmentStatusResponse, Host, PkiBundle,
    },
};
use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct HostConflict {
    pub existing_host: Host,
    pub message: String,
}

/// Define public enrollment routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/enroll", post(enroll_host))
        .route("/enroll/status/{token}", get(enroll_status))
}

/// POST /api/v1/enroll
/// Initiates host self-enrollment.
async fn enroll_host(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateEnrollmentRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // 1. IP-based Rate Limiting
    // Prefer real IP from headers if behind proxy (e.g., X-Forwarded-For)
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split(',').next())
        .and_then(|h| h.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| {
            tracing::warn!(
                "No X-Forwarded-For header found for enrollment request from public endpoint"
            );
            // Default to a placeholder IP since we can't extract the socket addr without the ConnectInfo layer
            "0.0.0.0".parse().unwrap()
        });

    {
        let mut rate_limits = state
            .enrollment_rate_limits
            .entry(ip)
            .or_insert(Instant::now() - std::time::Duration::from_secs(3600));
        let last_request = rate_limits.value();
        if last_request.elapsed().as_secs() < 60 {
            // 1 request per minute per IP
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "Rate limit exceeded. Try again in a minute." })),
            ));
        }
        *rate_limits = Instant::now();
    }

    // 2. Generate secure random polling token
    let polling_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    // For database storage, we'll hash the token (spec says hashed)
    // Using a simple SHA256 or similar for the hash storage
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(polling_token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    // 3. Store in DB
    db::create_enrollment_request(&state.db, payload, token_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create enrollment request");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Database error" })),
            )
        })?;

    // 4. Return the raw token to the client
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "polling_token": polling_token })),
    )
        .into_response())
}

/// GET /api/v1/enroll/status/{token}
/// Returns status of enrollment (pending/approved/denied/not_found).
async fn enroll_status(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<EnrollmentStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Hash the provided token to match DB
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    // 1. Check enrollment_requests table
    let requests = db::list_enrollment_requests(&state.db).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Database error" })),
        )
    })?;

    if let Some(req) = requests.into_iter().find(|r| r.polling_token == token_hash) {
        if req.expires_at < Utc::now() {
            return Ok(Json(EnrollmentStatusResponse::NotFound));
        }
        return Ok(Json(EnrollmentStatusResponse::Pending));
    }

    // 2. If not in pending, check if it was recently approved.
    if let Some(pki) = state.approved_enrollments.get(&token_hash) {
        return Ok(Json(EnrollmentStatusResponse::Approved {
            ca_crt: pki.ca_crt.clone(),
            server_crt: pki.server_crt.clone(),
            server_key: pki.server_key.clone(),
        }));
    }

    Ok(Json(EnrollmentStatusResponse::NotFound))
}

/// Define admin enrollment routes.
pub fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/enrollments", get(list_admin_enrollments))
        .route("/enrollments/{id}/approve", post(approve_enrollment))
        .route("/enrollments/{id}/deny", delete(deny_enrollment))
}

/// GET /api/v1/admin/enrollments
/// Lists all pending enrollment requests.
async fn list_admin_enrollments(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<EnrollmentRequest>>, (StatusCode, Json<serde_json::Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({ "error": { "code": "forbidden", "message": "Admin role required" } }),
            ),
        ));
    }

    db::list_enrollment_requests(&state.db)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list enrollment requests");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Database error" })),
            )
        })
}

/// POST /api/v1/admin/enrollments/{id}/approve
/// Approves a pending enrollment request, generates PKI, and moves to hosts table.
async fn approve_enrollment(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    auth: AuthUser,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({ "error": { "code": "forbidden", "message": "Admin role required" } }),
            ),
        ));
    }

    // Fetch the enrollment request
    let mut requests = db::list_enrollment_requests(&state.db).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to list enrollment requests for approval");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Database error" })),
        )
    })?;

    let enrollment_request = match requests.iter().position(|r| r.id == id) {
        Some(idx) => requests.remove(idx),
        None => return Ok(StatusCode::NOT_FOUND),
    };

    // Check for FQDN/IP collision in hosts table
    if let Some(existing_host) = sqlx::query_as::<_, Host>(
        "SELECT id, fqdn, ip_address::text, display_name, os_family, os_name, arch, agent_version, health_status, last_health_at, last_patch_at, agent_port, notes, registered_at, updated_at FROM hosts WHERE fqdn = $1 OR ip_address = $2::inet"
    )
    .bind(&enrollment_request.fqdn)
    .bind(enrollment_request.ip_address.to_string())
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to check for host collision");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })? {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "Host collision detected", "conflict": HostConflict { existing_host, message: "FQDN or IP already exists".to_string() } }))
        ));
    }

    // Move to hosts table FIRST (certificates table has FK reference to hosts)
    let os_name = enrollment_request
        .os_details
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let display_name = enrollment_request
        .hostname
        .clone()
        .unwrap_or_else(|| enrollment_request.fqdn.clone());
    sqlx::query(
        r#"
        INSERT INTO hosts (id, fqdn, ip_address, os_name, display_name, registered_at, updated_at)
        VALUES ($1, $2, $3::inet, $4, $5, NOW(), NOW())
        "#,
    )
    .bind(enrollment_request.id)
    .bind(&enrollment_request.fqdn)
    .bind(enrollment_request.ip_address.to_string())
    .bind(os_name)
    .bind(&display_name)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to insert host after approval");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Database error" })),
        )
    })?;

    // Generate PKI bundle using CA (after host row exists)
    let issued = state
        .ca
        .issue_client_cert(
            enrollment_request.id,
            &enrollment_request.fqdn,
            &enrollment_request.ip_address.to_string(),
            &state.db,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to issue client certificate");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Certificate generation failed" })),
            )
        })?;

    // Delete from enrollment_requests table
    db::delete_enrollment_request(&state.db, id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to delete enrollment request after approval");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Database error" })),
            )
        })?;

    // Store PKI bundle in cache for client retrieval
    let pki = PkiBundle {
        ca_crt: issued.ca_root_pem,
        server_crt: issued.server_cert_pem,
        server_key: issued.server_key_pem,
    };
    state
        .approved_enrollments
        .insert(enrollment_request.polling_token.clone(), pki);

    Ok(StatusCode::OK)
}

/// DELETE /api/v1/admin/enrollments/{id}/deny
/// Denies and purges a pending enrollment request.
async fn deny_enrollment(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    auth: AuthUser,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({ "error": { "code": "forbidden", "message": "Admin role required" } }),
            ),
        ));
    }

    db::delete_enrollment_request(&state.db, id)
        .await
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to deny enrollment request");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Database error" })),
            )
        })
}
