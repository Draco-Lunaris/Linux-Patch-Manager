use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::Utc;
use pm_auth::AuthUser;
use pm_core::{
    db,
    models::{
        detect_apt_suite, detect_distro_id, generate_distro_config, ApprovedEntry,
        CreateEnrollmentRequest, EnrollmentRequest, EnrollmentStatusResponse, Host, PkiBundle,
        RepoConfig,
    },
};
use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;

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
/// Rate limiting is handled by tower-governor middleware (per-IP, configurable).
async fn enroll_host(
    State(state): State<AppState>,
    Json(payload): Json<CreateEnrollmentRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Generate secure random polling token
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
    // Hash the provided token to match DB.
    // Security note: the raw polling token is intentionally never logged.
    // Only the SHA-256 hash is stored and compared; all tracing calls in
    // this module log error contexts only, never the token itself.
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
    //    Single-retrieval: remove() atomically consumes the entry, ensuring
    //    the private key can only be fetched once regardless of concurrent requests.
    if let Some((_, entry)) = state.approved_enrollments.remove(&token_hash) {
        if entry.is_expired() {
            // Bundle TTL expired — treat as not found. Entry is already removed.
            return Ok(Json(EnrollmentStatusResponse::NotFound));
        }
        return Ok(Json(EnrollmentStatusResponse::Approved {
            ca_crt: entry.pki.ca_crt.clone(),
            ca_chain: entry.pki.ca_chain.clone(),
            server_crt: entry.pki.server_crt.clone(),
            server_key: entry.pki.server_key.clone(),
            crl_pem: entry.pki.crl_pem.clone(),
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
        "SELECT id, fqdn, ip_address::text, display_name, os_family, os_name, arch, agent_version, health_status, last_health_at, last_patch_at, agent_port, notes, registered_at, updated_at, crl_status, crl_age_seconds, crl_next_update, gpg_key_status, gpg_key_expires_at FROM hosts WHERE fqdn = $1 OR ip_address = $2::inet"
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
    let os_family = enrollment_request
        .os_details
        .get("os")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let os_name = enrollment_request
        .os_details
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            // Build os_name from os + os_version if "name" is absent
            let os = enrollment_request
                .os_details
                .get("os")
                .and_then(|v| v.as_str())?;
            let ver = enrollment_request
                .os_details
                .get("os_version")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Some(format!("{} {}", os, ver).trim().to_string())
        });
    let arch = enrollment_request
        .os_details
        .get("architecture")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let display_name = enrollment_request
        .hostname
        .clone()
        .unwrap_or_else(|| enrollment_request.fqdn.clone());
    sqlx::query(
        r#"
        INSERT INTO hosts (id, fqdn, ip_address, os_family, os_name, arch, display_name, registered_at, updated_at)
        VALUES ($1, $2, $3::inet, $4, $5, $6, $7, NOW(), NOW())
        "#,
    )
    .bind(enrollment_request.id)
    .bind(&enrollment_request.fqdn)
    .bind(enrollment_request.ip_address.to_string())
    .bind(&os_family)
    .bind(&os_name)
    .bind(&arch)
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

    // Store PKI bundle in cache for single-use client retrieval.
    //
    // Design decision — server-generated keys vs CSR-based enrollment:
    // Currently the server generates the agent's private key and transmits it
    // over the (already mTLS-secured) polling endpoint. This approach was chosen
    // for initial implementation simplicity: the agent only needs to poll one
    // endpoint and receives a complete PKI bundle without an extra round-trip.
    //
    // A future enhancement should adopt CSR-based enrollment where the agent
    // generates its own key pair locally and submits a Certificate Signing
    // Request, eliminating the need for the server to ever hold or transmit
    // the agent's private key. This reduces the attack surface significantly
    // — the private key never traverses the network and never resides in
    // server memory beyond the signing operation.
    //
    // See: https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/9
    //
    // Include the full CA chain (for root mode, same as ca_crt; for sub-CA,
    // includes intermediate + root) and the current CRL.
    let ca_chain = issued.ca_root_pem.clone(); // Root mode: chain is just the root cert
    let crl_pem = state.ca.generate_crl(&state.db).await.unwrap_or_default(); // Empty string on failure: agent falls back to WebPKI-only

    // Build repo_config: detect distro from enrollment os_details, read GPG
    // public key, generate distro-specific sources_config and keyring_path.
    // If any step fails, repo_config is None and the agent falls back to
    // GET /api/v1/pki/repo-config (legacy path).
    let repo_config = {
        let os_family = enrollment_request
            .os_details
            .get("distro")
            .and_then(|v| v.as_str());
        let os_name = enrollment_request
            .os_details
            .get("name")
            .and_then(|v| v.as_str());

        match detect_distro_id(os_family, os_name) {
            Some(distro_id) => {
                let repo_cfg = &state.config.repo;
                let os_version = enrollment_request
                    .os_details
                    .get("version")
                    .and_then(|v| v.as_str());
                // Prefer the agent-provided codename from /etc/os-release's
                // VERSION_CODENAME. Only fall back to version-based detection
                // if the agent didn't send one. (Gap analysis HIGH-3)
                let codename = enrollment_request
                    .os_details
                    .get("codename")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| detect_apt_suite(os_version));
                match generate_distro_config(&distro_id, &repo_cfg.url_base, codename.as_deref()) {
                    Some((sources_config, keyring_path)) => {
                        match std::fs::read_to_string(&repo_cfg.gpg_public_key_path) {
                            Ok(gpg_public_key) => {
                                tracing::info!(
                                    distro_id = %distro_id,
                                    gpg_key_path = %repo_cfg.gpg_public_key_path,
                                    "repo_config populated for enrollment"
                                );
                                Some(RepoConfig {
                                    gpg_public_key,
                                    sources_config,
                                    distro_id,
                                    keyring_path,
                                })
                            },
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    path = %repo_cfg.gpg_public_key_path,
                                    "Failed to read GPG public key — repo_config will be None"
                                );
                                None
                            },
                        }
                    },
                    None => {
                        tracing::warn!(
                            distro_id = %distro_id,
                            "generate_distro_config returned None — unsupported distro, repo_config will be None"
                        );
                        None
                    },
                }
            },
            None => {
                tracing::error!(
                    os_family = ?os_family,
                    os_name = ?os_name,
                    "detect_distro_id returned None — unrecognized OS. Agent will be unable to self-update without fallback repo-config. Enrollment continues but this host needs manual repo provisioning or a manager-side distro mapping."
                );
                None
            },
        }
    };

    let pki = PkiBundle {
        ca_crt: issued.ca_root_pem,
        ca_chain,
        server_crt: issued.server_cert_pem,
        server_key: issued.server_key_pem,
        crl_pem,
        repo_config,
    };
    state.approved_enrollments.insert(
        enrollment_request.polling_token.clone(),
        ApprovedEntry::new(pki),
    );

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
