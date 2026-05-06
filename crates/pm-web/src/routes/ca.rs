//! CA / certificate management routes.
//!
//! ca_router()        → mounted at /api/v1/ca
//!   GET  /root.crt                           download_root_ca      (any authed role)
//!
//! certs_router()     → mounted at /api/v1/certificates
//!   GET  /                                   list_certificates     (any authed role)
//!   POST /:cert_id/renew                     renew_cert            (admin only)
//!   DELETE /:cert_id                         revoke_cert           (admin only)
//!
//! host_cert_router() → merged under /api/v1/hosts
//!   GET  /:host_id/client.crt                download_client_cert  (admin only)
//!   POST /:host_id/certificates              issue_client_cert     (admin only)
//!   POST /:host_id/certificates/reissue      reissue_host_cert     (admin only)

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, Response, StatusCode},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use chrono::{DateTime, Utc};
use pm_auth::rbac::AuthUser;
use pm_core::audit::{log_event, AuditAction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::AppState;

// ── Router constructors ───────────────────────────────────────────────────────

/// Handles routes mounted at /api/v1/ca
pub fn ca_router() -> Router<AppState> {
    Router::new().route("/root.crt", get(download_root_ca))
}

/// Handles routes mounted at /api/v1/certificates
pub fn certs_router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_certificates))
        .route("/{cert_id}/renew", post(renew_cert))
        .route("/{cert_id}", delete(revoke_cert))
}

/// Handles cert-specific paths merged under /api/v1/hosts.
/// Only adds paths not already claimed by the hosts router.
pub fn host_cert_router() -> Router<AppState> {
    Router::new()
        .route("/{host_id}/client.crt", get(download_client_cert))
        .route("/{host_id}/certificates", post(issue_client_cert))
        .route("/{host_id}/certificates/reissue", post(reissue_host_cert))
}

// ── Shared types ──────────────────────────────────────────────────────────────

/// Row returned from the `certificates` table.
#[derive(Debug, Serialize, sqlx::FromRow)]
struct CertRow {
    id: Uuid,
    host_id: Option<Uuid>,
    serial_number: String,
    common_name: String,
    /// Cast to TEXT in all queries to avoid custom-enum decode.
    status: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

/// Query params for `list_certificates`.
#[derive(Debug, Deserialize)]
struct CertListQuery {
    host_id: Option<Uuid>,
    status: Option<String>,
}

/// Request body for `issue_client_cert`.
#[derive(Debug, Deserialize)]
struct IssueCertRequest {
    hostname: String,
}

// ── Helper: build PEM download response ──────────────────────────────────────

fn pem_response(pem: String, filename: &str) -> Result<Response<Body>, (StatusCode, Json<Value>)> {
    let disposition = format!("attachment; filename=\"{filename}\"");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-pem-file")
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(Body::from(pem))
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to build PEM response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Response build error" } })),
            )
        })
}

// ── Helper: admin-only guard ──────────────────────────────────────────────────

fn require_admin(user: &AuthUser) -> Result<(), (StatusCode, Json<Value>)> {
    if !user.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Admin role required" } })),
        ));
    }
    Ok(())
}

// ── Helper: map sqlx error to 500 ─────────────────────────────────────────────

fn db_error(e: sqlx::Error) -> (StatusCode, Json<Value>) {
    tracing::error!(error = %e, "Database error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
    )
}

// ── Helper: build the full IssuedCert JSON response ──────────────────────────

fn issued_cert_json(issued: &pm_ca::IssuedCert) -> Value {
    json!({
        "cert_pem":            issued.cert_pem,
        "key_pem":             issued.key_pem,
        "serial_number":       issued.serial_number,
        "expires_at":          issued.expires_at,
        "server_cert_pem":     issued.server_cert_pem,
        "server_key_pem":      issued.server_key_pem,
        "server_serial_number": issued.server_serial_number,
        "ca_root_pem":         issued.ca_root_pem,
    })
}

// ── GET /api/v1/ca/root.crt ───────────────────────────────────────────────────

/// Download the root CA certificate as a PEM file.
async fn download_root_ca(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response<Body>, (StatusCode, Json<Value>)> {
    let pem = state.ca.root_cert_pem().to_owned();

    log_event(
        &state.db,
        AuditAction::CertificateDownloaded,
        Some(auth.user_id),
        Some(&auth.username),
        Some("certificate"),
        Some("root_ca"),
        json!({ "operation": "download_root_ca" }),
        None,
        None,
    )
    .await;

    pem_response(pem, "ca.crt")
}

// ── GET /api/v1/certificates ──────────────────────────────────────────────────

/// List certificates with optional `?host_id=` and `?status=` filters.
async fn list_certificates(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(q): Query<CertListQuery>,
) -> Result<Json<Vec<CertRow>>, (StatusCode, Json<Value>)> {
    // Use the non-macro query_as form — avoids needing DATABASE_URL at compile
    // time.  status is cast to TEXT so sqlx decodes it into String directly.
    let rows: Vec<CertRow> = match (q.host_id, q.status.as_deref()) {
        (Some(hid), Some(st)) => {
            sqlx::query_as::<_, CertRow>(
                r#"SELECT id, host_id, serial_number, common_name,
                          status::text AS status,
                          issued_at, expires_at, revoked_at
                   FROM certificates
                   WHERE host_id = $1 AND status::text = $2
                   ORDER BY issued_at DESC"#,
            )
            .bind(hid)
            .bind(st)
            .fetch_all(&state.db)
            .await
        },
        (Some(hid), None) => {
            sqlx::query_as::<_, CertRow>(
                r#"SELECT id, host_id, serial_number, common_name,
                          status::text AS status,
                          issued_at, expires_at, revoked_at
                   FROM certificates
                   WHERE host_id = $1
                   ORDER BY issued_at DESC"#,
            )
            .bind(hid)
            .fetch_all(&state.db)
            .await
        },
        (None, Some(st)) => {
            sqlx::query_as::<_, CertRow>(
                r#"SELECT id, host_id, serial_number, common_name,
                          status::text AS status,
                          issued_at, expires_at, revoked_at
                   FROM certificates
                   WHERE status::text = $1
                   ORDER BY issued_at DESC"#,
            )
            .bind(st)
            .fetch_all(&state.db)
            .await
        },
        (None, None) => {
            sqlx::query_as::<_, CertRow>(
                r#"SELECT id, host_id, serial_number, common_name,
                          status::text AS status,
                          issued_at, expires_at, revoked_at
                   FROM certificates
                   ORDER BY issued_at DESC"#,
            )
            .fetch_all(&state.db)
            .await
        },
    }
    .map_err(db_error)?;

    Ok(Json(rows))
}

// ── GET /api/v1/hosts/:host_id/client.crt ────────────────────────────────────

/// Download the most recent active client certificate PEM for a host.
async fn download_client_cert(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response<Body>, (StatusCode, Json<Value>)> {
    require_admin(&auth)?;

    let cert_pem: Option<String> = sqlx::query_scalar(
        r#"SELECT cert_pem
           FROM certificates
           WHERE host_id = $1
             AND status = 'active'::cert_status
             AND common_name NOT LIKE '%-server'
           ORDER BY issued_at DESC
           LIMIT 1"#,
    )
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %host_id, "Failed to fetch client cert");
        db_error(e)
    })?;

    match cert_pem {
        Some(pem) => {
            log_event(
                &state.db,
                AuditAction::CertificateDownloaded,
                Some(auth.user_id),
                Some(&auth.username),
                Some("certificate"),
                Some(&host_id.to_string()),
                json!({ "operation": "download_client_cert" }),
                None,
                None,
            )
            .await;
            pem_response(pem, "client.crt")
        },
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": {
                    "code": "not_found",
                    "message": "No active certificate found for this host"
                }
            })),
        )),
    }
}

// ── POST /api/v1/hosts/:host_id/certificates ─────────────────────────────────

/// Issue a new mTLS client certificate (and server certificate) for a host.
/// **The private keys are returned only once — the caller must save them.**
async fn issue_client_cert(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(host_id): Path<Uuid>,
    Json(req): Json<IssueCertRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&auth)?;

    // Look up the host's IP address from the database.
    let ip_address: String = sqlx::query_scalar("SELECT ip_address::text FROM hosts WHERE id = $1")
        .bind(host_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %host_id, "Failed to fetch host IP address");
            if e.to_string().contains("no rows") {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": { "code": "not_found", "message": "Host not found" } })),
                )
            } else {
                db_error(e)
            }
        })?;

    let issued = state
        .ca
        .issue_client_cert(host_id, &req.hostname, &ip_address, &state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %host_id, hostname = %req.hostname,
                "Failed to issue client cert");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
            )
        })?;

    log_event(
        &state.db,
        AuditAction::CertificateIssued,
        Some(auth.user_id),
        Some(&auth.username),
        Some("certificate"),
        Some(&host_id.to_string()),
        json!({ "hostname": req.hostname, "serial_number": issued.serial_number, "server_serial_number": issued.server_serial_number }),
        None,
        None,
    )
    .await;

    Ok(Json(issued_cert_json(&issued)))
}

// ── POST /api/v1/certificates/:cert_id/renew ─────────────────────────────────

/// Revoke the specified certificate and issue a replacement with the same CN.
async fn renew_cert(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(cert_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&auth)?;

    let issued = state.ca.renew_cert(cert_id, &state.db).await.map_err(|e| {
        let msg = e.to_string();
        tracing::error!(error = %e, %cert_id, "Failed to renew cert");
        if msg.contains("not found") {
            (
                StatusCode::NOT_FOUND,
                Json(
                    json!({ "error": { "code": "not_found", "message": "Certificate not found" } }),
                ),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": msg } })),
            )
        }
    })?;

    log_event(
        &state.db,
        AuditAction::CertificateRenewed,
        Some(auth.user_id),
        Some(&auth.username),
        Some("certificate"),
        Some(&cert_id.to_string()),
        json!({ "serial_number": issued.serial_number, "server_serial_number": issued.server_serial_number }),
        None,
        None,
    )
    .await;

    Ok(Json(issued_cert_json(&issued)))
}

// ── POST /api/v1/hosts/:host_id/certificates/reissue ────────────────────────

/// Revoke ALL active certificates for a host and issue new ones.
/// The private keys are returned only once — the caller must save them.
async fn reissue_host_cert(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(host_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&auth)?;

    // Look up the host's FQDN and IP address for the new certificate CN and SANs.
    let row = sqlx::query("SELECT fqdn, ip_address::text AS ip_address FROM hosts WHERE id = $1")
        .bind(host_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %host_id, "Failed to fetch host FQDN/IP");
            if e.to_string().contains("no rows") {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": { "code": "not_found", "message": "Host not found" } })),
                )
            } else {
                db_error(e)
            }
        })?;

    let fqdn: String = row.try_get("fqdn").map_err(|e| {
        tracing::error!(error = %e, %host_id, "Failed to read fqdn");
        db_error(e)
    })?;
    let ip_address: String = row.try_get("ip_address").map_err(|e| {
        tracing::error!(error = %e, %host_id, "Failed to read ip_address");
        db_error(e)
    })?;

    // Revoke all active certificates for this host.
    let revoked = sqlx::query(
        "UPDATE certificates SET status = 'revoked'::cert_status, revoked_at = NOW() \
         WHERE host_id = $1 AND status = 'active'::cert_status",
    )
    .bind(host_id)
    .execute(&state.db)
    .await
    .map_err(db_error)?;

    tracing::info!(%host_id, rows_revoked = revoked.rows_affected(), "Revoked all active certs for host");

    // Issue a new certificate bundle using the host's FQDN and IP.
    let issued = state
        .ca
        .issue_client_cert(host_id, &fqdn, &ip_address, &state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %host_id, "Failed to issue new cert during reissue");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
            )
        })?;

    log_event(
        &state.db,
        AuditAction::CertificateReissued,
        Some(auth.user_id),
        Some(&auth.username),
        Some("certificate"),
        Some(&host_id.to_string()),
        json!({ "hostname": &fqdn, "serial_number": issued.serial_number, "server_serial_number": issued.server_serial_number, "rows_revoked": revoked.rows_affected() }),
        None,
        None,
    )
    .await;

    Ok(Json(issued_cert_json(&issued)))
}

// ── DELETE /api/v1/certificates/:cert_id ─────────────────────────────────────

/// Revoke a certificate by ID. Sets status to 'revoked' in the database.
async fn revoke_cert(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(cert_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&auth)?;

    state
        .ca
        .revoke_cert(cert_id, &state.db)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            tracing::error!(error = %e, %cert_id, "Failed to revoke cert");
            if msg.contains("not found") {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": { "code": "not_found", "message": "Certificate not found" } })),
                )
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": msg } })),
                )
            }
        })?;

    tracing::info!(%cert_id, "Certificate revoked via API");

    log_event(
        &state.db,
        AuditAction::CertificateRevoked,
        Some(auth.user_id),
        Some(&auth.username),
        Some("certificate"),
        Some(&cert_id.to_string()),
        json!({ "operation": "revoke" }),
        None,
        None,
    )
    .await;

    Ok(Json(json!({ "revoked": true })))
}
