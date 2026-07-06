//! CA / certificate management routes.
//!
//! ca_router()        → mounted at /api/v1/ca
//!   GET  /root.crt                           download_root_ca      (any authed role)
//!   GET  /health                             cert_health           (any authed role)
//!   POST /regenerate                         regenerate_certs      (admin only)
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
    Router::new()
        .route("/root.crt", get(download_root_ca))
        .route("/health", get(cert_health))
        .route("/regenerate", post(regenerate_certs))
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

fn require_write_access(user: &AuthUser) -> Result<(), (StatusCode, Json<Value>)> {
    if !user.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
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
    require_write_access(&auth)?;

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
    require_write_access(&auth)?;

    // Look up the host's IP address from the database.
    let ip_address: String = sqlx::query_scalar("SELECT host(ip_address) FROM hosts WHERE id = $1")
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
    require_write_access(&auth)?;

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
    require_write_access(&auth)?;

    // Look up the host's FQDN and IP address for the new certificate CN and SANs.
    let row = sqlx::query("SELECT fqdn, host(ip_address) AS ip_address FROM hosts WHERE id = $1")
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
    require_write_access(&auth)?;

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

// ── GET /api/v1/ca/health ────────────────────────────────────────────────────

/// Web TLS certificate health details returned by [`cert_health`].
#[derive(Debug, Serialize)]
struct WebTlsHealth {
    cn: Option<String>,
    sans: Vec<String>,
    expiry: Option<String>,
    days_until_expiry: Option<i64>,
    is_fqdn: bool,
    cert_exists: bool,
    error: Option<String>,
}

/// CRL health details returned by [`cert_health`].
#[derive(Debug, Serialize)]
struct CrlHealth {
    status: String,
    last_generated: Option<String>,
    age_seconds: Option<i64>,
    next_update: Option<String>,
    revoked_count: Option<i64>,
    error: Option<String>,
}

/// Parse a PEM-encoded TLS certificate and extract health-relevant fields.
fn parse_web_tls_cert(pem: &str) -> WebTlsHealth {
    use base64::Engine;
    use x509_parser::extensions::GeneralName;

    // Strip PEM headers/footers and decode base64 to DER
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = match base64::engine::general_purpose::STANDARD.decode(&b64) {
        Ok(d) => d,
        Err(e) => {
            return WebTlsHealth {
                cn: None,
                sans: vec![],
                expiry: None,
                days_until_expiry: None,
                is_fqdn: false,
                cert_exists: true,
                error: Some(format!("Failed to decode PEM: {e}")),
            }
        },
    };

    match x509_parser::parse_x509_certificate(&der) {
        Ok((_, cert)) => {
            let cn = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|attr| attr.as_str().ok())
                .map(String::from);

            let sans: Vec<String> = cert
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|san| {
                    san.value
                        .general_names
                        .iter()
                        .filter_map(|gn| {
                            if let GeneralName::DNSName(s) = gn {
                                Some(s.to_string())
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let not_after = cert.validity().not_after;
            let expiry_ts = not_after.timestamp();
            let expiry = chrono::DateTime::from_timestamp(expiry_ts, 0).map(|dt| dt.to_rfc3339());
            let now = chrono::Utc::now();
            let days_until_expiry =
                chrono::DateTime::from_timestamp(expiry_ts, 0).map(|dt| (dt - now).num_days());

            let is_fqdn = cn.as_ref().map(|c| c.contains('.')).unwrap_or(false);

            WebTlsHealth {
                cn,
                sans,
                expiry,
                days_until_expiry,
                is_fqdn,
                cert_exists: true,
                error: None,
            }
        },
        Err(e) => WebTlsHealth {
            cn: None,
            sans: vec![],
            expiry: None,
            days_until_expiry: None,
            is_fqdn: false,
            cert_exists: true,
            error: Some(format!("Failed to parse certificate: {e}")),
        },
    }
}

/// Check CRL generation status by attempting to generate one on the fly.
async fn check_crl_status(state: &AppState) -> CrlHealth {
    match state.ca.generate_crl(&state.db).await {
        Ok(_) => {
            let revoked_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM certificates \
                 WHERE status = 'revoked'::cert_status AND expires_at > NOW()",
            )
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

            let now = chrono::Utc::now();
            CrlHealth {
                status: "available".to_string(),
                last_generated: Some(now.to_rfc3339()),
                age_seconds: Some(0),
                next_update: Some((now + chrono::Duration::hours(24)).to_rfc3339()),
                revoked_count: Some(revoked_count),
                error: None,
            }
        },
        Err(e) => CrlHealth {
            status: "error".to_string(),
            last_generated: None,
            age_seconds: None,
            next_update: None,
            revoked_count: None,
            error: Some(e.to_string()),
        },
    }
}

/// Determine overall health from individual components.
fn determine_health(web_tls: &WebTlsHealth, crl: &CrlHealth) -> String {
    if !web_tls.cert_exists || web_tls.error.is_some() || crl.status == "error" {
        return "critical".to_string();
    }

    if let Some(days) = web_tls.days_until_expiry {
        if days < 0 {
            return "critical".to_string();
        }
        if days < 30 || !web_tls.is_fqdn {
            return "warning".to_string();
        }
    }

    "healthy".to_string()
}

/// Return manager certificate health: web TLS cert details, CRL status, and overall health.
async fn cert_health(
    State(state): State<AppState>,
    _auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cert_path = &state.config.security.web_tls_cert_path;

    let web_tls = match tokio::fs::read_to_string(cert_path).await {
        Ok(pem) => parse_web_tls_cert(&pem),
        Err(_) => WebTlsHealth {
            cn: None,
            sans: vec![],
            expiry: None,
            days_until_expiry: None,
            is_fqdn: false,
            cert_exists: false,
            error: None,
        },
    };

    let crl = check_crl_status(&state).await;
    let overall = determine_health(&web_tls, &crl);

    Ok(Json(json!({
        "web_tls": web_tls,
        "crl": crl,
        "overall": overall,
    })))
}

// ── POST /api/v1/ca/regenerate ───────────────────────────────────────────────

/// Regenerate the web TLS certificate and CRL without touching the CA root.
async fn regenerate_certs(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_write_access(&auth)?;

    // Read the current system FQDN
    let output = tokio::process::Command::new("hostname")
        .arg("-f")
        .output()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to execute hostname -f");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Failed to determine hostname" } })),
            )
        })?;

    let fqdn = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if fqdn.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "error": { "code": "internal_error", "message": "hostname -f returned empty string" } }),
            ),
        ));
    }

    // Issue new web TLS cert using the CA
    let (cert_pem, key_pem) = state.ca.issue_web_tls_cert(&fqdn).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to issue web TLS cert");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
        )
    })?;

    // Write cert and key to configured paths
    let cert_path = std::path::Path::new(&state.config.security.web_tls_cert_path);
    let key_path = std::path::Path::new(&state.config.security.web_tls_key_path);

    if let Some(parent) = cert_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to create cert directory");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Failed to create certificate directory" } })),
            )
        })?;
    }
    if let Some(parent) = key_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to create key directory");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Failed to create key directory" } })),
            )
        })?;
    }

    tokio::fs::write(cert_path, &cert_pem).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to write web TLS cert");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Failed to write certificate file" } })),
        )
    })?;

    // Write key with restricted permissions
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::write(key_path, &key_pem).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to write web TLS key");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Failed to write key file" } })),
            )
        })?;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = tokio::fs::set_permissions(key_path, perms).await; // best-effort
    }

    // Regenerate CRL
    let _crl_pem = state.ca.generate_crl(&state.db).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to regenerate CRL");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": format!("CRL regeneration failed: {e}") } })),
        )
    })?;

    // Parse the new cert for response details
    let parsed = parse_web_tls_cert(&cert_pem);

    log_event(
        &state.db,
        AuditAction::CertificateReissued,
        Some(auth.user_id),
        Some(&auth.username),
        Some("certificate"),
        Some("web_tls"),
        json!({ "operation": "regenerate_server_certs", "hostname": &fqdn }),
        None,
        None,
    )
    .await;

    Ok(Json(json!({
        "common_name": parsed.cn,
        "sans": parsed.sans,
        "expires_at": parsed.expiry,
        "hostname": fqdn,
    })))
}
