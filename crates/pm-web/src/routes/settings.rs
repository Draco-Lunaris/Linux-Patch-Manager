//! Settings management routes.
//!
//! GET  /api/v1/settings              — get all settings (admin only)
//! PUT  /api/v1/settings              — update settings (admin only)
//! POST /api/v1/settings/sso/discover — discover OIDC endpoints (admin only)
//! POST /api/v1/settings/sso/test     — test OIDC provider connectivity (admin only)
//! POST /api/v1/settings/azure-sso/test — backward-compat alias for SSO test (admin only)
//! POST /api/v1/settings/smtp/test    — send test email (admin only)
//! GET  /api/v1/settings/ip-whitelist — get IP whitelist (admin only)
//! PUT  /api/v1/settings/ip-whitelist — update IP whitelist (admin only)
//! POST /api/v1/settings/audit-integrity          — verify audit log integrity (admin only)
//! POST /api/v1/settings/audit-integrity/repair   — repair audit hash chain (admin only)

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use pm_auth::rbac::AuthUser;
use pm_core::audit::{log_event, repair_integrity, verify_integrity, AuditAction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::AppState;

// ============================================================
// Data structures
// ============================================================

#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    pub oidc: OidcConfigResponse,
    pub smtp: SmtpConfig,
    pub polling: PollingConfig,
    pub ip_whitelist: Vec<String>,
    pub web_tls_strategy: String,
    pub notification: NotificationConfig,
    pub sso_callback_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcConfigResponse {
    pub enabled: bool,
    pub provider_type: String, // "keycloak", "azure", "custom"
    pub display_name: String,
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String, // Always masked in responses
    pub redirect_uri: String,
    pub scopes: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from: String,
    pub tls_mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PollingConfig {
    pub health_poll_interval_secs: u64,
    pub patch_poll_interval_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub oidc: Option<OidcConfigUpdate>,
    pub smtp: Option<SmtpConfigUpdate>,
    pub polling: Option<PollingConfigUpdate>,
    pub ip_whitelist: Option<Vec<String>>,
    pub web_tls_strategy: Option<String>,
    pub notification: Option<NotificationConfigUpdate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub email_enabled: bool,
    pub email_from: String,
    pub recipients: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct NotificationConfigUpdate {
    pub email_enabled: Option<bool>,
    pub email_from: Option<String>,
    pub recipients: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct OidcConfigUpdate {
    pub enabled: Option<bool>,
    pub provider_type: Option<String>,
    pub display_name: Option<String>,
    pub discovery_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub scopes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OidcDiscoveryRequest {
    pub discovery_url: String,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct OidcDiscoveryResult {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SmtpConfigUpdate {
    pub enabled: Option<bool>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: Option<String>,
    pub tls_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PollingConfigUpdate {
    pub health_poll_interval_secs: Option<u64>,
    pub patch_poll_interval_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct IpWhitelistUpdate {
    pub entries: Vec<String>,
}

// ============================================================
// Router
// ============================================================

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_settings).put(update_settings))
        .route("/sso/discover", post(discover_oidc))
        .route("/sso/test", post(test_oidc))
        .route("/azure-sso/test", post(test_azure_sso_compat))
        .route("/smtp/test", post(test_smtp))
        .route(
            "/ip-whitelist",
            get(get_ip_whitelist).put(update_ip_whitelist),
        )
        .route("/audit-integrity", post(audit_integrity))
        .route("/audit-integrity/repair", post(audit_integrity_repair))
}

// ============================================================
// Helpers
// ============================================================

const MASKED: &str = "********";

fn write_access_required(auth: &AuthUser) -> Result<(), (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }
    Ok(())
}

/// Gate Manager-wide authentication configuration (OIDC, SMTP, IP allowlist,
/// OIDC discover/test) behind the **Admin** role. Operators can still
/// access per-host settings (see `write_access_required`).
///
/// Returns `403 forbidden_role` if the user is not an Admin. The distinct
/// error code (vs `forbidden` from `write_access_required`) lets the SPA
/// differentiate "you don't have write access at all" from "you have
/// write access but not for this specific resource".
///
/// See issue #5 and `tasks/authz-gate-spec.md` for the full design.
fn admin_required(auth: &AuthUser) -> Result<(), (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({ "error": { "code": "forbidden_role", "message": "Admin role required to modify this resource" } }),
            ),
        ));
    }
    Ok(())
}

async fn load_system_config(
    pool: &sqlx::PgPool,
) -> Result<HashMap<String, String>, (StatusCode, Json<Value>)> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM system_config")
        .fetch_all(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to load system_config");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;

    Ok(rows.into_iter().collect())
}

fn build_settings_response(
    cfg: &HashMap<String, String>,
    oidc: OidcConfigResponse,
) -> SettingsResponse {
    let get = |key: &str| -> String { cfg.get(key).cloned().unwrap_or_default() };

    let recipients: Vec<String> =
        serde_json::from_str(&get("notification_email_recipients")).unwrap_or_default();

    SettingsResponse {
        oidc,
        smtp: SmtpConfig {
            enabled: get("smtp_enabled") == "true",
            host: get("smtp_host"),
            port: get("smtp_port").parse().unwrap_or(587),
            username: get("smtp_username"),
            from: get("smtp_from"),
            tls_mode: get("smtp_tls_mode"),
        },
        polling: PollingConfig {
            health_poll_interval_secs: get("health_poll_interval_secs").parse().unwrap_or(300),
            patch_poll_interval_secs: get("patch_poll_interval_secs").parse().unwrap_or(1800),
        },
        ip_whitelist: serde_json::from_str(&get("ip_whitelist")).unwrap_or_default(),
        web_tls_strategy: get("web_tls_strategy"),
        notification: NotificationConfig {
            email_enabled: get("notification_email_enabled") == "true",
            email_from: get("notification_email_from"),
            recipients,
        },
        sso_callback_url: get("sso_callback_url"),
    }
}

async fn update_config_key(
    pool: &sqlx::PgPool,
    key: &str,
    value: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    sqlx::query("UPDATE system_config SET value = $1, updated_at = NOW() WHERE key = $2")
        .bind(value)
        .bind(key)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, key, "Failed to update system_config");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
            )
        })?;
    Ok(())
}

/// Tuple type for SELECT from oidc_config table (used by fetch_oidc_config).
type OidcConfigRow = (
    bool,
    String,
    String,
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    String,
    String,
);
async fn fetch_oidc_config(
    pool: &sqlx::PgPool,
) -> Result<OidcConfigResponse, (StatusCode, Json<Value>)> {
    let row: Option<OidcConfigRow> = sqlx::query_as(
        "SELECT enabled, provider_type, display_name, discovery_url, client_id, client_secret_encrypted, client_secret_nonce, redirect_uri, scopes FROM oidc_config WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to load oidc_config");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    Ok(match row {
        Some((
            enabled,
            provider_type,
            display_name,
            discovery_url,
            client_id,
            client_secret_encrypted,
            _client_secret_nonce,
            redirect_uri,
            scopes,
        )) => OidcConfigResponse {
            enabled,
            provider_type,
            display_name,
            discovery_url,
            client_id,
            client_secret: if client_secret_encrypted.is_none() {
                String::new()
            } else {
                MASKED.to_string()
            },
            redirect_uri,
            scopes,
        },
        None => OidcConfigResponse {
            enabled: false,
            provider_type: "azure".to_string(),
            display_name: "Azure AD".to_string(),
            discovery_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scopes: "openid profile email".to_string(),
        },
    })
}

// ============================================================
// GET /api/v1/settings
// ============================================================

async fn get_settings(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SettingsResponse>, (StatusCode, Json<Value>)> {
    write_access_required(&auth)?;
    let cfg = load_system_config(&state.db).await?;
    // Inject read-only config values from TOML file (not stored in DB)
    let mut cfg = cfg;
    cfg.insert(
        "sso_callback_url".to_string(),
        state.config.security.sso_callback_url.clone(),
    );
    let oidc = fetch_oidc_config(&state.db).await?;
    Ok(Json(build_settings_response(&cfg, oidc)))
}

// ============================================================
// PUT /api/v1/settings
// ============================================================

async fn update_settings(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<SettingsResponse>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    // Update OIDC config
    if let Some(oidc) = req.oidc {
        let update_secret = oidc
            .client_secret
            .as_ref()
            .is_some_and(|s| s != MASKED && !s.is_empty());

        let result = if update_secret {
            // Encrypt the client_secret before persisting
            let key = crate::secret_key::get().map_err(|e| {
                tracing::error!(error = %e, "Failed to load secret-encryption key");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Encryption key error" } })),
                )
            })?;
            let plaintext = oidc.client_secret.as_deref().unwrap_or("");
            let (ciphertext, nonce) = pm_core::crypto::encrypt(plaintext, key).map_err(|e| {
                tracing::error!(error = %e, "Failed to encrypt OIDC client_secret");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": { "code": "internal_error", "message": "Encryption error" } })),
                )
            })?;
            sqlx::query(
                "UPDATE oidc_config SET \
                 enabled = COALESCE($1, enabled), \
                 provider_type = COALESCE($2, provider_type), \
                 display_name = COALESCE($3, display_name), \
                 discovery_url = COALESCE($4, discovery_url), \
                 client_id = COALESCE($5, client_id), \
                 client_secret_encrypted = $6, \
                 client_secret_nonce = $7, \
                 redirect_uri = COALESCE($8, redirect_uri), \
                 scopes = COALESCE($9, scopes), \
                 updated_at = NOW() \
                 WHERE id = 1",
            )
            .bind(oidc.enabled)
            .bind(&oidc.provider_type)
            .bind(&oidc.display_name)
            .bind(&oidc.discovery_url)
            .bind(&oidc.client_id)
            .bind(&ciphertext)
            .bind(&nonce)
            .bind(&oidc.redirect_uri)
            .bind(&oidc.scopes)
            .execute(&state.db)
            .await
        } else {
            sqlx::query(
                "UPDATE oidc_config SET \
                 enabled = COALESCE($1, enabled), \
                 provider_type = COALESCE($2, provider_type), \
                 display_name = COALESCE($3, display_name), \
                 discovery_url = COALESCE($4, discovery_url), \
                 client_id = COALESCE($5, client_id), \
                 redirect_uri = COALESCE($6, redirect_uri), \
                 scopes = COALESCE($7, scopes), \
                 updated_at = NOW() \
                 WHERE id = 1",
            )
            .bind(oidc.enabled)
            .bind(&oidc.provider_type)
            .bind(&oidc.display_name)
            .bind(&oidc.discovery_url)
            .bind(&oidc.client_id)
            .bind(&oidc.redirect_uri)
            .bind(&oidc.scopes)
            .execute(&state.db)
            .await
        };

        result.map_err(|e| {
            tracing::error!(error = %e, "Failed to update oidc_config");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": format!("Failed to update OIDC config: {}", e) } })),
            )
        })?;

        log_event(
            &state.db,
            AuditAction::OidcConfigUpdated,
            Some(auth.user_id),
            Some(&auth.username),
            Some("oidc"),
            Some("1"),
            json!({ "section": "oidc" }),
            None,
            None,
        )
        .await;
    }

    // Update SMTP config
    if let Some(smtp) = &req.smtp {
        if let Some(v) = smtp.enabled {
            update_config_key(&state.db, "smtp_enabled", &v.to_string()).await?;
        }
        if let Some(ref v) = smtp.host {
            update_config_key(&state.db, "smtp_host", v).await?;
        }
        if let Some(v) = smtp.port {
            update_config_key(&state.db, "smtp_port", &v.to_string()).await?;
        }
        if let Some(ref v) = smtp.username {
            update_config_key(&state.db, "smtp_username", v).await?;
        }
        if let Some(ref v) = smtp.password {
            if v != MASKED {
                // Encrypt the SMTP password before persisting
                let key = crate::secret_key::get().map_err(|e| {
                    tracing::error!(error = %e, "Failed to load secret-encryption key");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": { "code": "internal_error", "message": "Encryption key error" } })),
                    )
                })?;
                let (ciphertext, nonce) = pm_core::crypto::encrypt(v, key).map_err(|e| {
                    tracing::error!(error = %e, "Failed to encrypt SMTP password");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": { "code": "internal_error", "message": "Encryption error" } })),
                    )
                })?;
                // Delete old plaintext row, write two new rows (encrypted + nonce)
                sqlx::query("DELETE FROM system_config WHERE key = 'smtp_password'")
                    .execute(&state.db)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to delete old smtp_password row");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                        )
                    })?;
                // Store as hex in TEXT columns (system_config uses TEXT)
                let enc_hex: String = ciphertext.iter().map(|b| format!("{:02x}", b)).collect();
                let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
                sqlx::query("INSERT INTO system_config (key, value) VALUES ($1, $2)")
                    .bind("smtp_password_encrypted")
                    .bind(&enc_hex)
                    .execute(&state.db)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to write smtp_password_encrypted");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                        )
                    })?;
                sqlx::query("INSERT INTO system_config (key, value) VALUES ($1, $2)")
                    .bind("smtp_password_nonce")
                    .bind(&nonce_hex)
                    .execute(&state.db)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to write smtp_password_nonce");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
                        )
                    })?;
            }
        }
        if let Some(ref v) = smtp.from {
            update_config_key(&state.db, "smtp_from", v).await?;
        }
        if let Some(ref v) = smtp.tls_mode {
            update_config_key(&state.db, "smtp_tls_mode", v).await?;
        }

        log_event(
            &state.db,
            AuditAction::SmtpConfigUpdated,
            Some(auth.user_id),
            Some(&auth.username),
            Some("smtp"),
            Some("system_config"),
            json!({ "section": "smtp" }),
            None,
            None,
        )
        .await;
    }

    // Update polling config
    if let Some(polling) = &req.polling {
        if let Some(v) = polling.health_poll_interval_secs {
            update_config_key(&state.db, "health_poll_interval_secs", &v.to_string()).await?;
        }
        if let Some(v) = polling.patch_poll_interval_secs {
            update_config_key(&state.db, "patch_poll_interval_secs", &v.to_string()).await?;
        }

        log_event(
            &state.db,
            AuditAction::ConfigChanged,
            Some(auth.user_id),
            Some(&auth.username),
            Some("polling"),
            Some("system_config"),
            json!({ "section": "polling" }),
            None,
            None,
        )
        .await;
    }

    // Update IP whitelist
    if let Some(ref entries) = req.ip_whitelist {
        let json_str = serde_json::to_string(entries).unwrap_or_else(|_| "[]".to_string());
        update_config_key(&state.db, "ip_whitelist", &json_str).await?;

        // Update in-memory AuthConfig for immediate enforcement
        state.auth_config.update_ip_whitelist(entries.clone());

        log_event(
            &state.db,
            AuditAction::IpWhitelistUpdated,
            Some(auth.user_id),
            Some(&auth.username),
            Some("ip_whitelist"),
            Some("system_config"),
            json!({ "entries": entries }),
            None,
            None,
        )
        .await;
    }

    // Update web TLS strategy
    if let Some(ref v) = req.web_tls_strategy {
        update_config_key(&state.db, "web_tls_strategy", v).await?;

        log_event(
            &state.db,
            AuditAction::ConfigChanged,
            Some(auth.user_id),
            Some(&auth.username),
            Some("web_tls_strategy"),
            Some("system_config"),
            json!({ "web_tls_strategy": v }),
            None,
            None,
        )
        .await;
    }

    // Update notification config
    if let Some(notif) = &req.notification {
        if let Some(v) = notif.email_enabled {
            update_config_key(&state.db, "notification_email_enabled", &v.to_string()).await?;
        }
        if let Some(ref v) = notif.email_from {
            update_config_key(&state.db, "notification_email_from", v).await?;
        }
        if let Some(ref v) = notif.recipients {
            let json_str = serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string());
            update_config_key(&state.db, "notification_email_recipients", &json_str).await?;
        }

        log_event(
            &state.db,
            AuditAction::ConfigChanged,
            Some(auth.user_id),
            Some(&auth.username),
            Some("notification"),
            Some("system_config"),
            json!({ "section": "notification" }),
            None,
            None,
        )
        .await;
    }

    // Return updated settings
    let cfg = load_system_config(&state.db).await?;
    // Inject read-only config values from TOML file (not stored in DB)
    let mut cfg = cfg;
    cfg.insert(
        "sso_callback_url".to_string(),
        state.config.security.sso_callback_url.clone(),
    );
    let oidc = fetch_oidc_config(&state.db).await?;
    Ok(Json(build_settings_response(&cfg, oidc)))
}

// ============================================================
// POST /api/v1/settings/sso/discover
// ============================================================

async fn discover_oidc(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<OidcDiscoveryRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    if req.discovery_url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "bad_request", "message": "discovery_url is required" } }),
            ),
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to build HTTP client");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "HTTP client error" } })),
            )
        })?;

    match client.get(&req.discovery_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: Value = resp.json().await.unwrap_or(json!({}));
            // Audit log: Admin probed the OIDC discovery endpoint (issue #5).
            // Non-fatal: log_event logs errors internally and does not propagate.
            log_event(
                &state.db,
                AuditAction::OidcDiscoverPerformed,
                Some(auth.user_id),
                Some(&auth.username),
                Some("oidc"),
                Some(&req.discovery_url),
                json!({ "discovery_url": req.discovery_url }),
                None,
                None,
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "issuer": body.get("issuer").and_then(|v| v.as_str()).unwrap_or(""),
                "authorization_endpoint": body.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or(""),
                "token_endpoint": body.get("token_endpoint").and_then(|v| v.as_str()).unwrap_or(""),
                "jwks_uri": body.get("jwks_uri").and_then(|v| v.as_str()).unwrap_or(""),
                "userinfo_endpoint": body.get("userinfo_endpoint").and_then(|v| v.as_str()),
            })))
        },
        Ok(resp) => Err((
            StatusCode::BAD_GATEWAY,
            Json(
                json!({ "error": { "code": "discovery_failed", "message": format!("Discovery endpoint returned HTTP {}", resp.status()) } }),
            ),
        )),
        Err(e) => Err((
            StatusCode::BAD_GATEWAY,
            Json(
                json!({ "error": { "code": "discovery_failed", "message": format!("Failed to reach discovery endpoint: {}", e) } }),
            ),
        )),
    }
}

// ============================================================
// POST /api/v1/settings/sso/test
// ============================================================

async fn test_oidc(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    let row: Option<(bool, String, String)> = sqlx::query_as(
        "SELECT enabled, provider_type, discovery_url FROM oidc_config WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to load oidc_config");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let (enabled, provider_type, discovery_url) = match row {
        Some(r) => r,
        None => {
            return Ok(Json(json!({
                "success": false,
                "message": "OIDC is not configured"
            })));
        },
    };

    if !enabled {
        return Ok(Json(json!({
            "success": false,
            "message": "OIDC is not enabled"
        })));
    }

    if discovery_url.is_empty() {
        return Ok(Json(json!({
            "success": false,
            "message": "OIDC discovery URL is not set"
        })));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to build HTTP client");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": "HTTP client error" } })),
            )
        })?;

    match client.get(&discovery_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: Value = resp.json().await.unwrap_or(json!({}));
            let issuer = body.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
            let provider_label = match provider_type.as_str() {
                "keycloak" => "Keycloak",
                "azure" => "Azure AD",
                _ => "OIDC",
            };
            // Audit log: Admin tested the OIDC provider connection (issue #5).
            // Non-fatal: log_event logs errors internally and does not propagate.
            log_event(
                &state.db,
                AuditAction::OidcTestPerformed,
                Some(auth.user_id),
                Some(&auth.username),
                Some("oidc"),
                Some(&discovery_url),
                json!({
                    "discovery_url": discovery_url,
                    "provider_type": provider_type,
                }),
                None,
                None,
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": format!("{} provider verified successfully", provider_label),
                "issuer": issuer,
                "provider_type": provider_type,
            })))
        },
        Ok(resp) => Ok(Json(json!({
            "success": false,
            "message": format!("Failed to reach OIDC provider: HTTP {}", resp.status())
        }))),
        Err(e) => Ok(Json(json!({
            "success": false,
            "message": format!("Failed to reach OIDC provider: {}", e)
        }))),
    }
}

// Note: OIDC test audit log is emitted in the success path below.
// The above error cases don't persist, so no audit log is needed for them.

// ============================================================
// POST /api/v1/settings/azure-sso/test (backward-compatible alias)
// ============================================================

async fn test_azure_sso_compat(
    state: State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    test_oidc(state, auth).await
}

// ============================================================
// POST /api/v1/settings/smtp/test
// ============================================================

async fn test_smtp(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    write_access_required(&auth)?;

    let cfg = load_system_config(&state.db).await?;

    let smtp_enabled = cfg.get("smtp_enabled").map(|v| v.as_str()) == Some("true");
    if !smtp_enabled {
        return Ok(Json(json!({
            "success": false,
            "message": "SMTP is not enabled"
        })));
    }

    let host = cfg.get("smtp_host").cloned().unwrap_or_default();
    let port: u16 = cfg
        .get("smtp_port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(587);
    let username = cfg.get("smtp_username").cloned().unwrap_or_default();
    // Decrypt the SMTP password (issue #6 fix — stored as two rows in system_config:
    // `smtp_password_encrypted` (hex) and `smtp_password_nonce` (hex))
    let password = match (
        cfg.get("smtp_password_encrypted"),
        cfg.get("smtp_password_nonce"),
    ) {
        (Some(enc_hex), Some(nonce_hex)) => {
            let key = match crate::secret_key::get() {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to load secret-encryption key");
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({ "error": { "code": "internal_error", "message": "Encryption key error" } }),
                        ),
                    ));
                },
            };
            // Decode hex to bytes (hex_decode returns empty Vec on invalid input)
            let enc_bytes = hex_decode(enc_hex);
            let nonce_bytes = hex_decode(nonce_hex);
            pm_core::crypto::decrypt(&enc_bytes, &nonce_bytes, key).unwrap_or_default()
        },
        _ => String::new(),
    };
    let from_addr = cfg.get("smtp_from").cloned().unwrap_or_default();
    let tls_mode = cfg
        .get("smtp_tls_mode")
        .cloned()
        .unwrap_or_else(|| "starttls".to_string());

    let recipients_str = cfg
        .get("notification_email_recipients")
        .cloned()
        .unwrap_or_default();
    let recipients: Vec<String> = serde_json::from_str(&recipients_str).unwrap_or_default();

    if host.is_empty() || from_addr.is_empty() {
        return Ok(Json(json!({
            "success": false,
            "message": "SMTP host or from address is not configured"
        })));
    }

    let result = send_smtp_test(
        &host,
        port,
        &username,
        &password,
        &from_addr,
        &tls_mode,
        &recipients,
    )
    .await;

    match result {
        Ok(()) => {
            let recipient_info = if recipients.is_empty() {
                String::new()
            } else {
                format!(" and {} recipient(s)", recipients.len())
            };
            Ok(Json(json!({
                "success": true,
                "message": format!("Test email sent successfully to from address{}", recipient_info)
            })))
        },
        Err(e) => Ok(Json(json!({
            "success": false,
            "message": format!("Failed to send test email: {}", e)
        }))),
    }
}

async fn send_smtp_test(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    from_addr: &str,
    tls_mode: &str,
    recipients: &[String],
) -> Result<(), String> {
    let from_mailbox: Mailbox = from_addr
        .parse()
        .map_err(|e| format!("Invalid from address: {}", e))?;

    let mut builder = Message::builder()
        .from(from_mailbox.clone())
        .to(from_mailbox);

    for recipient in recipients {
        if let Ok(addr) = recipient.parse() {
            builder = builder.bcc(addr);
        }
    }

    let body = if recipients.is_empty() {
        "This is a test email from Linux Patch Manager.".to_string()
    } else {
        format!(
            "This is a test email from Linux Patch Manager.\n\nSent to: {}",
            recipients.join(", ")
        )
    };

    let email = builder
        .subject("Linux Patch Manager — SMTP Test")
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|e| format!("Failed to build email: {}", e))?;

    let result = match tls_mode {
        "tls" => {
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|e| format!("TLS relay error: {}", e))?;
            builder = builder.port(port);
            if !username.is_empty() {
                builder = builder
                    .credentials(Credentials::new(username.to_string(), password.to_string()));
            }
            let transport = builder.build();
            transport.send(email).await
        },
        "starttls" => {
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|e| format!("STARTTLS relay error: {}", e))?;
            builder = builder.port(port);
            if !username.is_empty() {
                builder = builder
                    .credentials(Credentials::new(username.to_string(), password.to_string()));
            }
            let transport = builder.build();
            transport.send(email).await
        },
        _ => {
            // "none" — plaintext / no TLS
            let mut builder =
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(port);
            if !username.is_empty() {
                builder = builder
                    .credentials(Credentials::new(username.to_string(), password.to_string()));
            }
            let transport = builder.build();
            transport.send(email).await
        },
    };

    result
        .map(|_| ())
        .map_err(|e| format!("SMTP send error: {}", e))
}

// ============================================================
// GET /api/v1/settings/ip-whitelist
// ============================================================

async fn get_ip_whitelist(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    write_access_required(&auth)?;

    let value: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_config WHERE key = 'ip_whitelist'",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to load ip_whitelist");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let entries: Vec<String> = serde_json::from_str(&value.unwrap_or_default()).unwrap_or_default();
    Ok(Json(json!({ "entries": entries })))
}

// ============================================================
// PUT /api/v1/settings/ip-whitelist
// ============================================================

async fn update_ip_whitelist(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<IpWhitelistUpdate>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    // Validate each entry
    for entry in &req.entries {
        if entry.parse::<ipnet::IpNet>().is_err() && entry.parse::<std::net::IpAddr>().is_err() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": { "code": "bad_request", "message": format!("Invalid CIDR or IP: {}", entry) } }),
                ),
            ));
        }
    }

    let json_str = serde_json::to_string(&req.entries).unwrap_or_else(|_| "[]".to_string());
    update_config_key(&state.db, "ip_whitelist", &json_str).await?;

    // Update in-memory AuthConfig for immediate enforcement
    state.auth_config.update_ip_whitelist(req.entries.clone());

    log_event(
        &state.db,
        AuditAction::IpWhitelistUpdated,
        Some(auth.user_id),
        Some(&auth.username),
        Some("ip_whitelist"),
        Some("system_config"),
        json!({ "entries": req.entries }),
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "entries": req.entries })))
}

// ============================================================
// POST /api/v1/settings/audit-integrity
// ============================================================

/// Verify audit log hash chain integrity.
/// Returns whether the chain is intact, rows checked, and any errors.
async fn audit_integrity(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    write_access_required(&auth)?;

    let result = verify_integrity(&state.db).await;

    log_event(
        &state.db,
        AuditAction::AuditIntegrityVerified,
        Some(auth.user_id),
        Some(&auth.username),
        Some("audit_log"),
        None,
        json!({
            "intact": result.intact,
            "rows_checked": result.rows_checked,
            "error_count": result.errors.len(),
        }),
        None,
        None,
    )
    .await;

    Ok(Json(json!({
        "intact": result.intact,
        "rows_checked": result.rows_checked,
        "errors": result.errors.iter().map(|e| json!({
            "row_id": e.row_id,
            "expected_hash": e.expected_hash,
            "actual_hash": e.actual_hash,
        })).collect::<Vec<_>>(),
    })))
}

// ============================================================
// POST /api/v1/settings/audit-integrity/repair
// ============================================================

/// Repair the audit log hash chain by recomputing all prev_hash and
/// row_hash values from row 1 forward. Admin-only — this is a
/// destructive operation that overwrites all hash values.
async fn audit_integrity_repair(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_required(&auth)?;

    tracing::warn!(
        user_id = %auth.user_id,
        username = %auth.username,
        "Audit chain repair initiated by admin"
    );

    let result = repair_integrity(&state.db).await;

    log_event(
        &state.db,
        AuditAction::AuditChainRepaired,
        Some(auth.user_id),
        Some(&auth.username),
        Some("audit_log"),
        None,
        json!({
            "intact": result.intact,
            "rows_checked": result.rows_checked,
            "prev_hash_fixed": result.prev_hash_fixed,
            "row_hash_fixed": result.row_hash_fixed,
            "remaining_errors": result.remaining_errors.len(),
        }),
        None,
        None,
    )
    .await;

    if result.intact {
        tracing::info!(
            rows_checked = result.rows_checked,
            prev_hash_fixed = result.prev_hash_fixed,
            row_hash_fixed = result.row_hash_fixed,
            "Audit chain repair succeeded"
        );
    } else {
        tracing::error!(
            rows_checked = result.rows_checked,
            prev_hash_fixed = result.prev_hash_fixed,
            row_hash_fixed = result.row_hash_fixed,
            remaining_errors = result.remaining_errors.len(),
            "Audit chain repair completed but chain is still broken"
        );
    }

    Ok(Json(json!({
        "intact": result.intact,
        "rows_checked": result.rows_checked,
        "prev_hash_fixed": result.prev_hash_fixed,
        "row_hash_fixed": result.row_hash_fixed,
        "remaining_errors": result.remaining_errors.iter().map(|e| json!({
            "row_id": e.row_id,
            "expected_hash": e.expected_hash,
            "actual_hash": e.actual_hash,
        })).collect::<Vec<_>>(),
    })))
}
/// Used by the SMTP password decryption logic (issue #6 fix).
fn hex_decode(s: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use super::*;
    use axum::http::StatusCode;
    use pm_auth::jwt::AccessClaims;
    use pm_auth::rbac::{AuthUser, UserRole};
    use uuid::Uuid;

    /// Build a minimal `AuthUser` for role-gate testing.
    /// The `admin_required` gate only inspects `auth.role`, so all other
    /// fields can be placeholder values.
    #[allow(dead_code)]
    fn test_auth_user(role: UserRole) -> AuthUser {
        let claims = AccessClaims {
            sub: Uuid::new_v4().to_string(),
            iat: 0,
            exp: i64::MAX,
            jti: Uuid::new_v4().to_string(),
            role: role.as_str().to_string(),
            username: "test-user".to_string(),
        };
        AuthUser {
            user_id: Uuid::new_v4(),
            username: "test-user".to_string(),
            role,
            claims,
        }
    }

    #[test]
    fn admin_required_admin_passes() {
        let auth = test_auth_user(UserRole::Admin);
        admin_required(&auth).expect("Admin should pass");
    }

    #[test]
    fn admin_required_operator_denied() {
        let auth = test_auth_user(UserRole::Operator);
        let err = admin_required(&auth).expect_err("Operator should be denied");
        let (status, body) = err;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "forbidden_role");
    }

    #[test]
    fn admin_required_reporter_denied() {
        let auth = test_auth_user(UserRole::Reporter);
        let err = admin_required(&auth).expect_err("Reporter should be denied");
        let (status, body) = err;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "forbidden_role");
    }
}
