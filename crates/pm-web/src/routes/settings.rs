//! Settings management routes.
//!
//! GET  /api/v1/settings              — get all settings (admin only)
//! PUT  /api/v1/settings              — update settings (admin only)
//! POST /api/v1/settings/azure-sso/test — test Azure SSO connectivity (admin only)
//! POST /api/v1/settings/smtp/test    — send test email (admin only)
//! GET  /api/v1/settings/ip-whitelist — get IP whitelist (admin only)
//! PUT  /api/v1/settings/ip-whitelist — update IP whitelist (admin only)
//! POST /api/v1/settings/audit-integrity — verify audit log integrity (admin only)

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
use pm_core::audit::{log_event, verify_integrity, AuditAction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::AppState;

// ============================================================
// Data structures
// ============================================================

#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    pub azure_sso: AzureSsoConfig,
    pub smtp: SmtpConfig,
    pub polling: PollingConfig,
    pub ip_whitelist: Vec<String>,
    pub web_tls_strategy: String,
    pub notification: NotificationConfig,
    pub sso_callback_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureSsoConfig {
    pub enabled: bool,
    pub tenant_id: String,
    pub client_id: String,
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
    pub azure_sso: Option<AzureSsoConfigUpdate>,
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
pub struct AzureSsoConfigUpdate {
    pub enabled: Option<bool>,
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub scopes: Option<String>,
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
        .route("/azure-sso/test", post(test_azure_sso))
        .route("/smtp/test", post(test_smtp))
        .route(
            "/ip-whitelist",
            get(get_ip_whitelist).put(update_ip_whitelist),
        )
        .route("/audit-integrity", post(audit_integrity))
}

// ============================================================
// Helpers
// ============================================================

const MASKED: &str = "********";

fn admin_only(auth: &AuthUser) -> Result<(), (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Admin access required" } })),
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
    azure: AzureSsoConfig,
) -> SettingsResponse {
    let get = |key: &str| -> String { cfg.get(key).cloned().unwrap_or_default() };

    let recipients: Vec<String> =
        serde_json::from_str(&get("notification_email_recipients")).unwrap_or_default();

    SettingsResponse {
        azure_sso: azure,
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

async fn fetch_azure_sso_config(
    pool: &sqlx::PgPool,
) -> Result<AzureSsoConfig, (StatusCode, Json<Value>)> {
    let row: Option<(bool, String, String, String, String)> = sqlx::query_as(
        "SELECT enabled, tenant_id, client_id, redirect_uri, scopes FROM azure_sso_config WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to load azure_sso_config");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    Ok(match row {
        Some((enabled, tenant_id, client_id, redirect_uri, scopes)) => AzureSsoConfig {
            enabled,
            tenant_id,
            client_id,
            redirect_uri,
            scopes,
        },
        None => AzureSsoConfig {
            enabled: false,
            tenant_id: String::new(),
            client_id: String::new(),
            redirect_uri: String::new(),
            scopes: "openid email profile".to_string(),
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
    admin_only(&auth)?;
    let cfg = load_system_config(&state.db).await?;
    // Inject read-only config values from TOML file (not stored in DB)
    let mut cfg = cfg;
    cfg.insert(
        "sso_callback_url".to_string(),
        state.config.security.sso_callback_url.clone(),
    );
    let azure = fetch_azure_sso_config(&state.db).await?;
    Ok(Json(build_settings_response(&cfg, azure)))
}

// ============================================================
// PUT /api/v1/settings
// ============================================================

async fn update_settings(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<SettingsResponse>, (StatusCode, Json<Value>)> {
    admin_only(&auth)?;

    // Update Azure SSO config
    // Use static queries with proper typed bindings to avoid boolean→string mismatch
    if let Some(azure) = req.azure_sso {
        let update_secret = azure.client_secret.as_ref().is_some_and(|s| s != MASKED);

        let result = if update_secret {
            sqlx::query(
                "UPDATE azure_sso_config SET \
                 enabled = COALESCE($1, enabled), \
                 tenant_id = COALESCE($2, tenant_id), \
                 client_id = COALESCE($3, client_id), \
                 client_secret = $4, \
                 redirect_uri = COALESCE($5, redirect_uri), \
                 scopes = COALESCE($6, scopes), \
                 updated_at = NOW() \
                 WHERE id = 1",
            )
            .bind(azure.enabled)
            .bind(&azure.tenant_id)
            .bind(&azure.client_id)
            .bind(azure.client_secret.as_deref().unwrap_or(""))
            .bind(&azure.redirect_uri)
            .bind(&azure.scopes)
            .execute(&state.db)
            .await
        } else {
            sqlx::query(
                "UPDATE azure_sso_config SET \
                 enabled = COALESCE($1, enabled), \
                 tenant_id = COALESCE($2, tenant_id), \
                 client_id = COALESCE($3, client_id), \
                 redirect_uri = COALESCE($4, redirect_uri), \
                 scopes = COALESCE($5, scopes), \
                 updated_at = NOW() \
                 WHERE id = 1",
            )
            .bind(azure.enabled)
            .bind(&azure.tenant_id)
            .bind(&azure.client_id)
            .bind(&azure.redirect_uri)
            .bind(&azure.scopes)
            .execute(&state.db)
            .await
        };

        result.map_err(|e| {
            tracing::error!(error = %e, "Failed to update azure_sso_config");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "code": "internal_error", "message": format!("Failed to update Azure SSO config: {}", e) } })),
            )
        })?;

        log_event(
            &state.db,
            AuditAction::ConfigChanged,
            Some(auth.user_id),
            Some(&auth.username),
            Some("azure_sso"),
            Some("1"),
            json!({ "section": "azure_sso" }),
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
                update_config_key(&state.db, "smtp_password", v).await?;
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
            AuditAction::ConfigChanged,
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
            AuditAction::ConfigChanged,
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
    let azure = fetch_azure_sso_config(&state.db).await?;
    Ok(Json(build_settings_response(&cfg, azure)))
}

// ============================================================
// POST /api/v1/settings/azure-sso/test
// ============================================================

async fn test_azure_sso(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_only(&auth)?;

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT tenant_id, client_id FROM azure_sso_config WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to load azure_sso_config");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })?;

    let (tenant_id, _client_id) = match row {
        Some(r) => r,
        None => {
            return Ok(Json(json!({
                "success": false,
                "message": "Azure SSO is not configured"
            })));
        },
    };

    if tenant_id.is_empty() {
        return Ok(Json(json!({
            "success": false,
            "message": "Azure tenant ID is not set"
        })));
    }

    let url = format!(
        "https://login.microsoftonline.com/{}/v2.0/.well-known/openid-configuration",
        tenant_id
    );

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

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: Value = resp.json().await.unwrap_or(json!({}));
            let issuer = body.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
            if issuer.contains(&tenant_id) {
                Ok(Json(json!({
                    "success": true,
                    "message": "Azure AD tenant verified successfully",
                    "issuer": issuer
                })))
            } else {
                Ok(Json(json!({
                    "success": true,
                    "message": "Azure AD endpoint reached, but issuer does not match tenant_id",
                    "issuer": issuer
                })))
            }
        },
        Ok(resp) => Ok(Json(json!({
            "success": false,
            "message": format!("Failed to reach Azure AD: HTTP {}", resp.status())
        }))),
        Err(e) => Ok(Json(json!({
            "success": false,
            "message": format!("Failed to reach Azure AD: {}", e)
        }))),
    }
}

// ============================================================
// POST /api/v1/settings/smtp/test
// ============================================================

async fn test_smtp(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admin_only(&auth)?;

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
    let password = cfg.get("smtp_password").cloned().unwrap_or_default();
    let from_addr = cfg.get("smtp_from").cloned().unwrap_or_default();
    let tls_mode = cfg
        .get("smtp_tls_mode")
        .cloned()
        .unwrap_or_else(|| "starttls".to_string());

    if host.is_empty() || from_addr.is_empty() {
        return Ok(Json(json!({
            "success": false,
            "message": "SMTP host or from address is not configured"
        })));
    }

    let result = send_smtp_test(&host, port, &username, &password, &from_addr, &tls_mode).await;

    match result {
        Ok(()) => Ok(Json(json!({
            "success": true,
            "message": "Test email sent successfully"
        }))),
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
) -> Result<(), String> {
    let from_mailbox: Mailbox = from_addr
        .parse()
        .map_err(|e| format!("Invalid from address: {}", e))?;

    let email = Message::builder()
        .from(from_mailbox.clone())
        .to(from_mailbox)
        .subject("Linux Patch Manager — SMTP Test")
        .header(ContentType::TEXT_PLAIN)
        .body("This is a test email from Linux Patch Manager.".to_string())
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
    admin_only(&auth)?;

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
    admin_only(&auth)?;

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
        AuditAction::ConfigChanged,
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
    admin_only(&auth)?;

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
