//! pm-web — Linux Patch Manager web server.

mod routes;

use axum::{extract::State, http::StatusCode, middleware, response::Json, routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use dashmap::DashMap;
use pm_auth::{
    jwt,
    rbac::{require_auth, AuthConfig},
};
use pm_core::{config::AppConfig, db, logging, request_id::request_id_middleware};
use routes::azure_sso::SsoSession;
use routes::ws::WsTicket;
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower_http::{services::{ServeDir, ServeFile}, trace::TraceLayer};

/// Shared application state threaded through Axum.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<AppConfig>,
    pub signing_key_pem: String,
    pub auth_config: Arc<AuthConfig>,
    /// In-memory store for single-use WebSocket authentication tickets.
    pub ws_tickets: Arc<DashMap<String, WsTicket>>,
    /// In-memory store for SSO PKCE sessions (state → code_verifier).
    pub sso_sessions: Arc<DashMap<String, SsoSession>>,
    /// Internal certificate authority for mTLS client cert issuance.
    pub ca: Arc<pm_ca::CertAuthority>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the default crypto provider for rustls (required since 0.23)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let config_path = std::env::var("PATCH_MANAGER_CONFIG")
        .unwrap_or_else(|_| "/etc/patch-manager/config.toml".to_string());

    let config = AppConfig::load(&config_path).unwrap_or_else(|_| {
        eprintln!("Config file not found or invalid, using defaults");
        AppConfig::default()
    });

    logging::init(&config.logging);
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "patch-manager-web starting"
    );

    let signing_key_pem = jwt::load_signing_key(&config.security.jwt_signing_key_path)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "JWT signing key not found (dev mode)");
            String::new()
        });

    let verify_key_pem =
        jwt::load_verify_key(&config.security.jwt_verify_key_path).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "JWT verify key not found (dev mode)");
            String::new()
        });

    let auth_config = Arc::new(AuthConfig::new(
        verify_key_pem,
        &config.security.ip_whitelist,
    ));

    let pool = db::init_pool(&config.database).await?;
    db::run_migrations(&pool).await?;

    // Initialise the internal CA.  Panics in production if CA files are missing
    // or corrupt — this is intentional; the service cannot operate without mTLS.
    let ca_base = std::path::Path::new("/etc/patch-manager/ca");
    let ca = pm_ca::CertAuthority::init(ca_base, &pool)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "CA init failed (dev mode)");
            panic!("CA initialization failed: {}", e);
        });

    let ws_tickets: Arc<DashMap<String, WsTicket>> = Arc::new(DashMap::new());
    let sso_sessions: Arc<DashMap<String, SsoSession>> = Arc::new(DashMap::new());

    // Background task: purge expired WS tickets every 30 seconds.
    {
        let tickets = ws_tickets.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = chrono::Utc::now();
                let before = tickets.len();
                tickets.retain(|_, v| v.expires_at > now);
                let removed = before.saturating_sub(tickets.len());
                if removed > 0 {
                    tracing::debug!(removed, "Purged expired WS tickets");
                }
            }
        });
    }

    let state = AppState {
        db: pool,
        config: Arc::new(config.clone()),
        signing_key_pem,
        auth_config,
        ws_tickets,
        sso_sessions,
        ca: Arc::new(ca),
    };

    let app = build_router(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid bind address");

    // Try to load TLS certificate and key; fall back to plain HTTP if missing.
    let tls_cert = std::path::Path::new(&config.security.web_tls_cert_path);
    let tls_key = std::path::Path::new(&config.security.web_tls_key_path);

    if tls_cert.exists() && tls_key.exists() {
        let tls_config = RustlsConfig::from_pem_file(
            &config.security.web_tls_cert_path,
            &config.security.web_tls_key_path,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to load TLS certificates");
            e
        })?;

        tracing::info!(%addr, "Listening (HTTPS)");
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        tracing::warn!(
            cert_path = %config.security.web_tls_cert_path,
            key_path = %config.security.web_tls_key_path,
            "TLS certificates not found — falling back to plain HTTP. \
             This is insecure for production!"
        );
        tracing::info!(%addr, "Listening (HTTP — no TLS)");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}

/// Construct the full Axum router.
pub fn build_router(state: AppState) -> Router {
    let static_dir = state.config.server.static_dir.clone();
    let auth_config = state.auth_config.clone();

    // All protected API routes — require valid JWT
    let protected_api = Router::new()
        // Auth: MFA setup/verify
        .merge(routes::auth::protected_router())
        // Hosts
        .nest("/hosts", routes::hosts::router())
        // Host-scoped certificate endpoints (merged separately to avoid conflict)
        .nest("/hosts", routes::ca::host_cert_router())
        // Groups
        .nest("/groups", routes::groups::router())
        // Users
        .nest("/users", routes::users::router())
        // Discovery
        .nest("/discovery", routes::discovery::router())
        // Fleet status
        .nest("/status", routes::status::router())
        // Patch jobs
        .nest("/jobs", routes::jobs::router())
        // Maintenance windows (nested under hosts path param)
        .nest(
            "/hosts/{host_id}/maintenance-windows",
            routes::maintenance_windows::router(),
        )
        // CA root certificate download
        .nest("/ca", routes::ca::ca_router())
        // Certificate list / renew / revoke
        .nest("/certificates", routes::ca::certs_router())
        // WS ticket issuance (JWT-protected — ticket returned to browser, then used for WS upgrade)
        .merge(routes::ws::ticket_router())
        // Reports
        .nest("/reports", routes::reports::router())
        .nest(
            "/hosts/{host_id}/health-checks",
            routes::health_checks::router(),
        )
        // Settings (admin-only)
        .nest("/settings", routes::settings::router())
        // Apply auth middleware to all the above
        .route_layer(middleware::from_fn(move |req, next| {
            let auth_config = auth_config.clone();
            require_auth(auth_config, req, next)
        }));

    Router::new()
        .route("/status/health", get(health_handler))
        // Public auth routes (no JWT needed)
        .nest("/api/v1/auth", routes::auth::public_router())
        // Public Azure SSO routes (no JWT needed)
        .nest("/api/v1/auth/azure", routes::azure_sso::public_router())
        // Protected API routes (JWT required)
        .nest("/api/v1", protected_api)
        // WebSocket browser endpoint — ticket-authenticated, outside JWT middleware
        .merge(routes::ws::ws_router())
        // Serve React SPA
        .fallback_service(
            ServeDir::new(&static_dir)
                .append_index_html_on_directories(true)
                .fallback(ServeFile::new(format!("{}/index.html", static_dir))),
        )
        .layer(middleware::from_fn(request_id_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    let status = if db_ok { "healthy" } else { "degraded" };
    let body = json!({ "service": "patch-manager-web", "version": env!("CARGO_PKG_VERSION"), "status": status, "database": if db_ok { "ok" } else { "error" } });
    if db_ok {
        Ok(Json(body))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}
