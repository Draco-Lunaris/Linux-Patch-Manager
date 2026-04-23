//! pm-web — Linux Patch Manager web server.

mod routes;

use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::Json,
    routing::get,
    Router,
};
use dashmap::DashMap;
use pm_core::{
    config::AppConfig,
    db,
    logging,
    request_id::request_id_middleware,
};
use pm_auth::{
    jwt,
    rbac::{AuthConfig, require_auth},
};
use routes::ws::WsTicket;
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tower_http::{
    services::ServeDir,
    trace::TraceLayer,
};

/// Shared application state threaded through Axum.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<AppConfig>,
    pub signing_key_pem: String,
    pub auth_config: Arc<AuthConfig>,
    /// In-memory store for single-use WebSocket authentication tickets.
    pub ws_tickets: Arc<DashMap<String, WsTicket>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("PATCH_MANAGER_CONFIG")
        .unwrap_or_else(|_| "/etc/patch-manager/config.toml".to_string());

    let config = AppConfig::load(&config_path).unwrap_or_else(|_| {
        eprintln!("Config file not found or invalid, using defaults");
        AppConfig::default()
    });

    logging::init(&config.logging);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "patch-manager-web starting");

    let signing_key_pem = jwt::load_signing_key(&config.security.jwt_signing_key_path)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "JWT signing key not found (dev mode)");
            String::new()
        });

    let verify_key_pem = jwt::load_verify_key(&config.security.jwt_verify_key_path)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "JWT verify key not found (dev mode)");
            String::new()
        });

    let auth_config = Arc::new(AuthConfig::new(
        verify_key_pem,
        &config.security.ip_whitelist,
    ));

    let pool = db::init_pool(&config.database).await?;
    db::run_migrations(&pool).await?;

    let ws_tickets: Arc<DashMap<String, WsTicket>> = Arc::new(DashMap::new());

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
    };

    let app = build_router(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid bind address");

    tracing::info!(%addr, "Listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
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
        .nest("/hosts/:host_id/maintenance-windows", routes::maintenance_windows::router())
        // WS ticket issuance (JWT-protected — ticket returned to browser, then used for WS upgrade)
        .merge(routes::ws::ticket_router())
        // Apply auth middleware to all the above
        .route_layer(middleware::from_fn(move |req, next| {
            let auth_config = auth_config.clone();
            require_auth(auth_config, req, next)
        }));

    Router::new()
        .route("/status/health", get(health_handler))
        // Public auth routes (no JWT needed)
        .nest("/api/v1/auth", routes::auth::public_router())
        // Protected API routes (JWT required)
        .nest("/api/v1", protected_api)
        // WebSocket browser endpoint — ticket-authenticated, outside JWT middleware
        .merge(routes::ws::ws_router())
        // Serve React SPA
        .fallback_service(
            ServeDir::new(&static_dir).append_index_html_on_directories(true),
        )
        .layer(middleware::from_fn(request_id_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    let status = if db_ok { "healthy" } else { "degraded" };
    let body = json!({ "service": "patch-manager-web", "version": env!("CARGO_PKG_VERSION"), "status": status, "database": if db_ok { "ok" } else { "error" } });
    if db_ok { Ok(Json(body)) } else { Err(StatusCode::SERVICE_UNAVAILABLE) }
}
