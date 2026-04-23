//! pm-web — Linux Patch Manager web server.
//!
//! Serves the React SPA, exposes the REST API, and handles WebSocket relay.

use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::Json,
    routing::get,
    Router,
};
use pm_core::{
    config::AppConfig,
    db,
    logging,
    request_id::request_id_middleware,
};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc};
use tower_http::{
    services::ServeDir,
    trace::TraceLayer,
};

/// Shared application state threaded through Axum.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config_path = std::env::var("PATCH_MANAGER_CONFIG")
        .unwrap_or_else(|_| "/etc/patch-manager/config.toml".to_string());

    let config = AppConfig::load(&config_path)
        .unwrap_or_else(|_| {
            eprintln!("Config file not found or invalid, using defaults");
            AppConfig::default()
        });

    // Initialize logging
    logging::init(&config.logging);

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "patch-manager-web starting");

    // Initialize database pool
    let pool = db::init_pool(&config.database).await?;

    // Run migrations (advisory lock guards single-writer)
    db::run_migrations(&pool).await?;

    let state = AppState {
        db: pool,
        config: Arc::new(config.clone()),
    };

    // Build the application router
    let app = build_router(state);

    // Bind address
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid bind address");

    tracing::info!(%addr, "Listening");

    // TODO M8: wrap with TLS (rustls). For M1 we bind plain HTTP for local dev.
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Construct the full Axum router.
pub fn build_router(state: AppState) -> Router {
    let static_dir = state.config.server.static_dir.clone();

    Router::new()
        // Health / status (unauthenticated)
        .route("/status/health", get(health_handler))
        // API v1 routes (stub — expanded in later milestones)
        .nest("/api/v1", api_v1_router())
        // Serve React SPA static files; fallback to index.html for client-side routing
        .fallback_service(
            ServeDir::new(&static_dir)
                .append_index_html_on_directories(true),
        )
        // Middleware stack
        .layer(middleware::from_fn(request_id_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// API v1 sub-router — routes added per milestone.
fn api_v1_router() -> Router<AppState> {
    Router::new()
        // M2+: auth routes will be nested here
        // M3+: host/group/user routes
        // M4+: fleet status, agent polling
        // M5+: jobs
        // M6+: maintenance windows
        // M7+: websocket relay
        // M8+: certificates
        // M9+: reports
        // M10+: settings
}

/// GET /status/health — liveness probe.
///
/// Returns 200 OK with a JSON payload including service name, version,
/// and basic database reachability.
async fn health_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    // Quick DB ping
    let db_ok = sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .is_ok();

    let status = if db_ok { "healthy" } else { "degraded" };

    let body = json!({
        "service": "patch-manager-web",
        "version": env!("CARGO_PKG_VERSION"),
        "status": status,
        "database": if db_ok { "ok" } else { "error" },
    });

    if db_ok {
        Ok(Json(body))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}
