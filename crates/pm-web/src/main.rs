//! pm-web — Linux Patch Manager web server.

mod routes;

mod secret_key;

use axum::{extract::State, http::StatusCode, middleware, response::Json, routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use dashmap::DashMap;
use pm_auth::{
    jwt,
    password::hash_password,
    rbac::{require_auth, AuthConfig},
};
use pm_core::{
    config::AppConfig, db, logging, models::ApprovedEntry, request_id::request_id_middleware,
};
use rand::Rng;
use routes::sso::{OidcCache, SsoHandoff, SsoSession};
use routes::ws::WsTicket;
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};

/// Placeholder Argon2id hash prefix used in the seed admin migration (issue #8).
/// Detecting this prefix means the admin password has not been bootstrapped yet.
const ADMIN_PLACEHOLDER_HASH_PREFIX: &str = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAA";

/// Bootstrap the default admin account with a random password.
///
/// On first startup after a fresh install, the `users` table contains the seed
/// admin row with a clearly-invalid placeholder hash (cannot validate any password).
/// This function detects that placeholder, generates a cryptographically random
/// 24-character password, hashes it with Argon2id, and UPDATEs the admin row.
///
/// The plaintext password is printed **once** to stderr (visible in `systemctl status`
/// or `journalctl`) and is never stored on disk.
///
/// If the admin row already has a real hash, this function is a no-op.
async fn bootstrap_admin_password(pool: &sqlx::PgPool) {
    // Check if the admin account still has the placeholder hash.
    let result: Option<String> = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE username = 'admin' AND auth_provider = 'local'",
    )
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let current_hash = match result {
        Some(h) => h,
        None => return, // No admin row — nothing to bootstrap.
    };

    if !current_hash.starts_with(ADMIN_PLACEHOLDER_HASH_PREFIX) {
        // Admin already has a real password — nothing to do.
        return;
    }

    // Generate a 24-character random alphanumeric password.
    let password: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();

    // Hash it with the application's Argon2id parameters.
    let new_hash = match hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "Failed to hash bootstrap admin password");
            return;
        },
    };

    // Replace the placeholder hash with the real one.
    // The WHERE clause matches the placeholder prefix to ensure idempotency.
    let rows = sqlx::query(
        r#"UPDATE users
            SET password_hash = $1
            WHERE username = 'admin'
              AND auth_provider = 'local'
              AND password_hash LIKE '$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAA%'"#,
    )
    .bind(&new_hash)
    .execute(pool)
    .await;

    match rows {
        Ok(result) if result.rows_affected() == 1 => {
            eprintln!();
            eprintln!("========================================");
            eprintln!("  INITIAL ADMIN PASSWORD (shown once)");
            eprintln!("  Username: admin");
            eprintln!("  Password: {}", password);
            eprintln!();
            eprintln!("  You will be forced to change this on first login.");
            eprintln!("  If lost, restart the service to generate a new one.");
            eprintln!("========================================");
            eprintln!();
            tracing::info!("Bootstrap admin password generated and set");
        },
        Ok(_) => {
            // Rows affected != 1 — concurrent bootstrap or already replaced.
            tracing::info!("Admin password already bootstrapped (concurrent or prior)");
        },
        Err(e) => {
            tracing::error!(error = %e, "Failed to update admin password hash");
        },
    }
}

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
    /// In-memory store for SSO handoff codes (single-use, 60s TTL).
    /// See `tasks/sso-token-handoff-spec.md` §4.1.
    pub sso_handoffs: Arc<DashMap<String, SsoHandoff>>,
    /// Cached OIDC discovery document and JWKS for SSO id_token verification.
    pub oidc_cache: Arc<Mutex<OidcCache>>,
    /// Internal certificate authority for mTLS client cert issuance.
    pub ca: Arc<pm_ca::CertAuthority>,
    /// Short-lived cache for approved enrollment PKI bundles.
    ///
    /// Entries are single-use (removed on retrieval) and expire after
    /// [`ENROLLMENT_BUNDLE_TTL_SECS`](pm_core::models::ENROLLMENT_BUNDLE_TTL_SECS).
    pub approved_enrollments: Arc<DashMap<String, ApprovedEntry>>,
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
        &config.security.trusted_proxies,
    ));

    let pool = db::init_pool(&config.database).await?;
    db::run_migrations(&pool).await?;

    // Bootstrap admin password if the seed admin still has the placeholder hash (issue #8).
    bootstrap_admin_password(&pool).await;

    // Initialise the internal CA using the configured certificate paths.
    // The CA certificate and key must exist at the configured locations and be
    // unencrypted PEM. If absent, a new CA is generated in that directory.
    let ca_base = std::path::Path::new(&config.security.ca_cert_path)
        .parent()
        .expect("CA certificate path must have a parent directory");
    let ca = pm_ca::CertAuthority::init(ca_base, &pool)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "CA init failed (dev mode)");
            panic!("CA initialization failed: {}", e);
        });

    let ws_tickets: Arc<DashMap<String, WsTicket>> = Arc::new(DashMap::new());
    let sso_sessions: Arc<DashMap<String, SsoSession>> = Arc::new(DashMap::new());
    let sso_handoffs: Arc<DashMap<String, SsoHandoff>> = Arc::new(DashMap::new());
    let oidc_cache: Arc<Mutex<OidcCache>> = Arc::new(Mutex::new(OidcCache::default()));
    let approved_enrollments: Arc<DashMap<String, ApprovedEntry>> = Arc::new(DashMap::new());

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

    // Background task: purge expired SSO sessions every 60 seconds (sessions older than 10 minutes).
    {
        let sessions = sso_sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = chrono::Utc::now();
                let cutoff = now - chrono::Duration::minutes(10);
                let before = sessions.len();
                sessions.retain(|_, v| v.created_at > cutoff);
                let removed = before.saturating_sub(sessions.len());
                if removed > 0 {
                    tracing::debug!(removed, "Purged expired SSO sessions");
                }
            }
        });
    }

    // Background task: purge expired approved enrollment PKI bundles.
    // Entries are also removed on first retrieval (single-use), so this
    // task only cleans up bundles that were never picked up by the agent.
    {
        let approved = approved_enrollments.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let before = approved.len();
                approved.retain(|_, entry| !entry.is_expired());
                let removed = before.saturating_sub(approved.len());
                if removed > 0 {
                    tracing::debug!(removed, "Purged expired enrollment PKI bundles");
                }
            }
        });
    }

    // Background task: purge expired SSO handoff codes every 60 seconds.
    // See `tasks/sso-token-handoff-spec.md` §4.3. Handoffs are also
    // atomically removed on exchange (single-use), so this task only
    // cleans up codes that the SPA never POSTed back for.
    {
        let handoffs = sso_handoffs.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                let before = handoffs.len();
                handoffs.retain(|_, v| v.expires_at > now);
                let removed = before.saturating_sub(handoffs.len());
                if removed > 0 {
                    tracing::debug!(removed, "Purged expired SSO handoff codes");
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
        sso_handoffs,
        ca: Arc::new(ca),
        approved_enrollments,
        oidc_cache,
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
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
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
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}

/// Construct the full Axum router.
pub fn build_router(state: AppState) -> Router {
    let static_dir = state.config.server.static_dir.clone();
    let auth_config = state.auth_config.clone();
    let rl = &state.config.rate_limit;

    // Enrollment rate limiting: strict (5 req/min per IP, burst 3)
    // Uses SmartIpKeyExtractor to respect X-Forwarded-For behind reverse proxy.
    // governor quota: 1 request per 12_000ms = ~5/min sustained
    let enrollment_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_millisecond(12_000)
            .burst_size(rl.enrollment_burst)
            .finish()
            .expect("Invalid enrollment governor config"),
    );

    // Auth rate limiting: moderate (20 req/min per IP, burst 10)
    // Uses SmartIpKeyExtractor to respect X-Forwarded-For behind reverse proxy.
    // governor quota: 1 request per 3_000ms = ~20/min sustained
    let auth_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_millisecond(3_000)
            .burst_size(rl.auth_burst)
            .finish()
            .expect("Invalid auth governor config"),
    );

    // API rate limiting: normal (120 req/min per IP, burst 30)
    // Uses SmartIpKeyExtractor to respect X-Forwarded-For behind reverse proxy.
    // governor quota: 1 request per 500ms = ~120/min sustained
    let api_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_millisecond(500)
            .burst_size(rl.api_burst)
            .finish()
            .expect("Invalid API governor config"),
    );

    // Enrollment routes with strict per-IP rate limiting
    let enrollment_router =
        routes::enrollment::router().layer(GovernorLayer::new(enrollment_governor));

    // Public auth routes with moderate per-IP rate limiting
    let auth_public_router =
        routes::auth::public_router().layer(GovernorLayer::new(Arc::clone(&auth_governor)));

    // SSO routes with moderate per-IP rate limiting
    let sso_public_router =
        routes::sso::public_router().layer(GovernorLayer::new(Arc::clone(&auth_governor)));
    let sso_azure_router =
        routes::sso::azure_compat_router().layer(GovernorLayer::new(auth_governor));

    // All protected API routes — require valid JWT, with normal per-IP rate limiting
    let protected_api = Router::new()
        // Auth: MFA setup/verify
        // Auth: MFA setup/verify/disable (nested under /auth so paths are /api/v1/auth/mfa/*)
        .nest("/auth", routes::auth::protected_router())
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
        // Maintenance windows — bulk list-all endpoint
        .nest(
            "/maintenance-windows",
            routes::maintenance_windows::all_windows_router(),
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
        // Admin enrollment routes (JWT protected, Admin role enforced)
        .nest("/admin", routes::enrollment::admin_router())
        // Apply rate limiting then auth middleware
        .layer(GovernorLayer::new(api_governor))
        .route_layer(middleware::from_fn(move |req, next| {
            let auth_config = auth_config.clone();
            require_auth(auth_config, req, next)
        }));

    Router::new()
        .route("/status/health", get(health_handler))
        // Public auth routes (rate-limited, no JWT)
        .nest("/api/v1/auth", auth_public_router)
        // Public enrollment endpoints (rate-limited, no JWT)
        .nest("/api/v1", enrollment_router)
        // Public SSO routes (rate-limited, no JWT)
        .nest("/api/v1/auth/sso", sso_public_router)
        // Public Azure SSO routes (rate-limited, no JWT)
        .nest("/api/v1/auth/azure", sso_azure_router)
        // Protected API routes (JWT required, rate-limited)
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
