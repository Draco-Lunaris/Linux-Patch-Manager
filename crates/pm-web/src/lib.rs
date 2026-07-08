//! pm-web — Linux Patch Manager web server (library crate).
//!
//! Re-exports [`AppState`], [`build_router`], and [`health_handler`] so that
//! integration tests can construct a test application without depending on
//! the binary entry-point.

pub mod routes;
pub mod secret_key;

use axum::{extract::State, http::StatusCode, middleware, response::Json, routing::get, Router};
use dashmap::DashMap;
use pm_auth::{
    password::hash_password,
    rbac::{require_auth, AuthConfig},
};
use pm_core::{config::AppConfig, models::ApprovedEntry, request_id::request_id_middleware};
use rand::Rng;
use routes::sso::{OidcCache, SsoHandoff, SsoSession};
use routes::ws::WsTicket;
use serde_json::{json, Value};
use std::sync::Arc;
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
pub async fn bootstrap_admin_password(pool: &sqlx::PgPool) {
    let result: Option<String> = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE username = 'admin' AND auth_provider = 'local'",
    )
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let current_hash = match result {
        Some(h) => h,
        None => return,
    };

    if !current_hash.starts_with(ADMIN_PLACEHOLDER_HASH_PREFIX) {
        return;
    }

    let password: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();

    let new_hash = match hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "Failed to hash bootstrap admin password");
            return;
        },
    };

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
    /// GPG key ID for the manager-hosted package repo signing key.
    /// Populated on startup by `pm_core::gpg::ensure_signing_key()`.
    pub gpg_key_id: String,
}

/// Construct the full Axum router.
pub fn build_router(state: AppState) -> Router {
    let static_dir = state.config.server.static_dir.clone();
    let auth_config = state.auth_config.clone();
    let rl = &state.config.rate_limit;

    // Enrollment rate limiting: strict (5 req/min per IP, burst 3)
    let enrollment_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_millisecond(12_000)
            .burst_size(rl.enrollment_burst)
            .finish()
            .expect("Invalid enrollment governor config"),
    );

    // Auth rate limiting: moderate (20 req/min per IP, burst 10)
    let auth_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_millisecond(3_000)
            .burst_size(rl.auth_burst)
            .finish()
            .expect("Invalid auth governor config"),
    );

    // API rate limiting: normal (120 req/min per IP, burst 30)
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
        .nest("/auth", routes::auth::protected_router())
        .nest("/hosts", routes::hosts::router())
        .nest("/hosts", routes::ca::host_cert_router())
        .nest("/groups", routes::groups::router())
        .nest("/users", routes::users::router())
        .nest("/discovery", routes::discovery::router())
        .nest("/status", routes::status::router())
        .nest("/jobs", routes::jobs::router())
        .nest(
            "/hosts/{host_id}/maintenance-windows",
            routes::maintenance_windows::router(),
        )
        .nest(
            "/maintenance-windows",
            routes::maintenance_windows::all_windows_router(),
        )
        .nest("/ca", routes::ca::ca_router())
        .nest("/certificates", routes::ca::certs_router())
        .merge(routes::ws::ticket_router())
        .nest("/reports", routes::reports::router())
        .nest(
            "/hosts/{host_id}/health-checks",
            routes::health_checks::router(),
        )
        .nest("/settings", routes::settings::router())
        .nest("/upgrades", routes::upgrades::router())
        .nest("/admin", routes::enrollment::admin_router())
        .nest("/admin", routes::repo_admin::router())
        .layer(GovernorLayer::new(api_governor))
        .route_layer(middleware::from_fn(move |req, next| {
            let auth_config = auth_config.clone();
            require_auth(auth_config, req, next)
        }));

    Router::new()
        .route("/status/health", get(health_handler))
        .nest("/api/v1/auth", auth_public_router)
        .nest("/api/v1", enrollment_router)
        .nest("/api/v1", routes::pki::router())
        .nest("/api/v1/upgrades", routes::upgrades::public_router())
        .nest("/api/v1/auth/sso", sso_public_router)
        .nest("/api/v1/auth/azure", sso_azure_router)
        .nest("/api/v1", protected_api)
        .merge(routes::ws::ws_router())
        .fallback_service(
            ServeDir::new(&static_dir)
                .append_index_html_on_directories(true)
                .fallback(ServeFile::new(format!("{}/index.html", static_dir))),
        )
        .layer(middleware::from_fn(request_id_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Construct the package repository router (served on plain HTTP port 80).
///
/// This router serves static package repo files for apt/dnf/apk/pacman
/// repositories. It is **unauthenticated** — package integrity is verified
/// via GPG signatures by the client's native package manager.
///
/// The repo directory base is read from `config.repo.dir` (default:
/// `/var/www/lpa-repo`). Subdirectories served:
/// - `/apt/` → `{repo_dir}/apt/` (reprepro output)
/// - `/dnf/` → `{repo_dir}/dnf/` (createrepo_c output)
/// - `/apk/` → `{repo_dir}/apk/` (apk index + .apk files)
/// - `/pacman/` → `{repo_dir}/pacman/` (repo-add output)
///
/// Added for issue #116 (M16).
pub fn build_repo_router(state: &AppState) -> Router {
    let repo_dir = state.config.repo.dir.clone();
    Router::new()
        .nest_service("/apt", ServeDir::new(format!("{repo_dir}/apt")))
        .nest_service("/dnf", ServeDir::new(format!("{repo_dir}/dnf")))
        .nest_service("/apk", ServeDir::new(format!("{repo_dir}/apk")))
        .nest_service("/pacman", ServeDir::new(format!("{repo_dir}/pacman")))
}

pub async fn health_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    let status = if db_ok { "healthy" } else { "degraded" };
    let body = json!({ "service": "patch-manager-web", "version": env!("CARGO_PKG_VERSION"), "status": status, "database": if db_ok { "ok" } else { "error" } });
    if db_ok {
        Ok(Json(body))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}