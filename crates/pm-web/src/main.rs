//! pm-web — Linux Patch Manager web server (binary entry-point).

use dashmap::DashMap;
use pm_auth::{jwt, rbac::AuthConfig};
use pm_core::{config::AppConfig, db, models::ApprovedEntry};
use pm_web::routes::sso::{OidcCache, SsoHandoff, SsoSession};
use pm_web::routes::ws::WsTicket;
use pm_web::{bootstrap_admin_password, build_repo_router, build_router, AppState};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;

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

    pm_core::logging::init(&config.logging);
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

    // Bootstrap admin password if the seed admin still has the placeholder hash.
    bootstrap_admin_password(&pool).await;

    // Initialise the internal CA using the configured certificate paths.
    let ca_base = std::path::Path::new(&config.security.ca_cert_path)
        .parent()
        .expect("CA certificate path must have a parent directory");
    let ca = pm_ca::CertAuthority::init(ca_base, &pool)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "CA init failed (dev mode)");
            panic!("CA initialization failed: {}", e);
        });

    // Bootstrap GPG signing key for the manager-hosted package repository.
    // Generates a per-manager RSA 4096 key if none exists, stored alongside CA material.
    let gpg_key_info = pm_core::gpg::ensure_signing_key(
        &config.repo.gpg_public_key_path,
        &config.repo.gpg_private_key_path,
    )
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "GPG key bootstrap failed (dev mode)");
        // Non-fatal — repo sync will fail later if gpg is truly unavailable.
        pm_core::gpg::GpgKeyInfo {
            key_id: String::new(),
            public_key_path: config.repo.gpg_public_key_path.clone(),
            private_key_path: config.repo.gpg_private_key_path.clone(),
            newly_generated: false,
        }
    });
    if gpg_key_info.newly_generated {
        tracing::info!(
            key_id = %gpg_key_info.key_id,
            "GPG signing key generated for manager-hosted repo"
        );
    } else if !gpg_key_info.key_id.is_empty() {
        tracing::info!(
            key_id = %gpg_key_info.key_id,
            "GPG signing key found — existing key will be used"
        );
    }

    // Initialize the manager-hosted package repo directory structure.
    // Creates apt/dnf/apk/pacman dirs and reprepro conf/distributions with SignWith.
    if !gpg_key_info.key_id.is_empty() {
        if let Err(e) =
            pm_core::gpg::ensure_repo_directories(&config.repo.dir, &gpg_key_info.key_id).await
        {
            tracing::warn!(error = %e, "Repo directory init failed (non-fatal for dev mode)");
        }
    } else {
        tracing::warn!("Skipping repo dir init — no GPG key ID available");
    }

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

    // Background task: purge expired SSO sessions every 60 seconds.
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
        gpg_key_id: gpg_key_info.key_id.clone(),
    };

    let app = build_router(state.clone());

    // Spawn the package repository HTTP server on port 80 (M16).
    // This serves GPG-signed package repos at /apt/, /dnf/, /apk/, /pacman/.
    // Plain HTTP — internal network, read-only, GPG provides integrity.
    let repo_app = build_repo_router(&state);
    let repo_port = config.repo.http_port;
    let repo_addr: SocketAddr = format!("0.0.0.0:{repo_port}")
        .parse()
        .expect("Invalid repo bind address");
    tracing::info!(addr = %repo_addr, "Listening (HTTP — package repo)");
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(repo_addr).await;
        match listener {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, repo_app.into_make_service()).await {
                    tracing::error!(error = %e, "Package repo server failed");
                }
            },
            Err(e) => {
                tracing::error!(error = %e, port = repo_port, "Failed to bind package repo port");
            },
        }
    });

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid bind address");

    // Try to load TLS certificate and key; fall back to plain HTTP if missing.
    let tls_cert = std::path::Path::new(&config.security.web_tls_cert_path);
    let tls_key = std::path::Path::new(&config.security.web_tls_key_path);

    if tls_cert.exists() && tls_key.exists() {
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
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
