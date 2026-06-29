//! PKI endpoints for certificate revocation list (CRL) distribution.
//!
//! This module exposes the CRL endpoint that agents poll every 24 hours to
//! check for revoked certificates. The CRL is signed by the internal CA and
//! is publicly accessible (CRLs are self-authenticating — they carry the CA
//! signature and do not require client authentication).

use crate::AppState;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};

/// Define public PKI routes.
///
/// These endpoints are **unauthenticated** because CRLs are self-authenticating:
/// the agent verifies the CRL signature against its pinned CA certificate.
/// No client certificate or API key is required.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/pki/crl.pem", get(get_crl))
        .route("/pki/repo-config", get(get_repo_config))
}

/// `GET /api/v1/pki/crl.pem`
///
/// Returns the current Certificate Revocation List (CRL) as a PEM-encoded
/// X.509 CRL. The CRL is signed by the internal CA and contains the serial
/// numbers of all revoked certificates that have not yet expired.
///
/// # Cache headers
///
/// The response includes `Cache-Control: max-age=3600` (1 hour) to allow
/// intermediate caches to serve the CRL. Agents refresh every 24 hours,
/// so a 1-hour cache is a reasonable balance between freshness and load.
///
/// # CRL generation
///
/// The CRL is generated on demand from the `certificates` table. For our
/// target scale (max ~2500 clients), this is a fast query and the resulting
/// CRL is KB-range. If performance becomes a concern, the CRL can be cached
/// in memory and regenerated on a schedule (see background task in main.rs).
async fn get_crl(State(state): State<AppState>) -> impl IntoResponse {
    match state.ca.generate_crl(&state.db).await {
        Ok(crl_pem) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/x-pem-file; charset=utf-8",
            )],
            [(header::CACHE_CONTROL, "max-age=3600")],
            crl_pem,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to generate CRL");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate CRL").into_response()
        },
    }
}

/// `GET /api/v1/pki/repo-config?distro_id=<distro_id>`
///
/// Fallback endpoint for agents that enrolled before v2.0.0 and did not
/// receive `repo_config` in their PkiBundle. Returns the GPG public key
/// and distro-specific sources configuration so the agent can provision
/// the manager-hosted package repo.
///
/// # Query parameters
///
/// - `distro_id` (required): The agent's distro identifier (e.g.,
///   `ubuntu-24.04`, `debian-12`, `fedora-40`, `alpine-3.21`, `arch`).
///
/// # Response
///
/// Returns JSON with `gpg_public_key`, `sources_config`, `distro_id`,
/// and `keyring_path` fields matching the `RepoConfig` struct.
///
/// Added for issue #116 (M2).
async fn get_repo_config(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<RepoConfigQuery>,
) -> impl IntoResponse {
    let distro_id = params.distro_id;

    if distro_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": { "code": "missing_param", "message": "distro_id query parameter is required" }
            })),
        )
            .into_response();
    }

    let repo_config = &state.config.repo;

    // Read GPG public key from configured path.
    let gpg_public_key = match tokio::fs::read_to_string(&repo_config.gpg_public_key_path).await {
        Ok(key) => key,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %repo_config.gpg_public_key_path,
                "GPG public key file not found or unreadable"
            );
            return (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": { "code": "repo_not_configured", "message": "GPG public key not available on this manager" }
                })),
            )
                .into_response();
        },
    };

    // Generate distro-specific sources_config and keyring_path.
    let (sources_config, keyring_path) = match pm_core::models::generate_distro_config(
        &distro_id,
        &repo_config.url_base,
    ) {
        Some(config) => config,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": { "code": "unsupported_distro", "message": format!("Unsupported distro_id: {}", distro_id) }
                })),
            )
                .into_response();
        },
    };

    let repo_config_response = pm_core::models::RepoConfig {
        gpg_public_key,
        sources_config,
        distro_id,
        keyring_path,
    };

    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "max-age=3600")],
        axum::Json(repo_config_response),
    )
        .into_response()
}

/// Query parameters for GET /pki/repo-config.
#[derive(serde::Deserialize)]
struct RepoConfigQuery {
    distro_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use dashmap::DashMap;
    use pm_auth::rbac::AuthConfig;
    use pm_core::config::AppConfig;
    use sqlx::PgPool;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    /// Helper: create a test AppState with a real CA and database pool.
    /// Returns None if TEST_DATABASE_URL is not set (tests are skipped).
    async fn setup_app_state() -> Option<(PgPool, AppState)> {
        let db_url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPool::connect(&db_url).await.ok()?;

        // Run migrations to ensure schema is up to date.
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;

        // Create a temp directory for the CA.
        let tmp_dir = tempfile::tempdir().ok()?;
        let ca_dir = tmp_dir.path().to_path_buf();

        let ca = pm_ca::CertAuthority::init(&ca_dir, &pool).await.ok()?;

        let config = Arc::new(AppConfig::default());

        use crate::routes::sso::OidcCache;

        let state = AppState {
            db: pool.clone(),
            config,
            signing_key_pem: String::new(),
            auth_config: Arc::new(AuthConfig::new(String::new(), &[], &[])),
            ws_tickets: Arc::new(DashMap::new()),
            sso_sessions: Arc::new(DashMap::new()),
            sso_handoffs: Arc::new(DashMap::new()),
            oidc_cache: Arc::new(Mutex::new(OidcCache::default())),
            ca: Arc::new(ca),
            approved_enrollments: Arc::new(DashMap::new()),
        };

        Some((pool, state))
    }

    /// Build an Axum app with just the PKI routes for testing.
    fn test_app(state: AppState) -> Router {
        Router::new().nest("/api/v1", router()).with_state(state)
    }

    #[tokio::test]
    async fn crl_endpoint_returns_200_with_valid_pem() {
        let Some((pool, state)) = setup_app_state().await else {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        };

        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/pki/crl.pem")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should succeed");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "CRL endpoint should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), 10_000)
            .await
            .expect("body should be readable");

        let body_str = String::from_utf8(body.to_vec()).expect("body should be UTF-8");

        assert!(
            body_str.contains("-----BEGIN X509 CRL-----"),
            "Response should contain CRL PEM header"
        );
        assert!(
            body_str.contains("-----END X509 CRL-----"),
            "Response should contain CRL PEM footer"
        );

        pool.close().await;
    }

    #[tokio::test]
    async fn crl_endpoint_returns_cache_control_header() {
        let Some((pool, state)) = setup_app_state().await else {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        };

        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/pki/crl.pem")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);

        let cache_control = response
            .headers()
            .get("cache-control")
            .expect("Cache-Control header should be present");

        assert_eq!(
            cache_control.to_str().unwrap(),
            "max-age=3600",
            "Cache-Control should be max-age=3600"
        );

        pool.close().await;
    }

    #[tokio::test]
    async fn crl_endpoint_works_without_authentication() {
        let Some((pool, state)) = setup_app_state().await else {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        };

        let app = test_app(state);

        // Make request without any auth headers — CRL endpoint is public.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/pki/crl.pem")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should succeed");

        // Should return 200, not 401 Unauthorized.
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "CRL endpoint should be accessible without authentication"
        );

        pool.close().await;
    }

    #[tokio::test]
    async fn crl_endpoint_returns_pem_content_type() {
        let Some((pool, state)) = setup_app_state().await else {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        };

        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/pki/crl.pem")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .expect("Content-Type header should be present");

        assert!(
            content_type
                .to_str()
                .unwrap()
                .contains("application/x-pem-file"),
            "Content-Type should be application/x-pem-file, got: {:?}",
            content_type
        );

        pool.close().await;
    }
}
