//! Integration tests for the upgrade catalog endpoints:
//!
//! - GET  /api/v1/upgrades/available-versions  (public)
//! - POST /api/v1/upgrades/refresh-versions   (admin)
//! - OS package mapping CRUD at /api/v1/settings/os-package-mappings (admin)
//!
//! All tests require a live PostgreSQL database and are marked `#[ignore]`.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use pm_auth::jwt;
use pm_auth::rbac::AuthConfig;
use pm_core::config::AppConfig;
use pm_web::routes::sso::OidcCache;
use pm_web::{build_router, AppState};
use serde_json::json;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

// ── Ed25519 test key pair ────────────────────────────────────────────────────
const TEST_SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBrWiMMcgpPXwtGDSSBl01fcQyb5Vh4CMzEmxcSXvcrJ
-----END PRIVATE KEY-----
";

const TEST_VERIFY_KEY: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEACgE6fMDCcG11NOpPKSO/ASpPUSntB7XsF5sBFBYDjFo=
-----END PUBLIC KEY-----
";

// ── Fixed test user IDs ─────────────────────────────────────────────────────
const ADMIN_USER_ID: &str = "00000000-0000-4000-8000-000000000001";

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Generate a valid JWT authorization header for the given role.
fn auth_header(role: &str) -> String {
    let user_id = match role {
        "admin" => Uuid::parse_str(ADMIN_USER_ID).unwrap(),
        _ => Uuid::parse_str(ADMIN_USER_ID).unwrap(),
    };
    let username = format!("test-{}", role);
    let token = jwt::issue_access_token(user_id, &username, role, 900, TEST_SIGNING_KEY)
        .expect("failed to issue test JWT");
    format!("Bearer {}", token)
}

/// Seed test users into the database.
async fn seed_test_users(pool: &PgPool) {
    let placeholder_hash = "$argon2id$v=19$m=65536,t=3,p=1$placeholder$placeholder";
    for (user_id, username, role) in [(ADMIN_USER_ID, "test-admin", "admin")] {
        sqlx::query(
            r#"INSERT INTO users (id, username, display_name, email, role, auth_provider, password_hash)
               VALUES ($1, $2, $3, $4, $5::user_role, 'local', $6)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(Uuid::parse_str(user_id).unwrap())
        .bind(username)
        .bind(username)
        .bind(format!("{}@test.example.com", username))
        .bind(role)
        .bind(placeholder_hash)
        .execute(pool)
        .await
        .expect("failed to seed test user");
    }
}

/// Build a full `AppState` with a live database connection.
async fn setup_state(pool: PgPool) -> AppState {
    seed_test_users(&pool).await;

    let mut config = AppConfig::default();
    config.server.static_dir = "/tmp".to_string();

    let auth_config = Arc::new(AuthConfig::new(TEST_VERIFY_KEY.to_string(), &[], &[]));

    let ca_dir = tempfile::tempdir().expect("failed to create temp dir for CA");
    let ca_dir_path = ca_dir.path().to_path_buf();
    std::mem::forget(ca_dir);

    let ca = pm_ca::CertAuthority::init(&ca_dir_path, &pool)
        .await
        .expect("CA init failed");

    AppState {
        db: pool,
        config: Arc::new(config),
        signing_key_pem: TEST_SIGNING_KEY.to_string(),
        auth_config,
        ws_tickets: Arc::new(DashMap::new()),
        sso_sessions: Arc::new(DashMap::new()),
        sso_handoffs: Arc::new(DashMap::new()),
        oidc_cache: Arc::new(Mutex::new(OidcCache::default())),
        ca: Arc::new(ca),
        approved_enrollments: Arc::new(DashMap::new()),
    }
}

/// Send a request through the full Axum router and return the response.
async fn send_request(
    state: AppState,
    method: axum::http::Method,
    uri: &str,
    auth_header: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let router = build_router(state);
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(auth) = auth_header {
        builder = builder.header("authorization", auth);
    }
    builder = builder.header("content-type", "application/json");

    let req = if let Some(b) = body {
        builder.body(Body::from(b.to_string())).unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };

    // Insert ConnectInfo so tower_governor's SmartIpKeyExtractor can resolve the client IP.
    let (mut parts, body) = req.into_parts();
    parts
        .extensions
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));
    let req = Request::from_parts(parts, body);

    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|_| {
        let raw = String::from_utf8_lossy(&body_bytes);
        json!({ "_raw": raw.to_string() })
    });
    (status, body_json)
}

// ═══════════════════════════════════════════════════════════════════════════
// DB-required tests — need live PostgreSQL
// ═══════════════════════════════════════════════════════════════════════════

/// GET /upgrades/available-versions returns 200 with seeded data.
#[tokio::test]
#[ignore]
async fn test_available_versions_list() {
    let db_url = std::env::var("TEST_DATABASE_URL").ok();
    if db_url.is_none() {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    }
    let pool = sqlx::PgPool::connect(&db_url.unwrap()).await.unwrap();

    // Seed an available version
    sqlx::query(
        r#"INSERT INTO available_versions (version, download_url, checksum, file_name, source, prerelease)
           VALUES ('1.0.0-test-list', 'https://example.com/v1.0.0-test-list.deb', NULL,
                   'lpm_1.0.0-test-list_u2404_amd64.deb', 'test-integration', false)
           ON CONFLICT (version, source) DO NOTHING"#,
    )
    .execute(&pool)
    .await
    .expect("failed to seed available version");

    let state = setup_state(pool.clone()).await;

    // No auth needed — this is a public endpoint
    let (status, body) = send_request(
        state,
        axum::http::Method::GET,
        "/api/v1/upgrades/available-versions",
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, got {}: {:?}",
        status,
        body
    );

    let versions = body["versions"]
        .as_array()
        .expect("expected versions array");
    assert!(
        versions
            .iter()
            .any(|v| v["version"].as_str() == Some("1.0.0-test-list")),
        "expected seeded version in response, got: {:?}",
        body
    );

    // Cleanup
    sqlx::query("DELETE FROM available_versions WHERE version = '1.0.0-test-list'")
        .execute(&pool)
        .await
        .ok();
}

/// POST /upgrades/refresh-versions with admin auth.
///
/// Note: This endpoint calls the GitHub API, which may be unreachable in test
/// environments. The test accepts either 200 (GitHub reachable) or 502
/// (GitHub unreachable) as valid outcomes — both confirm auth and routing work.
#[tokio::test]
#[ignore]
async fn test_refresh_versions() {
    let db_url = std::env::var("TEST_DATABASE_URL").ok();
    if db_url.is_none() {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    }
    let pool = sqlx::PgPool::connect(&db_url.unwrap()).await.unwrap();

    let state = setup_state(pool.clone()).await;
    let auth = auth_header("admin");

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/upgrades/refresh-versions",
        Some(&auth),
        None,
    )
    .await;

    // Accept 200 (GitHub reachable) or 502 (GitHub unreachable) — both confirm
    // auth and routing work correctly. 403 would indicate an auth issue.
    assert!(
        status == StatusCode::OK || status == StatusCode::BAD_GATEWAY,
        "expected 200 or 502, got {}: {:?}",
        status,
        body
    );

    if status == StatusCode::OK {
        // Verify response structure when GitHub is reachable
        assert!(
            body["upserted"].is_number(),
            "expected upserted count in response, got: {:?}",
            body
        );
    }
}

/// OS package mapping CRUD: create, read, update, delete.
#[tokio::test]
#[ignore]
async fn test_os_package_mapping_crud() {
    let db_url = std::env::var("TEST_DATABASE_URL").ok();
    if db_url.is_none() {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    }
    let pool = sqlx::PgPool::connect(&db_url.unwrap()).await.unwrap();

    let state = setup_state(pool.clone()).await;
    let auth = auth_header("admin");

    // ── CREATE ─────────────────────────────────────────────────────────────
    let (status, body) = send_request(
        state.clone(),
        axum::http::Method::POST,
        "/api/v1/settings/os-package-mappings",
        Some(&auth),
        Some(json!({
            "os_name": "TestOS",
            "os_version": "1.0",
            "package_pattern": ".testos1\\.deb$",
            "display_name": "TestOS 1.0"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "CREATE: expected 200, got {}: {:?}",
        status,
        body
    );

    let mapping_id = body["mapping"]["id"].as_str().expect("expected mapping id");
    assert_eq!(body["mapping"]["os_name"], "TestOS");
    assert_eq!(body["mapping"]["os_version"], "1.0");
    assert_eq!(body["mapping"]["package_pattern"], ".testos1\\.deb$");
    assert_eq!(body["mapping"]["display_name"], "TestOS 1.0");

    // ── READ (list) ───────────────────────────────────────────────────────
    let (status, body) = send_request(
        state.clone(),
        axum::http::Method::GET,
        "/api/v1/settings/os-package-mappings",
        Some(&auth),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "READ: expected 200, got {}: {:?}",
        status,
        body
    );

    let mappings = body["mappings"]
        .as_array()
        .expect("expected mappings array");
    assert!(
        mappings
            .iter()
            .any(|m| m["os_name"].as_str() == Some("TestOS")
                && m["os_version"].as_str() == Some("1.0")),
        "expected created mapping in list, got: {:?}",
        body
    );

    // ── UPDATE ─────────────────────────────────────────────────────────────
    let update_url = format!("/api/v1/settings/os-package-mappings/{}", mapping_id);
    let (status, body) = send_request(
        state.clone(),
        axum::http::Method::PUT,
        &update_url,
        Some(&auth),
        Some(json!({
            "package_pattern": ".testos1-updated\\.deb$",
            "display_name": "TestOS 1.0 Updated"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "UPDATE: expected 200, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["message"], "Mapping updated");

    // Verify update took effect
    let (status, body) = send_request(
        state.clone(),
        axum::http::Method::GET,
        "/api/v1/settings/os-package-mappings",
        Some(&auth),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let mappings = body["mappings"]
        .as_array()
        .expect("expected mappings array");
    let updated = mappings
        .iter()
        .find(|m| m["id"].as_str() == Some(mapping_id))
        .expect("expected updated mapping in list");
    assert_eq!(updated["package_pattern"], ".testos1-updated\\.deb$");
    assert_eq!(updated["display_name"], "TestOS 1.0 Updated");

    // ── DELETE ─────────────────────────────────────────────────────────────
    // Newly created mappings have is_default = true, which prevents deletion
    // via the API. Set is_default = false directly in the database first.
    sqlx::query("UPDATE os_package_mappings SET is_default = false WHERE id = $1")
        .bind(Uuid::parse_str(mapping_id).unwrap())
        .execute(&pool)
        .await
        .expect("failed to set is_default = false");

    let (status, body) = send_request(
        state.clone(),
        axum::http::Method::DELETE,
        &update_url,
        Some(&auth),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "DELETE: expected 200, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["message"], "Mapping deleted");

    // Verify deletion
    let (status, body) = send_request(
        state,
        axum::http::Method::GET,
        "/api/v1/settings/os-package-mappings",
        Some(&auth),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let mappings = body["mappings"]
        .as_array()
        .expect("expected mappings array");
    assert!(
        !mappings
            .iter()
            .any(|m| m["id"].as_str() == Some(mapping_id)),
        "expected deleted mapping to be removed from list"
    );
}
