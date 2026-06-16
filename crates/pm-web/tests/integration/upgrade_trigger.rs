//! Integration tests for the upgrade trigger endpoint (POST /upgrades/trigger)
//! and its RBAC / validation rules.
//!
//! ## Test organization
//!
//! The 403 / 400 tests verify authorization and input validation BEFORE any
//! database logic runs. They use a lazy PgPool (no live database required) and
//! pre-generated CA files, so they always pass in CI.
//!
//! The 200 tests verify the full handler path including database queries and
//! job creation. They require a live PostgreSQL database and are marked
//! `#[ignore]` so they only run when `TEST_DATABASE_URL` is set and
//! `--ignored` is passed.

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
const OPERATOR_USER_ID: &str = "00000000-0000-4000-8000-000000000002";
const REPORTER_USER_ID: &str = "00000000-0000-4000-8000-000000000003";

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Generate a valid JWT authorization header for the given role.
fn auth_header(role: &str) -> String {
    let user_id = match role {
        "admin" => Uuid::parse_str(ADMIN_USER_ID).unwrap(),
        "operator" => Uuid::parse_str(OPERATOR_USER_ID).unwrap(),
        "reporter" => Uuid::parse_str(REPORTER_USER_ID).unwrap(),
        _ => Uuid::parse_str(OPERATOR_USER_ID).unwrap(),
    };
    let username = format!("test-{}", role);
    let token = jwt::issue_access_token(user_id, &username, role, 900, TEST_SIGNING_KEY)
        .expect("failed to issue test JWT");
    format!("Bearer {}", token)
}

/// Generate CA key and cert files on disk so `CertAuthority::init` can load
/// them without needing a database connection.
fn generate_ca_files(ca_dir: &std::path::Path) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
    };

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate CA key");
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Test Root CA");

    let cert = params.self_signed(&key).expect("self-sign CA cert");

    std::fs::create_dir_all(ca_dir).expect("create CA dir");
    std::fs::write(ca_dir.join("ca.key"), key.serialize_pem()).expect("write ca.key");
    std::fs::write(ca_dir.join("ca.crt"), cert.pem()).expect("write ca.crt");
}

/// Build a minimal `AppState` suitable for 403 / 400 tests.
///
/// Uses a lazy PgPool (no live database connection required) and pre-generated
/// CA files. Authorization and input-validation checks reject requests BEFORE
/// any handler or database logic runs.
async fn setup_state_no_db() -> AppState {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://test:test@localhost:5432/test")
        .expect("failed to create lazy pool");

    let mut config = AppConfig::default();
    config.server.static_dir = "/tmp".to_string();

    let auth_config = Arc::new(AuthConfig::new(TEST_VERIFY_KEY.to_string(), &[], &[]));

    let ca_dir = tempfile::tempdir().expect("failed to create temp dir for CA");
    let ca_dir_path = ca_dir.path().to_path_buf();
    generate_ca_files(&ca_dir_path);
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

/// Seed test users into the database so that foreign-key constraints on
/// `actor_user_id` are satisfied.
async fn seed_test_users(pool: &PgPool) {
    let placeholder_hash = "$argon2id$v=19$m=65536,t=3,p=1$placeholder$placeholder";
    for (user_id, username, role) in [
        (ADMIN_USER_ID, "test-admin", "admin"),
        (OPERATOR_USER_ID, "test-operator", "operator"),
        (REPORTER_USER_ID, "test-reporter", "reporter"),
    ] {
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
// 403 / 400 tests — no database required
// ═══════════════════════════════════════════════════════════════════════════

/// Reporter role gets 403 on POST /upgrades/trigger.
/// The authorization middleware rejects non-operator roles BEFORE any handler
/// or database logic runs.
#[tokio::test]
async fn test_trigger_reporter_forbidden() {
    let state = setup_state_no_db().await;
    let auth = auth_header("reporter");
    let host_id = Uuid::new_v4();

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/upgrades/trigger",
        Some(&auth),
        Some(json!({ "host_ids": [host_id] })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected 403, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["error"]["code"], "forbidden");
}

/// POST with empty host_ids returns 400.
/// The handler validates input BEFORE any database logic runs.
#[tokio::test]
async fn test_trigger_empty_host_ids_400() {
    let state = setup_state_no_db().await;
    let auth = auth_header("operator");

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/upgrades/trigger",
        Some(&auth),
        Some(json!({ "host_ids": [] })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["error"]["code"], "bad_request");
}

// ═══════════════════════════════════════════════════════════════════════════
// DB-required tests — need live PostgreSQL
// ═══════════════════════════════════════════════════════════════════════════

/// Operator role gets 200 on POST /upgrades/trigger.
/// Seeds a host and available version, triggers upgrade, verifies job creation.
#[tokio::test]
#[ignore]
async fn test_trigger_operator_allowed() {
    let db_url = std::env::var("TEST_DATABASE_URL").ok();
    if db_url.is_none() {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    }
    let pool = sqlx::PgPool::connect(&db_url.unwrap()).await.unwrap();

    // Seed a host
    let host_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO hosts (id, fqdn, ip_address, os_name, agent_version, health_status)
           VALUES ($1, 'test-trigger-op.example.com', '10.0.0.100', 'Ubuntu 24.04', '1.0.0', 'healthy')"#,
    )
    .bind(host_id)
    .execute(&pool)
    .await
    .expect("failed to seed host");

    // Seed an available version matching Ubuntu 24.04 pattern (_u2404_)
    sqlx::query(
        r#"INSERT INTO available_versions (version, download_url, checksum, file_name, source, prerelease)
           VALUES ('2.0.0-test-op', 'https://example.com/v2.0.0-test-op.deb', NULL,
                   'lpm_2.0.0-test-op_u2404_amd64.deb', 'test-integration', false)"#,
    )
    .execute(&pool)
    .await
    .expect("failed to seed available version");

    let state = setup_state(pool.clone()).await;
    let auth = auth_header("operator");

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/upgrades/trigger",
        Some(&auth),
        Some(json!({ "host_ids": [host_id], "target_version": "2.0.0-test-op" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, got {}: {:?}",
        status,
        body
    );
    assert!(body["job_id"].is_string(), "expected job_id in response");
    assert_eq!(body["host_count"], 1, "expected host_count = 1");

    // Cleanup: delete in dependency order
    let job_id_str = body["job_id"].as_str().unwrap();
    let job_id = Uuid::parse_str(job_id_str).unwrap();
    sqlx::query("DELETE FROM patch_job_hosts WHERE job_id = $1")
        .bind(job_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM patch_jobs WHERE id = $1")
        .bind(job_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM available_versions WHERE version = '2.0.0-test-op'")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM hosts WHERE id = $1")
        .bind(host_id)
        .execute(&pool)
        .await
        .ok();
}

/// POST with non-existent target_version returns 400.
#[tokio::test]
#[ignore]
async fn test_trigger_unknown_version_400() {
    let db_url = std::env::var("TEST_DATABASE_URL").ok();
    if db_url.is_none() {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    }
    let pool = sqlx::PgPool::connect(&db_url.unwrap()).await.unwrap();

    // Seed a host (no available version needed — we're testing a non-existent version)
    let host_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO hosts (id, fqdn, ip_address, os_name, agent_version, health_status)
           VALUES ($1, 'test-trigger-unknown.example.com', '10.0.0.101', 'Ubuntu 24.04', '1.0.0', 'healthy')"#,
    )
    .bind(host_id)
    .execute(&pool)
    .await
    .expect("failed to seed host");

    let state = setup_state(pool.clone()).await;
    let auth = auth_header("operator");

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/upgrades/trigger",
        Some(&auth),
        Some(json!({ "host_ids": [host_id], "target_version": "99.99.99" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["error"]["code"], "bad_request");

    // Cleanup
    sqlx::query("DELETE FROM hosts WHERE id = $1")
        .bind(host_id)
        .execute(&pool)
        .await
        .ok();
}

/// Hosts already at target version are returned in `skipped`.
#[tokio::test]
#[ignore]
async fn test_trigger_hosts_already_at_version_skipped() {
    let db_url = std::env::var("TEST_DATABASE_URL").ok();
    if db_url.is_none() {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    }
    let pool = sqlx::PgPool::connect(&db_url.unwrap()).await.unwrap();

    // Seed a host already at the target version
    let host_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO hosts (id, fqdn, ip_address, os_name, agent_version, health_status)
           VALUES ($1, 'test-trigger-skip.example.com', '10.0.0.102', 'Ubuntu 24.04', '2.0.0-test-skip', 'healthy')"#,
    )
    .bind(host_id)
    .execute(&pool)
    .await
    .expect("failed to seed host");

    // Seed an available version matching the host's current version
    sqlx::query(
        r#"INSERT INTO available_versions (version, download_url, checksum, file_name, source, prerelease)
           VALUES ('2.0.0-test-skip', 'https://example.com/v2.0.0-test-skip.deb', NULL,
                   'lpm_2.0.0-test-skip_u2404_amd64.deb', 'test-integration', false)"#,
    )
    .execute(&pool)
    .await
    .expect("failed to seed available version");

    let state = setup_state(pool.clone()).await;
    let auth = auth_header("operator");

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/upgrades/trigger",
        Some(&auth),
        Some(json!({ "host_ids": [host_id], "target_version": "2.0.0-test-skip" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, got {}: {:?}",
        status,
        body
    );

    // Host should be in skipped, not in host_count
    let skipped = body["skipped"].as_array().expect("expected skipped array");
    assert!(
        skipped.iter().any(|s| {
            s["host_id"].as_str() == Some(&host_id.to_string())
                && s["reason"].as_str().unwrap().contains("already")
        }),
        "expected host {} in skipped with 'already' reason, got: {:?}",
        host_id,
        body
    );
    assert_eq!(body["host_count"], 0, "expected host_count = 0");

    // Cleanup
    sqlx::query("DELETE FROM available_versions WHERE version = '2.0.0-test-skip'")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM hosts WHERE id = $1")
        .bind(host_id)
        .execute(&pool)
        .await
        .ok();
}
