//! Shared integration-test helpers for pm-web.
//!
//! Extracted from individual test files to eliminate duplication of the
//! Ed25519 test key pair (which triggers GitHub secret-scanning false
//! positives when copy-pasted across multiple files).

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
pub const TEST_SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBrWiMMcgpPXwtGDSSBl01fcQyb5Vh4CMzEmxcSXvcrJ
-----END PRIVATE KEY-----
";

pub const TEST_VERIFY_KEY: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEACgE6fMDCcG11NOpPKSO/ASpPUSntB7XsF5sBFBYDjFo=
-----END PUBLIC KEY-----
";

// ── Fixed test user IDs (so we can seed matching rows in the DB) ─────────────
pub const ADMIN_USER_ID: &str = "00000000-0000-4000-8000-000000000001";
pub const OPERATOR_USER_ID: &str = "00000000-0000-4000-8000-000000000002";
pub const REPORTER_USER_ID: &str = "00000000-0000-4000-8000-000000000003";

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Generate a valid JWT authorization header for the given role.
pub fn auth_header(role: &str) -> String {
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
pub fn generate_ca_files(ca_dir: &std::path::Path) {
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
pub async fn setup_state_no_db() -> AppState {
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
pub async fn seed_test_users(pool: &PgPool) {
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
pub async fn setup_state(pool: PgPool) -> AppState {
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
pub async fn send_request(
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
