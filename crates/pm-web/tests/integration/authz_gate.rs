//! Integration tests for the authz gate that restricts auth config mutations
//! (OIDC, SMTP, IP whitelist) to the Admin role only.
//!
//! See Issue #15 for the full specification.
//!
//! ## Test organization
//!
//! The 403 (forbidden_role) tests verify that the authorization middleware
//! rejects non-admin roles BEFORE any handler or database logic runs. These
//! tests use a lazy PgPool (no live database required) and pre-generated CA
//! files, so they always pass in CI.
//!
//! The 200 (admin allowed) tests verify the full handler path including audit
//! logging. They require a live PostgreSQL database and are marked `#[ignore]`
//! so they only run when `DATABASE_URL` is set and `--ignored` is passed.

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

// ── Fixed test user IDs (so we can seed matching rows in the DB) ─────────────
const ADMIN_USER_ID: &str = "00000000-0000-4000-8000-000000000001";
const OPERATOR_USER_ID: &str = "00000000-0000-4000-8000-000000000002";

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Generate a valid JWT authorization header for the given role.
fn auth_header(role: &str) -> String {
    let user_id = match role {
        "admin" => Uuid::parse_str(ADMIN_USER_ID).unwrap(),
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

/// Build a minimal `AppState` suitable for 403 authz gate tests.
///
/// Uses a lazy PgPool (no live database connection required) and pre-generated
/// CA files. This works because the authorization middleware rejects non-admin
/// requests BEFORE any handler or database logic runs.
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

/// Seed test users into the database so that audit_log foreign-key
/// constraints on `actor_user_id` are satisfied.
async fn seed_test_users(pool: &PgPool) {
    let placeholder_hash = "$argon2id$v=19$m=65536,t=3,p=1$placeholder$placeholder";
    for (user_id, username, role) in [
        (ADMIN_USER_ID, "test-admin", "admin"),
        (OPERATOR_USER_ID, "test-operator", "operator"),
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
// 403 Forbidden Role tests — no database required
// ═══════════════════════════════════════════════════════════════════════════
//
// These tests verify that the authorization middleware rejects non-admin roles
// BEFORE any handler or database logic runs. They use a lazy PgPool and
// pre-generated CA files, so they always pass in CI.

/// 1. PUT /api/v1/settings with operator role → 403 forbidden_role
#[tokio::test]
async fn update_settings_operator_denied() {
    let state = setup_state_no_db().await;
    let auth = auth_header("operator");

    let (status, body) = send_request(
        state,
        axum::http::Method::PUT,
        "/api/v1/settings",
        Some(&auth),
        Some(json!({ "polling": { "health_poll_interval_secs": 300 } })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected 403, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["error"]["code"], "forbidden_role");
}

/// 3. PUT /api/v1/settings/ip-whitelist with operator role → 403 forbidden_role
#[tokio::test]
async fn update_ip_whitelist_operator_denied() {
    let state = setup_state_no_db().await;
    let auth = auth_header("operator");

    let (status, body) = send_request(
        state,
        axum::http::Method::PUT,
        "/api/v1/settings/ip-whitelist",
        Some(&auth),
        Some(json!({ "entries": ["10.0.0.0/8"] })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected 403, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["error"]["code"], "forbidden_role");
}

/// 5. POST /api/v1/settings/sso/discover with operator role → 403 forbidden_role
#[tokio::test]
async fn discover_oidc_operator_denied() {
    let state = setup_state_no_db().await;
    let auth = auth_header("operator");

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/settings/sso/discover",
        Some(&auth),
        Some(json!({ "discovery_url": "https://example.com/.well-known/openid-configuration" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected 403, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["error"]["code"], "forbidden_role");
}

/// 7. POST /api/v1/settings/sso/test with operator role → 403 forbidden_role
#[tokio::test]
async fn test_oidc_operator_denied() {
    let state = setup_state_no_db().await;
    let auth = auth_header("operator");

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/settings/sso/test",
        Some(&auth),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected 403, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["error"]["code"], "forbidden_role");
}

// ═══════════════════════════════════════════════════════════════════════════
// 200 Admin Allowed tests — require live database
// ═══════════════════════════════════════════════════════════════════════════
//
// These tests verify the full handler path including audit logging.
// They require a live PostgreSQL database and are marked `#[ignore]` so they
// only run when DATABASE_URL is set and `--ignored` is passed.

/// 2. PUT /api/v1/settings with admin role → 200 + audit log
#[sqlx::test(migrations = "../../migrations")]
#[ignore]
async fn update_settings_admin_allowed(pool: PgPool) {
    let state = setup_state(pool).await;
    let pool = state.db.clone();
    let auth = auth_header("admin");

    let (status, body) = send_request(
        state,
        axum::http::Method::PUT,
        "/api/v1/settings",
        Some(&auth),
        Some(json!({ "polling": { "health_poll_interval_secs": 300 } })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, got {}: {:?}",
        status,
        body
    );

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT action::text FROM audit_log WHERE action::text = 'config_changed' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .expect("audit log query failed");
    assert!(row.is_some(), "expected audit log entry for config_changed");
}

/// 4. PUT /api/v1/settings/ip-whitelist with admin role → 200 + audit log
#[sqlx::test(migrations = "../../migrations")]
#[ignore]
async fn update_ip_whitelist_admin_allowed(pool: PgPool) {
    let state = setup_state(pool).await;
    let pool = state.db.clone();
    let auth = auth_header("admin");

    let (status, body) = send_request(
        state,
        axum::http::Method::PUT,
        "/api/v1/settings/ip-whitelist",
        Some(&auth),
        Some(json!({ "entries": ["10.0.0.0/8"] })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, got {}: {:?}",
        status,
        body
    );

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT action::text FROM audit_log WHERE action::text = 'ip_whitelist_updated' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .expect("audit log query failed");
    assert!(
        row.is_some(),
        "expected audit log entry for ip_whitelist_updated"
    );
}

/// 6. POST /api/v1/settings/sso/discover with admin role → 200 + audit log
///    Uses mockito to simulate an OIDC discovery endpoint.
#[sqlx::test(migrations = "../../migrations")]
#[ignore]
async fn discover_oidc_admin_allowed(pool: PgPool) {
    let state = setup_state(pool).await;
    let pool = state.db.clone();
    let auth = auth_header("admin");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "issuer": "https://mock-oidc.example.com",
                "authorization_endpoint": "https://mock-oidc.example.com/auth",
                "token_endpoint": "https://mock-oidc.example.com/token",
                "jwks_uri": "https://mock-oidc.example.com/jwks",
                "userinfo_endpoint": "https://mock-oidc.example.com/userinfo"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let discovery_url = format!("{}/.well-known/openid-configuration", server.url());

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/settings/sso/discover",
        Some(&auth),
        Some(json!({ "discovery_url": discovery_url })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, got {}: {:?}",
        status,
        body
    );
    assert_eq!(body["success"], true);

    mock.assert_async().await;

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT action::text FROM audit_log WHERE action::text = 'oidc_discover_performed' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .expect("audit log query failed");
    assert!(
        row.is_some(),
        "expected audit log entry for oidc_discover_performed"
    );
}

/// 8. POST /api/v1/settings/sso/test with admin role → 200 + audit log
///    Uses mockito to simulate an OIDC discovery endpoint.
#[sqlx::test(migrations = "../../migrations")]
#[ignore]
async fn test_oidc_admin_allowed(pool: PgPool) {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "issuer": "https://mock-oidc.example.com",
                "authorization_endpoint": "https://mock-oidc.example.com/auth",
                "token_endpoint": "https://mock-oidc.example.com/token",
                "jwks_uri": "https://mock-oidc.example.com/jwks"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let discovery_url = format!("{}/.well-known/openid-configuration", server.url());

    // Seed the oidc_config table with an enabled provider pointing to mockito.
    sqlx::query("UPDATE oidc_config SET enabled = true, discovery_url = $1 WHERE id = 1")
        .bind(&discovery_url)
        .execute(&pool)
        .await
        .expect("failed to seed oidc_config");

    let state = setup_state(pool).await;
    let pool = state.db.clone();
    let auth = auth_header("admin");

    let (status, body) = send_request(
        state,
        axum::http::Method::POST,
        "/api/v1/settings/sso/test",
        Some(&auth),
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
    assert_eq!(body["success"], true);

    mock.assert_async().await;

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT action::text FROM audit_log WHERE action::text = 'oidc_test_performed' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .expect("audit log query failed");
    assert!(
        row.is_some(),
        "expected audit log entry for oidc_test_performed"
    );
}
