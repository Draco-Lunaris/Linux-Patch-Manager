//! Integration tests for the authz gate that restricts auth config mutations
//! (OIDC, SMTP, IP whitelist) to the Admin role only.
//!
//! See Issue #15 for the full specification.
//!
//! ## Test organization
//
//! The 403 (forbidden_role) tests verify that the authorization middleware
//! rejects non-admin roles BEFORE any handler or database logic runs. These
//! tests use a lazy PgPool (no live database required) and pre-generated CA
//! files, so they always pass in CI.
//!
//! The 200 (admin allowed) tests verify the full handler path including audit
//! logging. They require a live PostgreSQL database and are marked `#[ignore]`
//! so they only run when `DATABASE_URL` is set and `--ignored` is passed.

use super::common::*;
use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

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
