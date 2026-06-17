//! Integration tests for the upgrade catalog endpoints:
//!
//! - GET  /api/v1/upgrades/available-versions  (public)
//! - POST /api/v1/upgrades/refresh-versions   (admin)
//! - OS package mapping CRUD at /api/v1/settings/os-package-mappings (admin)
//!
//! All tests require a live PostgreSQL database and are marked `#[ignore]`.

use super::common::*;
use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

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
