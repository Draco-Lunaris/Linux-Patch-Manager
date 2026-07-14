//! Integration tests for the upgrade catalog endpoints:
//!
//! - GET /api/v1/upgrades/available-versions?host_id=... (public, host-filtered)
//! - POST /api/v1/upgrades/trigger (operator+)
//!
//! All tests require a live PostgreSQL database and are marked `#[ignore]`.

use super::common::*;
use axum::http::StatusCode;

// ═══════════════════════════════════════════════════════════════════════════
// DB-required tests — need live PostgreSQL
// ═══════════════════════════════════════════════════════════════════════════

/// GET /upgrades/available-versions?host_id=... returns 200 with seeded
/// repo_packages data filtered by the host's OS.
#[tokio::test]
#[ignore]
async fn test_available_versions_list() {
    let db_url = std::env::var("TEST_DATABASE_URL").ok();
    if db_url.is_none() {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    }
    let pool = sqlx::PgPool::connect(&db_url.unwrap()).await.unwrap();

    // Seed a host and a repo_package for its distro.
    let _host_id = uuid::Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO hosts (fqdn, ip_address, display_name, os_name, health_status)
           VALUES ('test-avail.example.com', '10.0.0.42', 'Test', 'Ubuntu 24.04 LTS', 'healthy')
           ON CONFLICT DO NOTHING"#,
    )
    .execute(&pool)
    .await
    .expect("failed to seed host");

    let host_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM hosts WHERE fqdn = 'test-avail.example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    sqlx::query(
        r#"INSERT INTO repo_packages (filename, version, distro, distro_codename, arch, file_size, source)
           VALUES ('linux-patch-api_2.0.0_u2404_amd64.deb', '2.0.0', 'apt', 'noble', 'amd64', 1000, 'test')
           ON CONFLICT (filename, version, distro, arch) DO NOTHING"#,
    )
    .execute(&pool)
    .await
    .expect("failed to seed repo_package");

    let state = setup_state(pool.clone()).await;

    let url = format!("/api/v1/upgrades/available-versions?host_id={}", host_id);
    let (status, body) = send_request(state, axum::http::Method::GET, &url, None, None).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, got {}: {:?}",
        status,
        body
    );

    let versions = body.as_array().expect("expected versions array");
    assert!(
        versions
            .iter()
            .any(|v| v["version"].as_str() == Some("2.0.0")),
        "expected seeded version in response, got: {:?}",
        body
    );

    // Cleanup
    sqlx::query(
        "DELETE FROM repo_packages WHERE filename = 'linux-patch-api_2.0.0_u2404_amd64.deb'",
    )
    .execute(&pool)
    .await
    .ok();
    sqlx::query("DELETE FROM hosts WHERE fqdn = 'test-avail.example.com'")
        .execute(&pool)
        .await
        .ok();
}
