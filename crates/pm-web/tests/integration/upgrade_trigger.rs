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

use super::common::*;
use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

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
