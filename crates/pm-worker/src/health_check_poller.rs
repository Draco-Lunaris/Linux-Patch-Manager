//! Periodic health check poller for configured service and HTTP checks.
//!
//! Polls every `health_check_poll_interval_secs`, querying each enabled health
//! check definition and storing results in `host_health_check_results`.
//! Results older than 4 days are pruned on each cycle.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use pm_core::{config::AppConfig, crypto};
use sqlx::{FromRow, PgPool};
use tokio::{sync::Semaphore, time};
use uuid::Uuid;

use crate::agent_loader::load_agent_certs;
use pm_agent_client::{AgentClient, AgentClientError};

// ─────────────────────────────────────────────────────────────────────────────
// DB row types
// ─────────────────────────────────────────────────────────────────────────────

/// Row fetched for each enabled health check, joined with host connection info.
#[derive(Debug, FromRow)]
struct HealthCheckRow {
    id: Uuid,
    host_id: Uuid,
    name: String,
    check_type: String,
    service_name: Option<String>,
    url: Option<String>,
    expected_body: Option<String>,
    ignore_cert_errors: Option<bool>,
    basic_auth_user: Option<String>,
    basic_auth_pass_encrypted: Option<Vec<u8>>,
    basic_auth_pass_nonce: Option<Vec<u8>>,
    ip_address: String,
    agent_port: i32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run the health check poller loop indefinitely.
///
/// On each tick all enabled health checks are queried concurrently (up to
/// `max_concurrent_agent_calls` in-flight at once). Results are persisted
/// to `host_health_check_results` and stale rows are pruned.
pub async fn run_health_check_poller(pool: PgPool, config: Arc<AppConfig>) {
    let interval_secs = config.worker.health_check_poll_interval_secs;
    let mut ticker = time::interval(std::time::Duration::from_secs(interval_secs));

    tracing::info!(interval_secs, "Health check poller started");

    loop {
        ticker.tick().await;

        // Load certs on each cycle so cert rotation is picked up automatically.
        let certs = match load_agent_certs(&config.security) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Health check poller: failed to load agent certs — skipping cycle"
                );
                continue;
            },
        };

        let client_cert = Arc::new(certs.client_cert);
        let client_key = Arc::new(certs.client_key);
        let ca_cert = Arc::new(certs.ca_cert);

        // Load the crypto key for decrypting HTTP check passwords.
        let crypto_key = match crypto::load_or_create_key(Path::new(crypto::KEY_PATH)) {
            Ok(k) => Arc::new(k),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Health check poller: failed to load crypto key — skipping cycle"
                );
                continue;
            },
        };

        // Fetch all enabled health checks with host connection info.
        let checks: Vec<HealthCheckRow> = match sqlx::query_as(
            r#"
            SELECT
                hc.id,
                hc.host_id,
                hc.name,
                hc.check_type,
                hc.service_name,
                hc.url,
                hc.expected_body,
                hc.ignore_cert_errors,
                hc.basic_auth_user,
                hc.basic_auth_pass_encrypted,
                hc.basic_auth_pass_nonce,
                host(h.ip_address)::text AS ip_address,
                h.agent_port
            FROM host_health_checks hc
            JOIN hosts h ON h.id = hc.host_id
            WHERE hc.enabled = TRUE
            ORDER BY hc.id
            "#,
        )
        .fetch_all(&pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "Health check poller: failed to fetch health checks");
                continue;
            },
        };

        if checks.is_empty() {
            tracing::debug!("Health check poller: no enabled health checks, skipping cycle");
            prune_old_results(&pool).await;
            continue;
        }

        let total = checks.len();
        let semaphore = Arc::new(Semaphore::new(config.worker.max_concurrent_agent_calls));

        let mut handles = Vec::with_capacity(total);

        for check in checks {
            let pool = pool.clone();
            let sem = semaphore.clone();
            let cert = client_cert.clone();
            let key = client_key.clone();
            let ca = ca_cert.clone();
            let ckey = crypto_key.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                run_check(pool, check, &cert, &key, &ca, &ckey).await
            });

            handles.push(handle);
        }

        // Collect results and tally counts.
        let mut healthy_count = 0usize;
        let mut unhealthy_count = 0usize;
        let mut error_count = 0usize;

        for handle in handles {
            match handle.await {
                Ok(true) => healthy_count += 1,
                Ok(false) => unhealthy_count += 1,
                Err(e) => {
                    tracing::error!(error = %e, "Health check poller task panicked");
                    error_count += 1;
                },
            }
        }

        tracing::info!(
            total,
            healthy_count,
            unhealthy_count,
            error_count,
            "Health check poll cycle complete"
        );

        // Prune results older than 4 days.
        prune_old_results(&pool).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Check dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Run a single health check and persist the result. Returns `true` if healthy.
async fn run_check(
    pool: PgPool,
    check: HealthCheckRow,
    client_cert: &[u8],
    client_key: &[u8],
    ca_cert: &[u8],
    crypto_key: &[u8; 32],
) -> bool {
    let start = Instant::now();

    let (healthy, detail) = match check.check_type.as_str() {
        "service" => run_service_check(&check, client_cert, client_key, ca_cert).await,
        "http" => run_http_check(&check, crypto_key).await,
        other => {
            tracing::warn!(
                check_id = %check.id,
                check_type = other,
                "Unknown health check type — treating as unhealthy"
            );
            (false, format!("Unknown check type: {other}"))
        },
    };

    let latency_ms = start.elapsed().as_millis() as i32;

    // Persist the result.
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO host_health_check_results (check_id, healthy, detail, latency_ms)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(check.id)
    .bind(healthy)
    .bind(&detail)
    .bind(latency_ms)
    .execute(&pool)
    .await
    {
        tracing::error!(
            check_id = %check.id,
            error = %e,
            "Health check poller: failed to insert result"
        );
    }

    healthy
}

// ─────────────────────────────────────────────────────────────────────────────
// Service check (via mTLS AgentClient)
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a service check by calling the agent's `/api/v1/system/services/{name}` endpoint.
async fn run_service_check(
    check: &HealthCheckRow,
    client_cert: &[u8],
    client_key: &[u8],
    ca_cert: &[u8],
) -> (bool, String) {
    let service_name = match &check.service_name {
        Some(name) => name.clone(),
        None => {
            return (false, "Service check missing service_name".to_string());
        },
    };

    let client = match AgentClient::new(
        &check.ip_address,
        check.agent_port as u16,
        client_cert,
        client_key,
        ca_cert,
    ) {
        Ok(c) => c,
        Err(e) => {
            return (false, format!("Failed to build AgentClient: {e}"));
        },
    };

    match client.service_status(&service_name).await {
        Ok(data) => {
            let detail = if data.healthy {
                format!(
                    "Service '{}' is {}/{} (enabled: {})",
                    data.name,
                    data.active_state,
                    data.sub_state,
                    data.enabled_state
                )
            } else {
                format!(
                    "Service '{}' status: {}/{} (unhealthy, enabled: {})",
                    data.name, data.active_state,
                    data.sub_state,
                    data.enabled_state
                )
            };
            (data.healthy, detail)
        },
        Err(AgentClientError::Timeout) => {
            (false, format!("Agent timed out querying service '{service_name}'"))
        },
        Err(AgentClientError::Connect(_)) => {
            (false, format!("Agent connection refused for service '{service_name}'"))
        },
        Err(AgentClientError::ApiError { code, message }) => {
            // 404, 400, 500 etc. from the agent means the service is unhealthy.
            (false, format!("Agent error [{code}]: {message}"))
        },
        Err(e) => {
            (false, format!("Agent error querying service '{service_name}': {e}"))
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP check (via reqwest, no mTLS)
// ─────────────────────────────────────────────────────────────────────────────

/// Execute an HTTP check by making a GET request to the configured URL.
/// Supports optional basic auth (decrypted from DB) and substring body matching.
async fn run_http_check(
    check: &HealthCheckRow,
    crypto_key: &[u8; 32],
) -> (bool, String) {
    let url = match &check.url {
        Some(u) => u.clone(),
        None => {
            return (false, "HTTP check missing URL".to_string());
        },
    };

    // Build a reqwest client for this check.
    // Use danger_accept_invalid_certs if ignore_cert_errors is set (default true).
    let ignore_cert_errors = check.ignore_cert_errors.unwrap_or(true);

    let client_builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5));

    let client = if ignore_cert_errors {
        client_builder
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    } else {
        client_builder.build().unwrap_or_else(|_| reqwest::Client::new())
    };

    // Build the request.
    let mut request = client.get(&url);

    // Add basic auth if configured.
    if let Some(user) = &check.basic_auth_user {
        // Decrypt the password if present.
        let password = match (&check.basic_auth_pass_encrypted, &check.basic_auth_pass_nonce) {
            (Some(enc), Some(nonce)) => {
                match crypto::decrypt(enc, nonce, crypto_key) {
                    Ok(p) => p,
                    Err(e) => {
                        return (
                            false,
                            format!("Failed to decrypt basic auth password: {e}"),
                        );
                    },
                }
            },
            _ => {
                // No encrypted password stored — treat as missing credentials.
                return (false, "HTTP check has basic_auth_user but no encrypted password".to_string());
            },
        };
        request = request.basic_auth(user.as_str(), Some(password.as_str()));
    }

    // Execute the request.
    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            if e.is_timeout() {
                return (false, format!("HTTP check timed out: {url}"));
            } else if e.is_connect() {
                return (false, format!("HTTP check connection failed: {url}"));
            } else {
                return (false, format!("HTTP check request error: {e}"));
            }
        },
    };

    let status = response.status();

    // Check HTTP status code.
    if !status.is_success() {
        return (
            false,
            format!("HTTP check returned status {} for {url}", status.as_u16()),
        );
    }

    // Read the response body for substring matching.
    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return (false, format!("HTTP check failed to read response body: {e}"));
        },
    };

    // Check expected_body substring match.
    if let Some(expected) = &check.expected_body {
        if !body.contains(expected) {
            return (
                false,
                format!(
                    "HTTP check body mismatch for {url}: expected substring not found"
                ),
            );
        }
    }

    (true, format!("HTTP check OK for {url} (status {})", status.as_u16()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Prune old results
// ─────────────────────────────────────────────────────────────────────────────

/// Delete health check results older than 4 days.
async fn prune_old_results(pool: &PgPool) {
    match sqlx::query(
        "DELETE FROM host_health_check_results WHERE checked_at < NOW() - INTERVAL '4 days'",
    )
    .execute(pool)
    .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                tracing::info!(
                    rows_deleted = result.rows_affected(),
                    "Health check poller: pruned old results"
                );
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "Health check poller: failed to prune old results");
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health check gate for job executor
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether all enabled health checks for a host are healthy.
///
/// Returns `Ok(true)` if all checks pass (or no checks are configured),
/// `Ok(false)` if any check is unhealthy or has no result yet.
pub async fn check_host_health_checks(pool: &PgPool, host_id: Uuid) -> anyhow::Result<bool> {
    // Check if there are any enabled health checks for this host.
    let check_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM host_health_checks WHERE host_id = $1 AND enabled = TRUE",
    )
    .bind(host_id)
    .fetch_one(pool)
    .await?;

    if check_count.0 == 0 {
        // No health checks configured for this host — treat as healthy.
        return Ok(true);
    }

    // Find any enabled check that has no healthy result or an unhealthy latest result.
    let unhealthy_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM host_health_checks hc
        LEFT JOIN LATERAL (
            SELECT healthy
            FROM host_health_check_results r
            WHERE r.check_id = hc.id
            ORDER BY r.checked_at DESC
            LIMIT 1
        ) latest ON true
        WHERE hc.host_id = $1
          AND hc.enabled = TRUE
          AND (latest.healthy IS NULL OR latest.healthy = FALSE)
        "#,
    )
    .bind(host_id)
    .fetch_one(pool)
    .await?;

    Ok(unhealthy_count.0 == 0)
}
