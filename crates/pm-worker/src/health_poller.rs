//! Periodic health poller for all registered hosts.
//!
//! Polls every host via the agent `/health` endpoint on each tick of
//! `health_poll_interval_secs`, with bounded concurrency controlled by a
//! [`tokio::sync::Semaphore`].

use std::sync::Arc;

use pm_agent_client::{AgentClient, AgentClientError};
use pm_core::{config::AppConfig, models::HostHealthStatus};
use sqlx::{FromRow, PgPool};
use tokio::{sync::Semaphore, time};
use uuid::Uuid;

use crate::agent_loader::load_agent_certs;

/// Minimal host projection fetched for each poll cycle.
#[derive(Debug, FromRow)]
struct HostRow {
    id: Uuid,
    ip_address: String,
    agent_port: i32,
}

/// Run the health poller loop indefinitely.
///
/// On each tick all registered hosts are queried concurrently (up to
/// `max_concurrent_agent_calls` in-flight at once). Results are persisted
/// to `host_health_data` and the `hosts` table is updated.
pub async fn run_health_poller(pool: PgPool, config: Arc<AppConfig>) {
    let interval_secs = config.worker.health_poll_interval_secs;
    let mut ticker = time::interval(std::time::Duration::from_secs(interval_secs));

    tracing::info!(interval_secs, "Health poller started");

    loop {
        ticker.tick().await;

        // Load certs on each cycle so cert rotation is picked up automatically.
        let certs = match load_agent_certs(&config.security) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "Health poller: failed to load agent certs — skipping cycle");
                continue;
            },
        };

        let client_cert = Arc::new(certs.client_cert);
        let client_key = Arc::new(certs.client_key);
        let ca_cert = Arc::new(certs.ca_cert);

        // Fetch all hosts.
        let hosts: Vec<HostRow> = match sqlx::query_as(
            "SELECT id, host(ip_address)::text AS ip_address, agent_port FROM hosts ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "Health poller: failed to fetch hosts");
                continue;
            },
        };

        if hosts.is_empty() {
            tracing::debug!("Health poller: no hosts registered, skipping cycle");
            continue;
        }

        let total = hosts.len();
        let semaphore = Arc::new(Semaphore::new(config.worker.max_concurrent_agent_calls));

        let mut handles = Vec::with_capacity(total);

        for host in hosts {
            let pool = pool.clone();
            let sem = semaphore.clone();
            let cert = client_cert.clone();
            let key = client_key.clone();
            let ca = ca_cert.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                poll_host_health(pool, host, &cert, &key, &ca).await
            });

            handles.push(handle);
        }

        // Collect results and tally counts.
        let mut healthy = 0usize;
        let mut degraded = 0usize;
        let mut unreachable = 0usize;

        for handle in handles {
            match handle.await {
                Ok(HostHealthStatus::Healthy) => healthy += 1,
                Ok(HostHealthStatus::Degraded) => degraded += 1,
                Ok(HostHealthStatus::Unreachable) => unreachable += 1,
                Ok(_) => {},
                Err(e) => tracing::error!(error = %e, "Health poller task panicked"),
            }
        }

        tracing::info!(
            total,
            healthy,
            degraded,
            unreachable,
            "Health poll cycle complete"
        );
    }
}

/// Poll a single host, persist the result, and return the determined status.
async fn poll_host_health(
    pool: PgPool,
    host: HostRow,
    client_cert: &[u8],
    client_key: &[u8],
    ca_cert: &[u8],
) -> HostHealthStatus {
    // Determine status and optional health payload.
    let (status, payload) = match AgentClient::new(
        &host.ip_address,
        host.agent_port as u16,
        client_cert,
        client_key,
        ca_cert,
    ) {
        Err(e) => {
            tracing::warn!(
                host_id = %host.id,
                error = %e,
                "Health poller: failed to build AgentClient"
            );
            (
                HostHealthStatus::Unreachable,
                serde_json::Value::Object(Default::default()),
            )
        },
        Ok(client) => match client.health().await {
            Ok(data) => {
                let payload = serde_json::to_value(&data).unwrap_or_default();
                (HostHealthStatus::Healthy, payload)
            },
            Err(AgentClientError::Timeout) => {
                tracing::warn!(host_id = %host.id, "Health poller: agent timed out");
                (
                    HostHealthStatus::Unreachable,
                    serde_json::Value::Object(Default::default()),
                )
            },
            Err(AgentClientError::Connect(_)) => {
                tracing::warn!(host_id = %host.id, "Health poller: agent connection refused");
                (
                    HostHealthStatus::Unreachable,
                    serde_json::Value::Object(Default::default()),
                )
            },
            Err(e) => {
                tracing::warn!(host_id = %host.id, error = %e, "Health poller: agent error");
                (
                    HostHealthStatus::Degraded,
                    serde_json::Value::Object(Default::default()),
                )
            },
        },
    };

    // Insert into host_health_data.
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO host_health_data (host_id, status, payload)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(host.id)
    .bind(&status)
    .bind(&payload)
    .execute(&pool)
    .await
    {
        tracing::error!(host_id = %host.id, error = %e, "Health poller: failed to insert health data");
    }

    // Update hosts table.
    if let Err(e) = sqlx::query(
        r#"
        UPDATE hosts
        SET health_status = $2, last_health_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(host.id)
    .bind(&status)
    .execute(&pool)
    .await
    {
        tracing::error!(host_id = %host.id, error = %e, "Health poller: failed to update host status");
    }

    status
}
