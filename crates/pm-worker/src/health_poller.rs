//! Periodic health poller for all registered hosts.
//!
//! Polls every host via the agent `/health` endpoint on each tick of
//! `health_poll_interval_secs`, with bounded concurrency controlled by a
//! [`tokio::sync::Semaphore`]. Also calls `/system/info` to refresh
//! `os_family`, `os_name`, `arch`, and `agent_version` in the hosts table.

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
///
/// Also updates `agent_version` from the health response,
/// `os_family`/`os_name`/`arch` from the `/system/info` endpoint when available,
/// and CRL status fields from the health response when reported by the agent.
async fn poll_host_health(
    pool: PgPool,
    host: HostRow,
    client_cert: &[u8],
    client_key: &[u8],
    ca_cert: &[u8],
) -> HostHealthStatus {
    // Determine status, payload, agent version, optional system info, and CRL fields.
    let (status, payload, agent_version, sys_info, crl_status, crl_age_seconds, crl_next_update) =
        match AgentClient::new(
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
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            Ok(client) => {
                let (status, payload, version, crl_status, crl_age, crl_next) = match client
                    .health()
                    .await
                {
                    Ok(data) => {
                        let payload = serde_json::to_value(&data).unwrap_or_default();
                        let crl_status = data.crl_status.clone();
                        let crl_age = data.crl_age_seconds;
                        let crl_next = data.crl_next_update.clone();
                        (
                            HostHealthStatus::Healthy,
                            payload,
                            Some(data.version),
                            crl_status,
                            crl_age,
                            crl_next,
                        )
                    },
                    Err(AgentClientError::Timeout) => {
                        tracing::warn!(host_id = %host.id, "Health poller: agent timed out");
                        (
                            HostHealthStatus::Unreachable,
                            serde_json::Value::Object(Default::default()),
                            None,
                            None,
                            None,
                            None,
                        )
                    },
                    Err(AgentClientError::Connect(_)) => {
                        tracing::warn!(host_id = %host.id, "Health poller: agent connection refused");
                        (
                            HostHealthStatus::Unreachable,
                            serde_json::Value::Object(Default::default()),
                            None,
                            None,
                            None,
                            None,
                        )
                    },
                    Err(e) => {
                        tracing::warn!(host_id = %host.id, error = %e, "Health poller: agent error");
                        (
                            HostHealthStatus::Degraded,
                            serde_json::Value::Object(Default::default()),
                            None,
                            None,
                            None,
                            None,
                        )
                    },
                };

                // Try to fetch system info for OS/arch details (best-effort).
                let sys_info = if status != HostHealthStatus::Unreachable {
                    match client.system_info().await {
                        Ok(info) => Some(info),
                        Err(e) => {
                            tracing::debug!(
                                host_id = %host.id,
                                error = %e,
                                "Health poller: failed to get system info (non-fatal)"
                            );
                            None
                        },
                    }
                } else {
                    None
                };

                (
                    status, payload, version, sys_info, crl_status, crl_age, crl_next,
                )
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

    // Build OS name from system info components (e.g. "Ubuntu 24.04").
    let os_name_from_sysinfo = sys_info
        .as_ref()
        .map(|i| format!("{} {}", i.os, i.os_version));

    // Parse CRL next_update from ISO-8601 string to DateTime if present.
    let crl_next_update_dt: Option<chrono::DateTime<chrono::Utc>> = crl_next_update
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.to_utc());

    // Update hosts table with health status, agent version, OS details, and CRL fields.
    // COALESCE preserves existing values when new data is unavailable.
    if let Err(e) = sqlx::query(
        r#"
        UPDATE hosts
        SET health_status = $2, last_health_at = NOW(),
            agent_version = COALESCE($3, agent_version),
            os_family = COALESCE($4, os_family),
            os_name = COALESCE($5, os_name),
            arch = COALESCE($6, arch),
            crl_status = COALESCE($7, crl_status),
            crl_age_seconds = COALESCE($8, crl_age_seconds),
            crl_next_update = COALESCE($9, crl_next_update)
        WHERE id = $1
        "#,
    )
    .bind(host.id)
    .bind(&status)
    .bind(&agent_version)
    .bind(sys_info.as_ref().map(|i| i.os.as_str()))
    .bind(os_name_from_sysinfo)
    .bind(sys_info.as_ref().map(|i| i.architecture.as_str()))
    .bind(&crl_status)
    .bind(crl_age_seconds)
    .bind(crl_next_update_dt)
    .execute(&pool)
    .await
    {
        tracing::error!(host_id = %host.id, error = %e, "Health poller: failed to update host status");
    }

    status
}
