//! Periodic health poller for all registered hosts.
//!
//! Polls every host via the agent `/health` endpoint on each tick of
//! `health_poll_interval_secs`, with bounded concurrency controlled by a
//! [`tokio::sync::Semaphore`]. Also calls `/system/info` to refresh
//! `os_family`, `os_name`, `arch`, and `agent_version` in the hosts table.
//!
//! CRL health aggregation rules (PR 5):
//! - `crl_status = "invalid"` → host health_status overridden to `unreachable`
//! - `crl_status = "expired"` → host health_status overridden to `degraded` (if currently healthy)
//! - `crl_status = "missing"` AND registered > 24h ago → host health_status overridden to `degraded` (if currently healthy)
//! - `crl_status = "valid"` or NULL → no override
//!
//! Audit events are logged for CRL state transitions.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use pm_agent_client::{AgentClient, AgentClientError};
use pm_core::{
    audit::{log_event, AuditAction},
    config::AppConfig,
    models::HostHealthStatus,
};
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
    /// Current CRL status from the hosts table (for transition detection).
    crl_status: Option<String>,
    /// When the host was first registered (for enrollment age checks).
    registered_at: DateTime<Utc>,
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

        // Fetch all hosts with CRL status and registration time.
        let hosts: Vec<HostRow> = match sqlx::query_as(
            "SELECT id, host(ip_address)::text AS ip_address, agent_port, crl_status, registered_at FROM hosts ORDER BY id",
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
/// CRL status fields from the health response when reported by the agent,
/// and applies CRL health aggregation rules.
async fn poll_host_health(
    pool: PgPool,
    host: HostRow,
    client_cert: &[u8],
    client_key: &[u8],
    ca_cert: &[u8],
) -> HostHealthStatus {
    // Determine status, payload, agent version, optional system info, and CRL fields.
    let (
        natural_status,
        payload,
        agent_version,
        sys_info,
        crl_status,
        crl_age_seconds,
        crl_next_update,
    ) = match AgentClient::new(
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

    // Apply CRL health aggregation rules to determine the effective status.
    // Only apply when the agent reported a CRL status (non-NULL).
    let effective_status = apply_crl_health_rules(&natural_status, &crl_status, host.registered_at);

    // Insert into host_health_data with the natural (pre-aggregation) status.
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO host_health_data (host_id, status, payload)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(host.id)
    .bind(&natural_status)
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

    // Update hosts table with the effective (post-aggregation) health status,
    // agent version, OS details, and CRL fields.
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
    .bind(&effective_status)
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
        // Don't log audit events if the DB update failed.
        return effective_status;
    }

    // Log CRL audit events after successful database update.
    if let Some(ref new_crl) = crl_status {
        log_crl_audit_events(
            &pool,
            host.id,
            host.crl_status.as_deref(),
            new_crl,
            crl_age_seconds,
        )
        .await;
    }

    effective_status
}

/// Apply CRL health aggregation rules to determine the effective health status.
///
/// Rules:
/// - `crl_status = "invalid"` → `Unreachable` (security event, always overrides)
/// - `crl_status = "expired"` → `Degraded` (only if natural status is `Healthy`)
/// - `crl_status = "missing"` AND registered > 24h ago → `Degraded` (only if natural status is `Healthy`)
/// - `crl_status = "valid"` or NULL → no override
fn apply_crl_health_rules(
    natural_status: &HostHealthStatus,
    crl_status: &Option<String>,
    registered_at: DateTime<Utc>,
) -> HostHealthStatus {
    let Some(crl) = crl_status else {
        // Older agent not reporting CRL — don't modify health status.
        return natural_status.clone();
    };

    match crl.as_str() {
        "invalid" => HostHealthStatus::Unreachable,
        "expired" => {
            if *natural_status == HostHealthStatus::Healthy {
                HostHealthStatus::Degraded
            } else {
                natural_status.clone()
            }
        },
        "missing" => {
            let age = Utc::now() - registered_at;
            if age > Duration::hours(24) && *natural_status == HostHealthStatus::Healthy {
                HostHealthStatus::Degraded
            } else {
                natural_status.clone()
            }
        },
        // "valid" or any other value — no override
        _ => natural_status.clone(),
    }
}

/// Log audit events for CRL state transitions.
///
/// Called after the hosts table has been successfully updated.
/// Logs:
/// - `CrlStatusChanged` when the CRL status transitions to a different value
/// - `CrlStaleDetected` when CRL status becomes "expired"
/// - `CrlInvalid` when CRL status becomes "invalid"
async fn log_crl_audit_events(
    pool: &PgPool,
    host_id: Uuid,
    old_crl_status: Option<&str>,
    new_crl_status: &str,
    crl_age_seconds: Option<i64>,
) {
    let host_id_str = host_id.to_string();
    let old_str = old_crl_status.unwrap_or("null");

    // Log a transition event if the status changed.
    if old_crl_status != Some(new_crl_status) {
        let details = serde_json::json!({
            "host_id": host_id_str,
            "old_crl_status": old_str,
            "new_crl_status": new_crl_status,
            "crl_age_seconds": crl_age_seconds,
        });
        log_event(
            pool,
            AuditAction::CrlStatusChanged,
            None,               // actor_user_id — system-initiated
            None,               // actor_username
            Some("host"),       // target_type
            Some(&host_id_str), // target_id
            details,
            None, // ip_address
            None, // request_id
        )
        .await;
    }

    // Log specific events for problematic CRL states.
    match new_crl_status {
        "expired" => {
            let details = serde_json::json!({
                "host_id": host_id_str,
                "old_crl_status": old_str,
                "new_crl_status": new_crl_status,
                "crl_age_seconds": crl_age_seconds,
            });
            log_event(
                pool,
                AuditAction::CrlStaleDetected,
                None,
                None,
                Some("host"),
                Some(&host_id_str),
                details,
                None,
                None,
            )
            .await;
        },
        "invalid" => {
            let details = serde_json::json!({
                "host_id": host_id_str,
                "old_crl_status": old_str,
                "new_crl_status": new_crl_status,
                "crl_age_seconds": crl_age_seconds,
            });
            log_event(
                pool,
                AuditAction::CrlInvalid,
                None,
                None,
                Some("host"),
                Some(&host_id_str),
                details,
                None,
                None,
            )
            .await;
        },
        _ => {},
    }
}
