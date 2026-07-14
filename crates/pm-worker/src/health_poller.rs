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
    /// Current consecutive failure count (for hysteresis).
    consecutive_failures: i32,
}

/// Number of consecutive failures required before a host is marked unreachable.
const FAILURE_THRESHOLD: i32 = 3;

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
            "SELECT id, host(ip_address)::text AS ip_address, agent_port, crl_status, registered_at, consecutive_failures FROM hosts ORDER BY id",
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
    // Determine status, payload, agent version, optional system info, CRL fields, and GPG key fields.
    let (
        natural_status,
        payload,
        agent_version,
        sys_info,
        crl_status,
        crl_age_seconds,
        crl_next_update,
        gpg_key_status,
        gpg_key_expires_at,
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
                None,
                None,
            )
        },
        Ok(client) => {
            let (status, payload, version, crl_status, crl_age, crl_next, gpg_status, gpg_expires) =
                match client.health().await {
                    Ok(data) => {
                        let payload = serde_json::to_value(&data).unwrap_or_default();
                        let crl_status = data.crl_status.clone();
                        let crl_age = data.crl_age_seconds;
                        let crl_next = data.crl_next_update.clone();
                        let gpg_status = data.gpg_key_status.clone();
                        let gpg_expires = data.gpg_key_expires_at.clone();
                        (
                            HostHealthStatus::Healthy,
                            payload,
                            Some(data.version),
                            crl_status,
                            crl_age,
                            crl_next,
                            gpg_status,
                            gpg_expires,
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
                status,
                payload,
                version,
                sys_info,
                crl_status,
                crl_age,
                crl_next,
                gpg_status,
                gpg_expires,
            )
        },
    };

    // Apply CRL health aggregation rules to determine the effective status.
    // Only apply when the agent reported a CRL status (non-NULL).
    let effective_status = apply_crl_health_rules(&natural_status, &crl_status, host.registered_at);

    // ── Hysteresis: prevent flapping from transient failures ────────────
    // A host is only marked Unreachable after FAILURE_THRESHOLD consecutive
    // failures. Below the threshold, transient failures are reported as
    // Degraded so the UI doesn't flap. Healthy polls reset the counter.
    let (new_failure_count, hysteresis_status) =
        apply_hysteresis(&natural_status, effective_status, host.consecutive_failures);

    if new_failure_count != host.consecutive_failures {
        tracing::debug!(
            host_id = %host.id,
            natural_status = ?natural_status,
            hysteresis_status = ?hysteresis_status,
            consecutive_failures = new_failure_count,
            threshold = FAILURE_THRESHOLD,
            "Health poller: hysteresis applied",
        );
    }

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

    // Parse GPG key expiry from ISO-8601 string to DateTime if present.
    let gpg_key_expires_at_dt: Option<chrono::DateTime<chrono::Utc>> = gpg_key_expires_at
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.to_utc());

    // Update hosts table with the hysteresis-adjusted health status,
    // agent version, OS details, CRL fields, and consecutive failure count.
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
            crl_next_update = COALESCE($9, crl_next_update),
            gpg_key_status = COALESCE($10, gpg_key_status),
            gpg_key_expires_at = COALESCE($11, gpg_key_expires_at),
            consecutive_failures = $12
        WHERE id = $1
        "#,
    )
    .bind(host.id)
    .bind(&hysteresis_status)
    .bind(&agent_version)
    .bind(sys_info.as_ref().map(|i| i.os.as_str()))
    .bind(os_name_from_sysinfo)
    .bind(sys_info.as_ref().map(|i| i.architecture.as_str()))
    .bind(&crl_status)
    .bind(crl_age_seconds)
    .bind(crl_next_update_dt)
    .bind(&gpg_key_status)
    .bind(gpg_key_expires_at_dt)
    .bind(new_failure_count)
    .execute(&pool)
    .await
    {
        tracing::error!(host_id = %host.id, error = %e, "Health poller: failed to update host status");
        // Don't log audit events if the DB update failed.
        return hysteresis_status;
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

    hysteresis_status
}

/// Apply hysteresis to prevent health status flapping.
///
/// Returns `(new_failure_count, adjusted_status)`:
/// - **Healthy** poll → reset failures to 0, status unchanged
/// - **Unreachable** poll → increment failures; if below threshold, suppress to Degraded
/// - **Other** (Degraded/Pending) → leave failure count unchanged, status unchanged
///
/// The `effective_status` input is the post-CRL-aggregation status. The hysteresis
/// only suppresses `Unreachable` → `Degraded` when failures haven't reached the
/// threshold. It never suppresses CRL-forced `Unreachable` (e.g. `crl_status =
/// "invalid"`) because those are set by `apply_crl_health_rules` from a *healthy*
/// natural status, not from a connection failure.
fn apply_hysteresis(
    natural_status: &HostHealthStatus,
    effective_status: HostHealthStatus,
    current_failures: i32,
) -> (i32, HostHealthStatus) {
    let new_failures = match natural_status {
        HostHealthStatus::Healthy => 0,
        HostHealthStatus::Unreachable => current_failures + 1,
        _ => current_failures,
    };

    let adjusted = if new_failures >= FAILURE_THRESHOLD {
        effective_status
    } else if *natural_status == HostHealthStatus::Unreachable
        && effective_status == HostHealthStatus::Unreachable
    {
        HostHealthStatus::Degraded
    } else {
        effective_status
    };

    (new_failures, adjusted)
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

// ---------------------------------------------------------------------------
// Tests — CRL health aggregation rules
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_crl_health {
    use super::*;
    use chrono::{Duration, Utc};

    /// Helper: create a DateTime that is `hours` hours in the past.
    fn hours_ago(h: i64) -> DateTime<Utc> {
        Utc::now() - Duration::hours(h)
    }

    // ---- crl_status = "invalid" → Unreachable (always overrides) ----

    #[test]
    fn crl_invalid_overrides_healthy_to_unreachable() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Healthy,
            &Some("invalid".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Unreachable);
    }

    #[test]
    fn crl_invalid_overrides_degraded_to_unreachable() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Degraded,
            &Some("invalid".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Unreachable);
    }

    #[test]
    fn crl_invalid_overrides_unreachable_stays_unreachable() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Unreachable,
            &Some("invalid".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Unreachable);
    }

    // ---- crl_status = "expired" → Degraded (only if currently Healthy) ----

    #[test]
    fn crl_expired_downgrades_healthy_to_degraded() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Healthy,
            &Some("expired".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Degraded);
    }

    #[test]
    fn crl_expired_does_not_override_degraded() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Degraded,
            &Some("expired".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Degraded);
    }

    #[test]
    fn crl_expired_does_not_downgrade_unreachable() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Unreachable,
            &Some("expired".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Unreachable);
    }

    // ---- crl_status = "missing" AND registered > 24h → Degraded (if Healthy) ----

    #[test]
    fn crl_missing_old_registration_downgrades_healthy() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Healthy,
            &Some("missing".to_string()),
            hours_ago(25),
        );
        assert_eq!(result, HostHealthStatus::Degraded);
    }

    #[test]
    fn crl_missing_recent_registration_no_override() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Healthy,
            &Some("missing".to_string()),
            hours_ago(12),
        );
        assert_eq!(result, HostHealthStatus::Healthy);
    }

    #[test]
    fn crl_missing_does_not_override_degraded() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Degraded,
            &Some("missing".to_string()),
            hours_ago(25),
        );
        assert_eq!(result, HostHealthStatus::Degraded);
    }

    #[test]
    fn crl_missing_does_not_override_unreachable() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Unreachable,
            &Some("missing".to_string()),
            hours_ago(25),
        );
        assert_eq!(result, HostHealthStatus::Unreachable);
    }

    // ---- crl_status = "valid" → no override ----

    #[test]
    fn crl_valid_does_not_override_healthy() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Healthy,
            &Some("valid".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Healthy);
    }

    #[test]
    fn crl_valid_preserves_degraded() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Degraded,
            &Some("valid".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Degraded);
    }

    #[test]
    fn crl_valid_preserves_unreachable() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Unreachable,
            &Some("valid".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Unreachable);
    }

    // ---- NULL crl_status → no override (backward compat) ----

    #[test]
    fn null_crl_status_preserves_healthy() {
        let result = apply_crl_health_rules(&HostHealthStatus::Healthy, &None, hours_ago(0));
        assert_eq!(result, HostHealthStatus::Healthy);
    }

    #[test]
    fn null_crl_status_preserves_degraded() {
        let result = apply_crl_health_rules(&HostHealthStatus::Degraded, &None, hours_ago(0));
        assert_eq!(result, HostHealthStatus::Degraded);
    }

    #[test]
    fn null_crl_status_preserves_unreachable() {
        let result = apply_crl_health_rules(&HostHealthStatus::Unreachable, &None, hours_ago(0));
        assert_eq!(result, HostHealthStatus::Unreachable);
    }

    // ---- Edge cases ----

    #[test]
    fn crl_missing_just_under_24h_no_override() {
        // 23h 59m old — should NOT trigger degraded (threshold is > 24h)
        let result = apply_crl_health_rules(
            &HostHealthStatus::Healthy,
            &Some("missing".to_string()),
            Utc::now() - Duration::hours(23) - Duration::minutes(59),
        );
        assert_eq!(result, HostHealthStatus::Healthy);
    }

    #[test]
    fn crl_missing_just_over_24h_triggers_degraded() {
        // 24h + 1 minute old — should trigger degraded
        let result = apply_crl_health_rules(
            &HostHealthStatus::Healthy,
            &Some("missing".to_string()),
            Utc::now() - Duration::hours(24) - Duration::minutes(1),
        );
        assert_eq!(result, HostHealthStatus::Degraded);
    }

    #[test]
    fn crl_pending_status_preserved_with_valid_crl() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Pending,
            &Some("valid".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Pending);
    }

    #[test]
    fn crl_invalid_overrides_pending_to_unreachable() {
        let result = apply_crl_health_rules(
            &HostHealthStatus::Pending,
            &Some("invalid".to_string()),
            hours_ago(0),
        );
        assert_eq!(result, HostHealthStatus::Unreachable);
    }
}

// ---------------------------------------------------------------------------
// Tests — Hysteresis logic
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_hysteresis {
    use super::*;

    // ---- Healthy polls reset the failure counter ----

    #[test]
    fn healthy_poll_resets_failures_to_zero() {
        let (failures, status) =
            apply_hysteresis(&HostHealthStatus::Healthy, HostHealthStatus::Healthy, 5);
        assert_eq!(failures, 0);
        assert_eq!(status, HostHealthStatus::Healthy);
    }

    #[test]
    fn healthy_poll_after_failures_clears_counter() {
        // Host had 2 consecutive failures, now responds healthy
        let (failures, status) =
            apply_hysteresis(&HostHealthStatus::Healthy, HostHealthStatus::Healthy, 2);
        assert_eq!(failures, 0);
        assert_eq!(status, HostHealthStatus::Healthy);
    }

    // ---- First failure is suppressed to Degraded ----

    #[test]
    fn first_failure_suppressed_to_degraded() {
        let (failures, status) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            0,
        );
        assert_eq!(failures, 1);
        assert_eq!(status, HostHealthStatus::Degraded);
    }

    #[test]
    fn second_failure_still_suppressed_to_degraded() {
        let (failures, status) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            1,
        );
        assert_eq!(failures, 2);
        assert_eq!(status, HostHealthStatus::Degraded);
    }

    // ---- Third failure reaches threshold → Unreachable ----

    #[test]
    fn third_failure_reaches_threshold_unreachable() {
        let (failures, status) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            2,
        );
        assert_eq!(failures, 3);
        assert_eq!(status, HostHealthStatus::Unreachable);
    }

    #[test]
    fn fourth_failure_stays_unreachable() {
        let (failures, status) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            3,
        );
        assert_eq!(failures, 4);
        assert_eq!(status, HostHealthStatus::Unreachable);
    }

    // ---- Recovery: one healthy poll after failures resets to Healthy ----

    #[test]
    fn recovery_after_threshold_breach_resets_immediately() {
        // Host was unreachable (4 failures), now responds healthy
        let (failures, status) =
            apply_hysteresis(&HostHealthStatus::Healthy, HostHealthStatus::Healthy, 4);
        assert_eq!(failures, 0);
        assert_eq!(status, HostHealthStatus::Healthy);
    }

    // ---- Degraded natural status doesn't change failure count ----

    #[test]
    fn degraded_poll_does_not_increment_failures() {
        let (failures, status) =
            apply_hysteresis(&HostHealthStatus::Degraded, HostHealthStatus::Degraded, 0);
        assert_eq!(failures, 0);
        assert_eq!(status, HostHealthStatus::Degraded);
    }

    #[test]
    fn degraded_poll_preserves_existing_failure_count() {
        let (failures, status) =
            apply_hysteresis(&HostHealthStatus::Degraded, HostHealthStatus::Degraded, 2);
        assert_eq!(failures, 2);
        assert_eq!(status, HostHealthStatus::Degraded);
    }

    // ---- CRL-forced Unreachable from a Healthy natural status is not suppressed ----

    #[test]
    fn crl_invalid_unreachable_not_suppressed_by_hysteresis() {
        // Agent responded (natural = Healthy) but CRL is invalid → effective = Unreachable.
        // Hysteresis should NOT suppress this because it's not a connection failure.
        let (failures, status) = apply_hysteresis(
            &HostHealthStatus::Healthy,
            HostHealthStatus::Unreachable, // CRL-forced
            0,
        );
        assert_eq!(failures, 0);
        assert_eq!(status, HostHealthStatus::Unreachable);
    }

    // ---- Flapping scenario: intermittent failures never reach threshold ----

    #[test]
    fn flapping_scenario_fail_success_fail_never_unreachable() {
        // Simulate: fail, succeed, fail, succeed, fail
        // The host should never reach Unreachable because each success resets the counter
        let (f1, s1) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            0,
        );
        assert_eq!((f1, s1), (1, HostHealthStatus::Degraded));

        let (f2, s2) = apply_hysteresis(&HostHealthStatus::Healthy, HostHealthStatus::Healthy, f1);
        assert_eq!((f2, s2), (0, HostHealthStatus::Healthy));

        let (f3, s3) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            f2,
        );
        assert_eq!((f3, s3), (1, HostHealthStatus::Degraded));

        let (f4, s4) = apply_hysteresis(&HostHealthStatus::Healthy, HostHealthStatus::Healthy, f3);
        assert_eq!((f4, s4), (0, HostHealthStatus::Healthy));

        let (f5, s5) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            f4,
        );
        assert_eq!((f5, s5), (1, HostHealthStatus::Degraded));
    }

    // ---- Sustained failure scenario: 3 consecutive failures → Unreachable ----

    #[test]
    fn sustained_failures_reach_unreachable() {
        let (f1, s1) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            0,
        );
        assert_eq!((f1, s1), (1, HostHealthStatus::Degraded));

        let (f2, s2) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            f1,
        );
        assert_eq!((f2, s2), (2, HostHealthStatus::Degraded));

        let (f3, s3) = apply_hysteresis(
            &HostHealthStatus::Unreachable,
            HostHealthStatus::Unreachable,
            f2,
        );
        assert_eq!((f3, s3), (3, HostHealthStatus::Unreachable));
    }
}
