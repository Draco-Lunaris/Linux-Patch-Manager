//! WS relay — M7
//!
//! For every running `patch_job_hosts` row that has an `agent_job_id`, open a
//! WebSocket to the corresponding agent, stream job-status events, update the
//! DB row, and fire `pg_notify('job_update', payload_json)` so the browser WS
//! handler can forward the event to connected clients.

use std::{collections::HashSet, error::Error, sync::Arc, time::Duration};

use anyhow::Context;
use futures::StreamExt;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig as TlsClientConfig, RootCertStore,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::protocol::Message, Connector};
use uuid::Uuid;

use pm_agent_client::client::AgentClient;
use pm_agent_client::client::DEFAULT_AGENT_PORT;
use pm_core::config::AppConfig;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct RunningHostJob {
    job_id: Uuid,
    host_id: Uuid,
    agent_job_id: String,
    host_address: String,
}

/// JSON event streamed by the agent over its WS endpoint.
#[derive(Debug, Deserialize)]
struct AgentWsEvent {
    #[allow(dead_code)]
    job_id: String,
    status: String,
    output: Option<String>,
    error: Option<String>,
    #[allow(dead_code)]
    progress_percent: Option<u8>,
}

/// Payload broadcast via `pg_notify('job_update', …)`.
#[derive(Debug, Serialize)]
struct NotifyPayload {
    event_type: String, // "host" or "job"
    job_id: String,
    host_id: String,
    status: String,
    output: Option<String>,
    error_message: Option<String>,
    agent_job_id: String,
    // Job-level fields (only present when event_type === "job")
    succeeded_count: Option<i64>,
    failed_count: Option<i64>,
    host_count: Option<i64>,
}

// ── Cert PEM bytes for building AgentClient ────────────────────────────────────

/// Raw PEM bytes read from the security config cert paths.
/// Used to build an [`AgentClient`] for HTTP polling fallback.
#[derive(Clone)]
struct CertPems {
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
    ca_cert: Vec<u8>,
}

/// Read the three PEM files referenced by the security config.
/// Mirrors the file reads in [`build_tls_config`] but returns raw bytes instead of
/// parsing them into rustls types.
async fn read_cert_pems(config: &AppConfig) -> anyhow::Result<CertPems> {
    let sec = &config.security;
    let client_cert = tokio::fs::read(&sec.agent_client_cert_path)
        .await
        .with_context(|| format!("read agent client cert '{}'", sec.agent_client_cert_path))?;
    let client_key = tokio::fs::read(&sec.agent_client_key_path)
        .await
        .with_context(|| format!("read agent client key '{}'", sec.agent_client_key_path))?;
    let ca_cert = tokio::fs::read(&sec.ca_cert_path)
        .await
        .with_context(|| format!("read CA cert '{}'", sec.ca_cert_path))?;
    Ok(CertPems {
        client_cert,
        client_key,
        ca_cert,
    })
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Long-running task: polls the DB for running host-jobs and spawns a per-pair
/// relay task for each one that isn't already being tracked.
pub async fn run_ws_relay(pool: PgPool, config: Arc<AppConfig>) {
    tracing::info!("WS relay task started");

    let active: Arc<Mutex<HashSet<(Uuid, Uuid)>>> = Arc::new(Mutex::new(HashSet::new()));

    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let rows = match query_running_jobs(&pool).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "ws_relay: DB poll failed");
                continue;
            },
        };

        for row in rows {
            let key = (row.job_id, row.host_id);

            // Skip pairs that already have an active relay.
            if active.lock().await.contains(&key) {
                continue;
            }

            // Build the rustls ClientConfig once per connection.
            let tls_config = match build_tls_config(&config).await {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    tracing::error!(error = %e, "ws_relay: TLS config error");
                    continue;
                },
            };

            // Read raw cert PEM bytes for HTTP polling fallback.
            let cert_pems = match read_cert_pems(&config).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(error = %e, "ws_relay: cert PEM read error");
                    continue;
                },
            };

            let poll_interval = config.worker.ws_relay_poll_interval_secs;

            active.lock().await.insert(key);

            let pool_c = pool.clone();
            let active_c = active.clone();

            tokio::spawn(async move {
                tracing::info!(
                    job_id       = %row.job_id,
                    host_id      = %row.host_id,
                    agent_job_id = %row.agent_job_id,
                    host         = %row.host_address,
                    "WS relay: starting relay"
                );

                match relay_one_job(&pool_c, &row, tls_config, &cert_pems, poll_interval).await {
                    Ok(()) => tracing::info!(
                        job_id  = %row.job_id,
                        host_id = %row.host_id,
                        "WS relay: completed"
                    ),
                    Err(e) => tracing::error!(
                        error   = %e,
                        job_id  = %row.job_id,
                        host_id = %row.host_id,
                        "WS relay: ended with error"
                    ),
                }

                active_c.lock().await.remove(&key);
            });
        }
    }
}

// ── DB helpers ────────────────────────────────────────────────────────────────

async fn query_running_jobs(pool: &PgPool) -> anyhow::Result<Vec<RunningHostJob>> {
    sqlx::query_as::<_, RunningHostJob>(
        r#"
        SELECT
            pjh.job_id,
            pjh.host_id,
            pjh.agent_job_id,
             COALESCE(h.fqdn, host(h.ip_address)::text) AS host_address
        FROM patch_job_hosts pjh
        JOIN hosts h ON h.id = pjh.host_id
        WHERE pjh.status = 'running'::job_status
          AND pjh.agent_job_id IS NOT NULL
        "#,
    )
    .fetch_all(pool)
    .await
    .context("query_running_jobs")
}

// ── TLS ───────────────────────────────────────────────────────────────────────

async fn build_tls_config(config: &AppConfig) -> anyhow::Result<TlsClientConfig> {
    let sec = &config.security;

    let cert_pem = tokio::fs::read(&sec.agent_client_cert_path)
        .await
        .with_context(|| format!("read agent client cert '{}'", sec.agent_client_cert_path))?;
    let key_pem = tokio::fs::read(&sec.agent_client_key_path)
        .await
        .with_context(|| format!("read agent client key '{}'", sec.agent_client_key_path))?;
    let ca_pem = tokio::fs::read(&sec.ca_cert_path)
        .await
        .with_context(|| format!("read CA cert '{}'", sec.ca_cert_path))?;

    // Parse client certificate chain.
    let client_certs: Vec<CertificateDer<'static>> = {
        let mut cur = std::io::Cursor::new(&cert_pem);
        rustls_pemfile::certs(&mut cur)
            .collect::<Result<Vec<_>, _>>()
            .context("parse client cert PEM")?
    };

    // Parse client private key.
    let client_key: PrivateKeyDer<'static> = {
        let mut cur = std::io::Cursor::new(&key_pem);
        rustls_pemfile::private_key(&mut cur)
            .context("parse client key PEM")?
            .context("no private key in PEM")?
    };

    // Build root store from CA cert.
    let mut root_store = RootCertStore::empty();
    {
        let mut cur = std::io::Cursor::new(&ca_pem);
        for cert_result in rustls_pemfile::certs(&mut cur) {
            root_store
                .add(cert_result.context("read CA cert entry")?)
                .context("add CA cert to root store")?;
        }
    }

    let mut config = TlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .context("build TlsClientConfig")?;

    // WebSocket requires HTTP/1.1 — without ALPN the server may negotiate
    // h2 (HTTP/2), which breaks the WebSocket upgrade handshake
    // ("Key mismatch in Sec-WebSocket-Accept header").
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

// ── Per-job relay ─────────────────────────────────────────────────────────────

async fn relay_one_job(
    pool: &PgPool,
    row: &RunningHostJob,
    tls_config: Arc<TlsClientConfig>,
    cert_pems: &CertPems,
    poll_interval_secs: u64,
) -> anyhow::Result<()> {
    let url = format!(
        "wss://{}:{}/api/v1/ws/jobs",
        row.host_address, DEFAULT_AGENT_PORT,
    );

    let (ws_stream, _) = match connect_async_tls_with_config(
        url.as_str(),
        None,
        false,
        Some(Connector::Rustls(tls_config)),
    )
    .await
    {
        Ok(ws) => ws,
        Err(e) => {
            // Log the full error chain for TLS debugging
            let mut source = e.source();
            let mut depth = 0;
            while let Some(err) = source {
                tracing::warn!(
                    job_id = %row.job_id,
                    host_id = %row.host_id,
                    depth,
                    error = %err,
                    "WS relay: TLS connection error detail"
                );
                source = err.source();
                depth += 1;
            }
            // Fall back to HTTP polling instead of returning an error.
            tracing::info!(
                job_id = %row.job_id,
                host_id = %row.host_id,
                host = %row.host_address,
                "WS relay: WebSocket connection failed, falling back to HTTP polling"
            );
            return relay_one_job_poll(pool, row, cert_pems, poll_interval_secs).await;
        },
    };

    let (_sink, mut stream) = ws_stream.split();

    while let Some(frame) = stream.next().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    error   = %e,
                    job_id  = %row.job_id,
                    host_id = %row.host_id,
                    "WS relay: stream error"
                );
                break;
            },
        };

        let text = match frame {
            Message::Text(t) => t.to_string(),
            Message::Binary(b) => String::from_utf8(b.into()).unwrap_or_default(),
            Message::Close(_) => {
                tracing::info!(job_id = %row.job_id, "Agent WS closed cleanly");
                break;
            },
            _ => continue,
        };

        if text.is_empty() {
            continue;
        }

        let event: AgentWsEvent = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    error = %e, raw = %text,
                    "WS relay: unparseable agent frame"
                );
                continue;
            },
        };

        process_event(pool, row, &event).await;

        if matches!(event.status.as_str(), "succeeded" | "failed" | "cancelled") {
            tracing::info!(
                job_id  = %row.job_id,
                host_id = %row.host_id,
                status  = %event.status,
                "WS relay: terminal state — stopping"
            );
            break;
        }
    }

    Ok(())
}

// ── Per-job HTTP polling fallback ─────────────────────────────────────────────

/// Fall back to HTTP polling when the WebSocket connection fails.
///
/// Builds an [`AgentClient`] from the same cert paths used for TLS, polls
/// `GET /api/v1/jobs/{id}` every `poll_interval_secs`, and calls
/// [`process_event`] whenever the status changes from the previous poll.
/// Stops when the job reaches a terminal state (succeeded/failed/cancelled).
async fn relay_one_job_poll(
    pool: &PgPool,
    row: &RunningHostJob,
    cert_pems: &CertPems,
    poll_interval_secs: u64,
) -> anyhow::Result<()> {
    // Build the HTTP client using the same mTLS certs.
    let agent_client = AgentClient::new(
        &row.host_address,
        DEFAULT_AGENT_PORT,
        &cert_pems.client_cert,
        &cert_pems.client_key,
        &cert_pems.ca_cert,
    )
    .context("build AgentClient for polling fallback")?;

    let mut last_status: Option<String> = None;
    let poll_interval = Duration::from_secs(poll_interval_secs);

    loop {
        tokio::time::sleep(poll_interval).await;

        let job_status = match agent_client.job_status(&row.agent_job_id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(
                    job_id = %row.job_id,
                    host_id = %row.host_id,
                    error = %e,
                    "WS relay poll: job_status request failed, will retry"
                );
                continue;
            },
        };

        // Map agent status to the WS event format.
        // The agent uses "completed" but pm-worker expects "succeeded".
        // The agent uses "queued" but pm-worker expects "running".
        let mapped_status = match job_status.status.as_str() {
            "queued" => "running",
            "running" => "running",
            "succeeded" => "succeeded",
            "completed" => "succeeded",
            "failed" => "failed",
            "cancelled" => "cancelled",
            other => {
                tracing::warn!(
                    status = %other,
                    job_id = %row.job_id,
                    "WS relay poll: unknown agent status, treating as running"
                );
                "running"
            },
        };

        tracing::debug!(
            job_id = %row.job_id,
            host_id = %row.host_id,
            agent_status = %job_status.status,
            mapped_status = %mapped_status,
            progress = ?job_status.progress_percent,
            "WS relay poll: fetched job status"
        );

        // Only process when the status has changed since the last poll.
        if last_status.as_deref() == Some(mapped_status) {
            continue;
        }

        last_status = Some(mapped_status.to_string());

        let event = AgentWsEvent {
            job_id: job_status.job_id.clone(),
            status: mapped_status.to_string(),
            output: job_status.output.clone(),
            error: job_status.error.clone(),
            progress_percent: job_status.progress_percent,
        };

        process_event(pool, row, &event).await;

        // Stop polling on terminal states.
        if matches!(mapped_status, "succeeded" | "failed" | "cancelled") {
            tracing::info!(
                job_id = %row.job_id,
                host_id = %row.host_id,
                status = %mapped_status,
                "WS relay poll: terminal state — stopping"
            );
            break;
        }
    }

    Ok(())
}

// ── Event processing ──────────────────────────────────────────────────────────

async fn process_event(pool: &PgPool, row: &RunningHostJob, event: &AgentWsEvent) {
    // Map agent status string to DB job_status enum value.
    //
    // The agent sends "completed" (from JobStatus::Completed.as_str()), not
    // "succeeded". The HTTP polling path in job_executor.rs already handles
    // both ("succeeded" | "completed"). This must match.
    let db_status = match event.status.as_str() {
        "running" => "running",
        "succeeded" | "completed" => "succeeded",
        "failed" => "failed",
        "cancelled" => "cancelled",
        other => {
            tracing::warn!(status = %other, "WS relay: unknown agent status");
            return;
        },
    };

    let output = event.output.as_deref().unwrap_or("");
    let error_msg = event.error.as_deref();

    // Determine timestamps based on terminal state.
    let is_terminal = matches!(db_status, "succeeded" | "failed" | "cancelled");

    // Update the DB row. The status guard prevents a late/racing event from
    // overwriting a row that a concurrent writer (the HTTP poller in
    // job_executor.rs, or a prior event) already drove to a terminal state —
    // the succeeded→failed false negative.
    let update_result = if is_terminal {
        sqlx::query(
            r#"
            UPDATE patch_job_hosts
            SET status        = $1::job_status,
                output        = CASE WHEN $2 != '' THEN $2 ELSE output END,
                error_message = $3,
                completed_at  = NOW()
            WHERE job_id = $4
              AND host_id = $5
              AND status NOT IN ('succeeded','failed','cancelled')
            "#,
        )
        .bind(db_status)
        .bind(output)
        .bind(error_msg)
        .bind(row.job_id)
        .bind(row.host_id)
        .execute(pool)
        .await
    } else {
        sqlx::query(
            r#"
            UPDATE patch_job_hosts
            SET status = $1::job_status,
                output = CASE WHEN $2 != '' THEN $2 ELSE output END
            WHERE job_id = $3
              AND host_id = $4
              AND status NOT IN ('succeeded','failed','cancelled')
            "#,
        )
        .bind(db_status)
        .bind(output)
        .bind(row.job_id)
        .bind(row.host_id)
        .execute(pool)
        .await
    };

    let rows_affected = match update_result {
        Ok(res) => res.rows_affected(),
        Err(e) => {
            tracing::error!(
                error   = %e,
                job_id  = %row.job_id,
                host_id = %row.host_id,
                "WS relay: DB update failed"
            );
            return;
        },
    };

    // 0 rows = the guard found the row already terminal. A stale event must
    // not re-sync the parent (could clobber the parent aggregate) and must not
    // fire pg_notify (the payload carries this event's status, which would
    // flip the browser display to a stale terminal state).
    if rows_affected == 0 {
        tracing::info!(
            job_id  = %row.job_id,
            host_id = %row.host_id,
            status  = %db_status,
            "WS relay: row already terminal — skipping parent sync and notify"
        );
        return;
    }

    // Also update the parent patch_jobs status when the host-level job reaches
    // a terminal state: running → if all hosts terminal then update parent.
    if is_terminal {
        update_parent_job_status(pool, row.job_id).await;
    }

    // Fire pg_notify so browser WS handlers forward the host-level event.
    let payload = NotifyPayload {
        event_type: "host".to_string(),
        job_id: row.job_id.to_string(),
        host_id: row.host_id.to_string(),
        status: db_status.to_string(),
        output: event.output.clone(),
        error_message: event.error.clone(),
        agent_job_id: row.agent_job_id.clone(),
        succeeded_count: None,
        failed_count: None,
        host_count: None,
    };

    let payload_json = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "WS relay: failed to serialize notify payload");
            return;
        },
    };

    if let Err(e) = sqlx::query("SELECT pg_notify('job_update', $1)")
        .bind(&payload_json)
        .execute(pool)
        .await
    {
        tracing::error!(
            error   = %e,
            job_id  = %row.job_id,
            host_id = %row.host_id,
            "WS relay: pg_notify failed"
        );
    } else {
        tracing::debug!(
            job_id  = %row.job_id,
            host_id = %row.host_id,
            status  = %db_status,
            "WS relay: pg_notify sent"
        );
    }
}

// ── Parent job status rollup ──────────────────────────────────────────────────

/// After a host-level job reaches a terminal state, check whether ALL hosts for
/// that job are now terminal and update the parent `patch_jobs` row accordingly.
///
/// If the parent job transitions to a terminal status, also fires a `job_update`
/// pg_notify with `event_type: "job"` so the frontend can update the job row.
async fn update_parent_job_status(pool: &PgPool, job_id: Uuid) {
    // Count hosts that are still in a non-terminal state.
    let pending: i64 = match sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM patch_job_hosts
        WHERE job_id = $1
          AND status NOT IN (
              'succeeded'::job_status,
              'failed'::job_status,
              'cancelled'::job_status
          )
        "#,
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, %job_id, "update_parent_job_status: count query failed");
            return;
        },
    };

    if pending > 0 {
        return; // still hosts running — parent stays running
    }

    // All hosts terminal — determine final parent status and counts.
    #[derive(sqlx::FromRow)]
    struct RollupCounts {
        total: i64,
        succeeded: i64,
        failed: i64,
    }

    let counts: RollupCounts = match sqlx::query_as(
        r#"
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'succeeded') AS succeeded,
            COUNT(*) FILTER (WHERE status = 'failed') AS failed
        FROM patch_job_hosts
        WHERE job_id = $1
        "#,
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, %job_id, "update_parent_job_status: rollup query failed");
            return;
        },
    };

    let final_status = if counts.failed > 0 {
        "failed"
    } else {
        "succeeded"
    };

    if let Err(e) = sqlx::query(
        "UPDATE patch_jobs SET status = $1::job_status, completed_at = NOW() WHERE id = $2",
    )
    .bind(final_status)
    .bind(job_id)
    .execute(pool)
    .await
    {
        tracing::error!(
            error  = %e,
            %job_id,
            status = %final_status,
            "update_parent_job_status: UPDATE failed"
        );
        return;
    }

    tracing::info!(
        %job_id,
        status = %final_status,
        "Parent job status updated"
    );

    // Fire job-level pg_notify so the frontend can update the job row.
    let payload = NotifyPayload {
        event_type: "job".to_string(),
        job_id: job_id.to_string(),
        host_id: String::new(), // no specific host for job-level events
        status: final_status.to_string(),
        output: None,
        error_message: None,
        agent_job_id: String::new(),
        succeeded_count: Some(counts.succeeded),
        failed_count: Some(counts.failed),
        host_count: Some(counts.total),
    };

    let payload_json = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, %job_id, "update_parent_job_status: failed to serialize job-level notify payload");
            return;
        },
    };

    if let Err(e) = sqlx::query("SELECT pg_notify('job_update', $1)")
        .bind(&payload_json)
        .execute(pool)
        .await
    {
        tracing::error!(
            error  = %e,
            %job_id,
            "update_parent_job_status: job-level pg_notify failed"
        );
    } else {
        tracing::info!(
            %job_id,
            status = %final_status,
            "Job-level pg_notify sent"
        );
    }
}
