//! Job execution engine.
//!
//! Picks up patch jobs from the database, dispatches them to agents via mTLS,
//! tracks progress, and handles retries with exponential back-off.
//!
//! Two concurrent loops run inside [`run_job_executor`]:
//!
//! 1. **NOTIFY listener** — listens on `job_enqueued`; triggers immediate
//!    dispatch for newly-enqueued jobs.
//! 2. **Periodic scanner** — every 60 seconds:
//!    - picks up queued non-immediate jobs that were missed by NOTIFY,
//!    - polls running agent jobs for completion,
//!    - retries pending host jobs whose back-off window has elapsed.

use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use pm_agent_client::{types::ApplyPatchesRequest, AgentClient};
use pm_core::config::AppConfig;
use sqlx::{FromRow, PgPool};
use tokio::{sync::Semaphore, time};
use uuid::Uuid;

use crate::agent_loader::load_agent_certs;
use crate::email;

// ─────────────────────────────────────────────────────────────────────────────
// Internal DB row types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, FromRow)]
#[allow(dead_code)]
struct PatchJobHostQueued {
    id: Uuid,
    host_id: Uuid,
    job_id: Uuid,
}

#[derive(Debug, FromRow)]
struct PatchJobHostRunning {
    id: Uuid,
    agent_job_id: String,
    job_id: Uuid,
    ip_address: String,
    agent_port: i32,
}

#[derive(Debug, FromRow)]
struct PatchJobHostPending {
    id: Uuid,
    host_id: Uuid,
    job_id: Uuid,
}

#[derive(Debug, FromRow)]
struct HostRow {
    ip_address: String,
    agent_port: i32,
}

#[derive(Debug, FromRow)]
struct JobPatchSelection {
    patch_selection: serde_json::Value,
}

#[derive(Debug, FromRow)]
struct RetryRow {
    job_id: Uuid,
    retry_count: i32,
}

#[derive(Debug, FromRow)]
struct StatusCounts {
    running_count: i64,
    pending_count: i64,
    queued_count: i64,
    succeeded_count: i64,
    failed_count: i64,
    cancelled_count: i64,
    total_count: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the job executor and run it indefinitely.
///
/// Runs two independent tasks joined until both complete (they never do under
/// normal operation):
/// - NOTIFY-driven immediate dispatch (auto-reconnect on DB disconnect).
/// - 60-second periodic scanner for queued / running / pending rows.
pub async fn run_job_executor(pool: PgPool, config: Arc<AppConfig>) {
    tracing::info!("Job executor started");

    let (pool_n, cfg_n) = (pool.clone(), config.clone());
    let (pool_s, cfg_s) = (pool.clone(), config.clone());

    let notify_task = tokio::spawn(async move {
        run_notify_listener(pool_n, cfg_n).await;
    });
    let scan_task = tokio::spawn(async move {
        run_periodic_scanner(pool_s, cfg_s).await;
    });

    let _ = tokio::join!(notify_task, scan_task);
}

// ─────────────────────────────────────────────────────────────────────────────
// NOTIFY listener (outer reconnect wrapper)
// ─────────────────────────────────────────────────────────────────────────────

async fn run_notify_listener(pool: PgPool, config: Arc<AppConfig>) {
    tracing::info!("Job executor NOTIFY listener starting");
    loop {
        if let Err(e) = notify_listen_loop(&pool, &config).await {
            tracing::error!(
                error = %e,
                "Job executor NOTIFY listener disconnected, reconnecting in 5s"
            );
            time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

/// Inner NOTIFY loop — returns `Err` only on a fatal connection error so the
/// outer loop can reconnect.
async fn notify_listen_loop(pool: &PgPool, config: &Arc<AppConfig>) -> anyhow::Result<()> {
    let mut listener = sqlx::postgres::PgListener::connect(&config.database.url).await?;
    listener.listen("job_enqueued").await?;
    tracing::debug!("Job executor NOTIFY listener connected");

    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload().to_string();
        tracing::info!(payload, "job_enqueued notification received");

        let job_id = match payload.parse::<Uuid>() {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    payload,
                    error = %e,
                    "Job executor: invalid UUID in job_enqueued payload"
                );
                continue;
            },
        };

        let (p, c) = (pool.clone(), config.clone());
        tokio::spawn(async move {
            process_job(p, c, job_id).await;
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Periodic scanner
// ─────────────────────────────────────────────────────────────────────────────

async fn run_periodic_scanner(pool: PgPool, config: Arc<AppConfig>) {
    // First tick fires immediately — consume it to avoid a duplicate burst
    // right after NOTIFY already dispatched the same jobs.
    let mut ticker = time::interval(std::time::Duration::from_secs(60));
    ticker.tick().await;

    loop {
        ticker.tick().await;
        tracing::debug!("Job executor periodic scan starting");

        // 1. Pick up queued pjh rows that belong to non-cancelled jobs.
        scan_queued_jobs(pool.clone(), config.clone()).await;

        // 2. Poll running pjh rows against the agent.
        poll_running_jobs(pool.clone(), config.clone()).await;

        // 3. Retry pending pjh rows whose back-off window has elapsed.
        retry_pending_jobs(pool.clone(), config.clone()).await;

        tracing::debug!("Job executor periodic scan complete");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// scan_queued_jobs — feeds non-immediate jobs into process_job
// ─────────────────────────────────────────────────────────────────────────────

/// Discover distinct job-IDs that have queued host entries ready for dispatch
/// and call [`process_job`] for each.
async fn scan_queued_jobs(pool: PgPool, config: Arc<AppConfig>) {
    #[derive(FromRow)]
    struct JobIdRow {
        job_id: Uuid,
    }

    let rows: Vec<JobIdRow> = match sqlx::query_as(
        r#"
        SELECT DISTINCT pjh.job_id
        FROM   patch_job_hosts pjh
        JOIN   patch_jobs j ON j.id = pjh.job_id
        WHERE  pjh.status = 'queued'
          AND  (pjh.retry_next_at IS NULL OR pjh.retry_next_at <= NOW())
          AND  j.status != 'cancelled'
          AND  (
            -- Immediate jobs always dispatch
            j.immediate = TRUE
            OR
            -- Non-immediate jobs only dispatch when the host has an open window
            EXISTS (
              SELECT 1 FROM maintenance_windows mw
              WHERE mw.host_id = pjh.host_id
                AND mw.enabled = TRUE
                AND (
                  (mw.recurrence = 'once'
                   AND mw.start_at <= NOW()
                   AND NOW() < mw.start_at + (mw.duration_minutes * INTERVAL '1 minute'))
                  OR
                  (mw.recurrence = 'daily'
                   AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
                   AND (NOW() AT TIME ZONE 'UTC')::time < ((mw.start_at AT TIME ZONE 'UTC')::time
                                                           + (mw.duration_minutes * INTERVAL '1 minute')))
                  OR
                  (mw.recurrence = 'weekly'
                   AND EXTRACT(DOW FROM NOW() AT TIME ZONE 'UTC') = mw.recurrence_day
                   AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
                   AND (NOW() AT TIME ZONE 'UTC')::time < ((mw.start_at AT TIME ZONE 'UTC')::time
                                                           + (mw.duration_minutes * INTERVAL '1 minute')))
                  OR
                  (mw.recurrence = 'monthly'
                   AND EXTRACT(DAY FROM NOW() AT TIME ZONE 'UTC') = mw.recurrence_day
                   AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
                   AND (NOW() AT TIME ZONE 'UTC')::time < ((mw.start_at AT TIME ZONE 'UTC')::time
                                                           + (mw.duration_minutes * INTERVAL '1 minute')))
                )
            )
          )
        "#,
    )
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "scan_queued_jobs: DB query failed");
            return;
        }
    };

    for row in rows {
        let (p, c) = (pool.clone(), config.clone());
        tokio::spawn(async move {
            process_job(p, c, row.job_id).await;
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// process_job
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch all queued host entries for `job_id` and dispatch them concurrently,
/// bounded by `config.worker.max_concurrent_agent_calls`.
pub async fn process_job(pool: PgPool, config: Arc<AppConfig>, job_id: Uuid) {
    tracing::info!(%job_id, "process_job: dispatching queued hosts");

    // Mark the parent job as running (idempotent guard).
    if let Err(e) = sqlx::query(
        r#"
        UPDATE patch_jobs
        SET    status     = 'running',
               started_at = COALESCE(started_at, NOW())
        WHERE  id     = $1
          AND  status NOT IN ('running','succeeded','failed','cancelled')
        "#,
    )
    .bind(job_id)
    .execute(&pool)
    .await
    {
        tracing::error!(%job_id, error = %e, "process_job: failed to mark job running");
    }

    // Fetch all queued host entries for this job.
    let hosts: Vec<PatchJobHostQueued> = match sqlx::query_as(
        r#"
        SELECT id, host_id, job_id
        FROM   patch_job_hosts
        WHERE  job_id = $1
          AND  status = 'queued'
        "#,
    )
    .bind(job_id)
    .fetch_all(&pool)
    .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(%job_id, error = %e, "process_job: failed to fetch queued hosts");
            return;
        },
    };

    if hosts.is_empty() {
        tracing::debug!(%job_id, "process_job: no queued hosts found (already dispatched)");
        return;
    }

    let sem = Arc::new(Semaphore::new(config.worker.max_concurrent_agent_calls));

    for host in hosts {
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(%job_id, error = %e, "process_job: semaphore closed");
                break;
            },
        };

        let (p, c) = (pool.clone(), config.clone());
        let pjh_id = host.id;
        let host_id = host.host_id;

        tokio::spawn(async move {
            execute_host_job(p, c, job_id, host_id, pjh_id).await;
            drop(permit);
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execute_host_job
// ─────────────────────────────────────────────────────────────────────────────

/// Connect to a single host agent, submit the patch job, and record the
/// agent-assigned async job ID for later polling.
async fn execute_host_job(
    pool: PgPool,
    config: Arc<AppConfig>,
    job_id: Uuid,
    host_id: Uuid,
    pjh_id: Uuid,
) {
    tracing::info!(%job_id, %host_id, %pjh_id, "execute_host_job: starting");

    // ── 1. Fetch host connection details ─────────────────────────────────────
    let host: HostRow = match sqlx::query_as(
        "SELECT host(ip_address)::text AS ip_address, agent_port FROM hosts WHERE id = $1",
    )
    .bind(host_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::error!(%host_id, "execute_host_job: host not found");
            handle_host_failure(
                pool,
                pjh_id,
                format!("Host {host_id} not found in database"),
            )
            .await;
            return;
        },
        Err(e) => {
            tracing::error!(%host_id, error = %e, "execute_host_job: DB error fetching host");
            handle_host_failure(pool, pjh_id, format!("DB error fetching host: {e}")).await;
            return;
        },
    };

    // ── 2. Fetch the job's patch_selection ──────────────────────────────────
    let patch_sel: JobPatchSelection =
        match sqlx::query_as("SELECT patch_selection FROM patch_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_optional(&pool)
            .await
        {
            Ok(Some(row)) => row,
            Ok(None) => {
                tracing::error!(%job_id, "execute_host_job: parent job not found");
                handle_host_failure(pool, pjh_id, format!("Parent job {job_id} not found")).await;
                return;
            },
            Err(e) => {
                tracing::error!(%job_id, error = %e, "execute_host_job: DB error fetching job");
                handle_host_failure(pool, pjh_id, format!("DB error fetching job: {e}")).await;
                return;
            },
        };

    let packages: Vec<String> =
        serde_json::from_value(patch_sel.patch_selection).unwrap_or_default();

    // ── 3. Load mTLS certs ───────────────────────────────────────────────────
    let certs = match load_agent_certs(&config.security) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%host_id, error = %e, "execute_host_job: failed to load agent certs");
            handle_host_failure(pool, pjh_id, format!("Failed to load agent certs: {e}")).await;
            return;
        },
    };

    // ── 4. Build AgentClient ─────────────────────────────────────────────────
    let client = match AgentClient::new(
        &host.ip_address,
        host.agent_port as u16,
        &certs.client_cert,
        &certs.client_key,
        &certs.ca_cert,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%host_id, error = %e, "execute_host_job: failed to build AgentClient");
            handle_host_failure(pool, pjh_id, format!("Failed to build agent client: {e}")).await;
            return;
        },
    };

    // ── 5. Mark pjh as running ───────────────────────────────────────────────
    if let Err(e) = sqlx::query(
        r#"
        UPDATE patch_job_hosts
        SET    status     = 'running',
               started_at = COALESCE(started_at, NOW())
        WHERE  id = $1
        "#,
    )
    .bind(pjh_id)
    .execute(&pool)
    .await
    {
        tracing::error!(%pjh_id, error = %e, "execute_host_job: failed to mark pjh running");
    }

    // ── 6. Submit the patch job to the agent ─────────────────────────────────
    let req = ApplyPatchesRequest {
        packages,
        allow_reboot: true,
    };

    match client.apply_patches(&req).await {
        Ok(resp) => {
            tracing::info!(
                %pjh_id,
                agent_job_id = %resp.job_id,
                "execute_host_job: agent accepted job"
            );

            // ── 7. Store agent_job_id; status stays 'running' (agent is async) ──
            if let Err(e) =
                sqlx::query("UPDATE patch_job_hosts SET agent_job_id = $1 WHERE id = $2")
                    .bind(&resp.job_id)
                    .bind(pjh_id)
                    .execute(&pool)
                    .await
            {
                tracing::error!(
                    %pjh_id,
                    error = %e,
                    "execute_host_job: failed to store agent_job_id"
                );
            }
        },
        Err(e) => {
            tracing::warn!(%pjh_id, error = %e, "execute_host_job: agent rejected job");
            handle_host_failure(pool, pjh_id, format!("Agent error: {e}")).await;
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// poll_running_jobs
// ─────────────────────────────────────────────────────────────────────────────

/// Poll all running pjh rows that have an agent job ID and update their status.
pub async fn poll_running_jobs(pool: PgPool, config: Arc<AppConfig>) {
    let rows: Vec<PatchJobHostRunning> = match sqlx::query_as(
        r#"
        SELECT pjh.id,
               pjh.agent_job_id,
               pjh.job_id,
               host(h.ip_address)::text AS ip_address,
               h.agent_port
        FROM   patch_job_hosts pjh
        JOIN   hosts h ON h.id = pjh.host_id
        WHERE  pjh.status       = 'running'
          AND  pjh.agent_job_id IS NOT NULL
        "#,
    )
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "poll_running_jobs: DB query failed");
            return;
        },
    };

    for row in rows {
        let (p, c) = (pool.clone(), config.clone());
        tokio::spawn(async move {
            poll_single_host(p, c, row).await;
        });
    }
}

/// Poll one running host entry and update its status from the agent response.
async fn poll_single_host(pool: PgPool, config: Arc<AppConfig>, row: PatchJobHostRunning) {
    let certs = match load_agent_certs(&config.security) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                pjh_id = %row.id,
                error = %e,
                "poll_single_host: failed to load agent certs"
            );
            return;
        },
    };

    let client = match AgentClient::new(
        &row.ip_address,
        row.agent_port as u16,
        &certs.client_cert,
        &certs.client_key,
        &certs.ca_cert,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                pjh_id = %row.id,
                error = %e,
                "poll_single_host: failed to build AgentClient"
            );
            return;
        },
    };

    let status = match client.job_status(&row.agent_job_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                pjh_id = %row.id,
                agent_job_id = %row.agent_job_id,
                error = %e,
                "poll_single_host: agent status call failed"
            );
            return;
        },
    };

    match status.status.as_str() {
        "succeeded" | "completed" => {
            tracing::info!(pjh_id = %row.id, "poll_single_host: agent job succeeded");
            if let Err(e) = sqlx::query(
                r#"
                UPDATE patch_job_hosts
                SET    status       = 'succeeded',
                       completed_at = NOW(),
                       output       = $2
                WHERE  id = $1
                "#,
            )
            .bind(row.id)
            .bind(status.output.as_deref())
            .execute(&pool)
            .await
            {
                tracing::error!(pjh_id = %row.id, error = %e, "poll_single_host: update failed");
            }
            sync_job_status(&pool, row.job_id).await;
        },
        "failed" => {
            tracing::warn!(pjh_id = %row.id, "poll_single_host: agent job failed");
            let err_msg = status
                .error
                .unwrap_or_else(|| "Agent reported failure (no detail)".to_string());
            handle_host_failure(pool, row.id, err_msg).await;
        },
        "running" | "queued" => {
            // Still in progress — nothing to update; will poll again next cycle.
            tracing::debug!(
                pjh_id = %row.id,
                agent_status = %status.status,
                "poll_single_host: job still in progress"
            );
        },
        "cancelled" => {
            tracing::info!(pjh_id = %row.id, "poll_single_host: agent job cancelled");
            let err_msg = status
                .error
                .unwrap_or_else(|| "Agent job was cancelled".to_string());
            handle_host_failure(pool, row.id, err_msg).await;
        },
        other => {
            tracing::warn!(
                pjh_id = %row.id,
                agent_status = %other,
                "poll_single_host: unexpected agent status — ignoring"
            );
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// handle_host_failure
// ─────────────────────────────────────────────────────────────────────────────

/// Apply exponential back-off retry logic to a failed host job entry.
///
/// Retries up to 3 times (1 min / 5 min / 30 min delays).  After the third
/// failure the entry is marked `failed` and the parent job status is synced.
async fn handle_host_failure(pool: PgPool, pjh_id: Uuid, error_msg: String) {
    let row: Option<RetryRow> = match sqlx::query_as(
        "SELECT job_id, retry_count FROM patch_job_hosts WHERE id = $1",
    )
    .bind(pjh_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(%pjh_id, error = %e, "handle_host_failure: DB error fetching retry row");
            return;
        },
    };

    let row = match row {
        Some(r) => r,
        None => {
            tracing::error!(%pjh_id, "handle_host_failure: pjh row not found");
            return;
        },
    };

    if row.retry_count < 3 {
        let new_retry_count = row.retry_count + 1;
        let retry_next_at = Utc::now()
            + match new_retry_count {
                1 => ChronoDuration::minutes(1),
                2 => ChronoDuration::minutes(5),
                _ => ChronoDuration::minutes(30),
            };

        tracing::warn!(
            %pjh_id,
            retry_count = new_retry_count,
            ?retry_next_at,
            error = %error_msg,
            "handle_host_failure: scheduling retry"
        );

        if let Err(e) = sqlx::query(
            r#"
            UPDATE patch_job_hosts
            SET    status        = 'pending',
                   retry_count   = $2,
                   retry_next_at = $3,
                   last_error    = $4
            WHERE  id = $1
            "#,
        )
        .bind(pjh_id)
        .bind(new_retry_count)
        .bind(retry_next_at)
        .bind(&error_msg)
        .execute(&pool)
        .await
        {
            tracing::error!(%pjh_id, error = %e, "handle_host_failure: failed to set pending");
        }
    } else {
        tracing::warn!(
            %pjh_id,
            retry_count = row.retry_count,
            error = %error_msg,
            "handle_host_failure: max retries exceeded, marking failed"
        );

        if let Err(e) = sqlx::query(
            r#"
            UPDATE patch_job_hosts
            SET    status        = 'failed',
                   error_message = $2,
                   completed_at  = NOW()
            WHERE  id = $1
            "#,
        )
        .bind(pjh_id)
        .bind(&error_msg)
        .execute(&pool)
        .await
        {
            tracing::error!(%pjh_id, error = %e, "handle_host_failure: failed to mark pjh failed");
        }

        sync_job_status(&pool, row.job_id).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// sync_job_status
// ─────────────────────────────────────────────────────────────────────────────

/// Roll up `patch_job_hosts` aggregate status into the parent `patch_jobs` row.
///
/// Logic (in priority order):
/// 1. Any `running` or `pending` hosts → keep parent `running`.
/// 2. All hosts `succeeded` → parent `succeeded`.
/// 3. All hosts `cancelled` → parent `cancelled`.
/// 4. Any `failed` with none still active → parent `failed` (includes partial).
///
/// After rolling up, sends email notifications for completed/failed jobs.
async fn sync_job_status(pool: &PgPool, job_id: Uuid) {
    let counts: StatusCounts = match sqlx::query_as(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE status = 'running')   AS running_count,
            COUNT(*) FILTER (WHERE status = 'pending')   AS pending_count,
            COUNT(*) FILTER (WHERE status = 'queued')    AS queued_count,
            COUNT(*) FILTER (WHERE status = 'succeeded') AS succeeded_count,
            COUNT(*) FILTER (WHERE status = 'failed')    AS failed_count,
            COUNT(*) FILTER (WHERE status = 'cancelled') AS cancelled_count,
            COUNT(*)                                     AS total_count
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
            tracing::error!(%job_id, error = %e, "sync_job_status: DB query failed");
            return;
        },
    };

    // Determine the aggregate status.
    let new_status: &str;
    let set_completed: bool;

    if counts.running_count > 0 || counts.pending_count > 0 || counts.queued_count > 0 {
        // Still work in flight — keep parent running.
        new_status = "running";
        set_completed = false;
    } else if counts.total_count > 0 && counts.succeeded_count == counts.total_count {
        // Every host succeeded.
        new_status = "succeeded";
        set_completed = true;
    } else if counts.total_count > 0 && counts.cancelled_count == counts.total_count {
        // Every host cancelled.
        new_status = "cancelled";
        set_completed = true;
    } else if counts.failed_count > 0 {
        // At least one failure and nothing still active → failed (partial counts too).
        new_status = "failed";
        set_completed = true;
    } else {
        // Fallback: nothing actionable yet.
        return;
    }

    tracing::info!(
        %job_id,
        new_status,
        running  = counts.running_count,
        pending  = counts.pending_count,
        queued   = counts.queued_count,
        succeeded = counts.succeeded_count,
        failed   = counts.failed_count,
        "sync_job_status: updating parent job"
    );

    let result = if set_completed {
        sqlx::query(
            r#"
            UPDATE patch_jobs
            SET    status       = $2,
                   completed_at = COALESCE(completed_at, NOW())
            WHERE  id = $1
            "#,
        )
        .bind(job_id)
        .bind(new_status)
        .execute(pool)
        .await
    } else {
        sqlx::query("UPDATE patch_jobs SET status = $2 WHERE id = $1")
            .bind(job_id)
            .bind(new_status)
            .execute(pool)
            .await
    };

    if let Err(e) = result {
        tracing::error!(%job_id, error = %e, "sync_job_status: failed to update parent job");
    }

    // Send email notifications for completed/failed jobs
    if set_completed {
        // Spawn email notification in background — non-blocking
        let pool_clone = pool.clone();
        let job_id_str = job_id.to_string();
        let total = counts.total_count;
        let succeeded = counts.succeeded_count;
        let failed = counts.failed_count;

        tokio::spawn(async move {
            email::send_job_completion_email(&pool_clone, &job_id_str, total, succeeded, failed)
                .await;

            // If there are failures, also send failure emails per host
            if failed > 0 {
                let failed_hosts: Vec<(String, String)> = match sqlx::query_as(
                    r#"
                    SELECT h.fqdn, COALESCE(pjh.error_message, 'Unknown error')
                    FROM patch_job_hosts pjh
                    JOIN hosts h ON h.id = pjh.host_id
                    WHERE pjh.job_id = $1 AND pjh.status = 'failed'
                    "#,
                )
                .bind(job_id)
                .fetch_all(&pool_clone)
                .await
                {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!(%job_id, error = %e, "sync_job_status: failed to fetch failed hosts for email");
                        Vec::new()
                    },
                };

                for (fqdn, error_msg) in failed_hosts {
                    email::send_patch_failure_email(&pool_clone, &fqdn, &job_id_str, &error_msg)
                        .await;
                }
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// retry_pending_jobs
// ─────────────────────────────────────────────────────────────────────────────

/// Find pending host entries whose back-off window has elapsed, reset them to
/// `queued`, and dispatch them immediately.
pub async fn retry_pending_jobs(pool: PgPool, config: Arc<AppConfig>) {
    let rows: Vec<PatchJobHostPending> = match sqlx::query_as(
        r#"
        SELECT pjh.id, pjh.host_id, pjh.job_id
        FROM   patch_job_hosts pjh
        JOIN   patch_jobs j ON j.id = pjh.job_id
        WHERE  pjh.status        = 'pending'
          AND  pjh.retry_next_at <= NOW()
          AND  j.status         != 'cancelled'
        "#,
    )
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "retry_pending_jobs: DB query failed");
            return;
        },
    };

    for row in rows {
        // Reset to queued so execute_host_job can pick it up cleanly.
        if let Err(e) = sqlx::query(
            "UPDATE patch_job_hosts SET status = 'queued', retry_next_at = NULL WHERE id = $1",
        )
        .bind(row.id)
        .execute(&pool)
        .await
        {
            tracing::error!(
                pjh_id = %row.id,
                error = %e,
                "retry_pending_jobs: failed to reset pjh to queued"
            );
            continue;
        }

        tracing::info!(
            pjh_id = %row.id,
            job_id = %row.job_id,
            "retry_pending_jobs: re-dispatching host job"
        );

        let (p, c) = (pool.clone(), config.clone());
        let (job_id, host_id, pjh_id) = (row.job_id, row.host_id, row.id);
        tokio::spawn(async move {
            execute_host_job(p, c, job_id, host_id, pjh_id).await;
        });
    }
}
