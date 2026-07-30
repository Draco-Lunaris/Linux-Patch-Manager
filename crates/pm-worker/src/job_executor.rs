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
use pm_agent_client::{
    types::{ApplyPatchesRequest, RebootRequest},
    AgentClient, AgentClientError,
};
use pm_core::config::AppConfig;
use pm_core::models::JobKind;
use serde_json::json;
use sqlx::{FromRow, PgPool};
use tokio::{sync::Semaphore, time};
use uuid::Uuid;

use crate::agent_loader::load_agent_certs;
use crate::email;
use crate::health_check_poller::check_host_health_checks;

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
    host_id: Uuid,
    ip_address: String,
    agent_port: i32,
    job_kind: JobKind,
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
struct JobInfo {
    kind: JobKind,
    patch_selection: serde_json::Value,
    #[sqlx(default)]
    allow_reboot: bool,
    #[sqlx(default)]
    reboot_delay_seconds: i64,
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
    waiting_health_check_count: i64,
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

        // 4. Fail running pjh rows that have exceeded the job timeout.
        fail_timed_out_jobs(pool.clone(), config.clone()).await;

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

    // ── 1b. Health check gate ──────────────────────────────────────────────
    // All enabled health checks for this host must be healthy before we proceed.
    match check_host_health_checks(&pool, host_id).await {
        Ok(true) => {
            tracing::debug!(%host_id, "execute_host_job: health checks passed");
        },
        Ok(false) => {
            tracing::info!(%host_id, %pjh_id, "execute_host_job: health checks not passed, setting waiting_health_check");
            // Check if the maintenance window is still open for this host.
            let window_open: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM maintenance_windows mw
                    WHERE mw.host_id = $1
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
                "#,
            )
            .bind(host_id)
            .fetch_optional(&pool)
            .await
            .unwrap_or(Some(true))
            .unwrap_or(true); // Default to true if no window configured

            if !window_open {
                tracing::warn!(%host_id, %pjh_id, "execute_host_job: health checks not passed and maintenance window closed");
                handle_host_failure(
                    pool,
                    pjh_id,
                    "Health checks did not pass before maintenance window closed".to_string(),
                )
                .await;
                return;
            }

            // Set status to waiting_health_check and retry in 5 minutes.
            let retry_at = Utc::now() + ChronoDuration::minutes(5);
            if let Err(e) = sqlx::query(
                r#"
                UPDATE patch_job_hosts
                SET    status        = 'waiting_health_check',
                       retry_next_at = $2,
                       last_error    = 'Waiting for health checks to pass'
                WHERE  id = $1
                "#,
            )
            .bind(pjh_id)
            .bind(retry_at)
            .execute(&pool)
            .await
            {
                tracing::error!(%pjh_id, error = %e, "execute_host_job: failed to set waiting_health_check status");
            }
            return;
        },
        Err(e) => {
            tracing::warn!(%host_id, error = %e, "execute_host_job: health check query failed, proceeding anyway");
            // If we can't query health checks, proceed with the job rather than blocking.
        },
    }

    // ── 2. Fetch the job's kind and patch_selection ──────────────────────────
    let job_info: JobInfo = match sqlx::query_as(
        "SELECT kind, patch_selection, allow_reboot, reboot_delay_seconds FROM patch_jobs WHERE id = $1",
    )
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

    // ── 6. Dispatch by job kind ─────────────────────────────────────────────
    match job_info.kind {
        JobKind::SelfUpgrade => {
            execute_self_upgrade_host_job(
                pool,
                config,
                pjh_id,
                host_id,
                &client,
                &job_info.patch_selection,
            )
            .await;
        },
        JobKind::Reboot => {
            execute_reboot_host_job(pool, pjh_id, host_id, &client).await;
        },
        _ => {
            // PatchApply, PatchRemove, Rollback — use the existing
            // patch-apply path (agent dispatches by kind internally).
            execute_patch_host_job(
                pool,
                config,
                pjh_id,
                host_id,
                &client,
                &job_info.patch_selection,
                job_info.allow_reboot,
                job_info.reboot_delay_seconds as u64,
            )
            .await;
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execute_patch_host_job — existing patch-apply path (all non-self-upgrade kinds)
// ─────────────────────────────────────────────────────────────────────────────

async fn execute_patch_host_job(
    pool: PgPool,
    _config: Arc<AppConfig>,
    pjh_id: Uuid,
    host_id: Uuid,
    client: &AgentClient,
    patch_selection: &serde_json::Value,
    allow_reboot: bool,
    reboot_delay_seconds: u64,
) {
    let mut packages: Vec<String> =
        serde_json::from_value(patch_selection.clone()).unwrap_or_default();

    // Per SPEC: "empty = all available patches".  The agent treats an empty
    // list as "apply nothing", so we must expand it here.
    if packages.is_empty() {
        match sqlx::query_scalar::<_, serde_json::Value>(
            r#"
            SELECT available_patches
            FROM   host_patch_data
            WHERE  host_id = $1
            ORDER  BY polled_at DESC
            LIMIT  1
            "#,
        )
        .bind(host_id)
        .fetch_optional(&pool)
        .await
        {
            Ok(Some(val)) => {
                if let Ok(patches) = serde_json::from_value::<Vec<serde_json::Value>>(val) {
                    for p in &patches {
                        if let Some(name) = p.get("name").and_then(|n| n.as_str()) {
                            packages.push(name.to_string());
                        }
                    }
                    tracing::info!(
                        %pjh_id,
                        count = packages.len(),
                        "execute_patch_host_job: expanded empty packages to all available patches"
                    );
                }
            },
            Ok(None) => {
                tracing::warn!(%pjh_id, "execute_patch_host_job: no patch data for host, sending empty packages");
            },
            Err(e) => {
                tracing::error!(%pjh_id, error = %e, "execute_patch_host_job: failed to fetch patch data for expansion");
            },
        }
    }

    let req = ApplyPatchesRequest {
        packages,
        allow_reboot,
        reboot_delay_seconds,
    };

    match client.apply_patches(&req).await {
        Ok(resp) => {
            tracing::info!(
                %pjh_id,
                agent_job_id = %resp.job_id,
                "execute_patch_host_job: agent accepted job"
            );
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
                    "execute_patch_host_job: failed to store agent_job_id"
                );
            }
        },
        Err(e) => {
            tracing::warn!(%pjh_id, error = %e, "execute_patch_host_job: agent rejected job");
            handle_host_failure(pool, pjh_id, format!("Agent error: {e}")).await;
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execute_reboot_host_job — explicit reboot dispatch
// ─────────────────────────────────────────────────────────────────────────────

async fn execute_reboot_host_job(pool: PgPool, pjh_id: Uuid, host_id: Uuid, client: &AgentClient) {
    tracing::info!(%pjh_id, %host_id, "execute_reboot_host_job: triggering reboot");

    let req = RebootRequest {
        delay_seconds: 0,
        force: false,
    };

    match client.reboot(&req).await {
        Ok(resp) => {
            tracing::info!(
                %pjh_id,
                %host_id,
                agent_job_id = %resp.job_id,
                "execute_reboot_host_job: agent accepted reboot job"
            );
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
                    "execute_reboot_host_job: failed to store agent_job_id"
                );
            }
        },
        Err(e) => {
            tracing::warn!(%pjh_id, %host_id, error = %e, "execute_reboot_host_job: agent rejected reboot");
            handle_host_failure(pool, pjh_id, format!("Agent error: {e}")).await;
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execute_self_upgrade_host_job — self-upgrade dispatch
// ─────────────────────────────────────────────────────────────────────────────

async fn execute_self_upgrade_host_job(
    pool: PgPool,
    _config: Arc<AppConfig>,
    pjh_id: Uuid,
    host_id: Uuid,
    client: &AgentClient,
    _patch_selection: &serde_json::Value,
) {
    tracing::info!(
        %pjh_id,
        %host_id,
        "execute_self_upgrade_host_job: triggering standard package update for linux-patch-api"
    );

    match client.update_package("linux-patch-api").await {
        Ok(resp) => {
            tracing::info!(
                %pjh_id,
                agent_job_id = %resp.job_id,
                "execute_self_upgrade_host_job: agent accepted package update"
            );
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
                    "execute_self_upgrade_host_job: failed to store agent_job_id"
                );
            }
        },
        Err(e) => {
            tracing::warn!(
                %pjh_id,
                error = %e,
                "execute_self_upgrade_host_job: agent rejected self-upgrade"
            );
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
               pjh.host_id,
               host(h.ip_address)::text AS ip_address,
               h.agent_port,
               j.kind AS job_kind
        FROM   patch_job_hosts pjh
        JOIN   hosts h ON h.id = pjh.host_id
        JOIN   patch_jobs j ON j.id = pjh.job_id
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
///
/// For `SelfUpgrade` jobs, a dropped connection is the *expected* success path —
/// the agent restarts mid-job.  Instead of treating a connection failure as an
/// error, we enter reconnect-confirm mode: wait for the agent to come back online,
/// then verify the new version matches the target.
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

    // ── SelfUpgrade fast-path: try job_status first ──────────────────────────
    let status_result = client.job_status(&row.agent_job_id).await;

    match row.job_kind {
        JobKind::SelfUpgrade => {
            poll_self_upgrade_host(&pool, &config, &row, &client, status_result).await;
        },
        _ => {
            // Standard (non-self-upgrade) poll path.
            let status = match status_result {
                Ok(s) => s,
                Err(e) => {
                    // Check if this is a JOB_NOT_FOUND error — the agent lost
                    // the job (e.g. after a reboot). This is a terminal failure,
                    // not a transient error. The job will never complete.
                    if let pm_agent_client::AgentClientError::ApiError { code, message } = &e {
                        if code == "JOB_NOT_FOUND" {
                            tracing::warn!(
                                pjh_id = %row.id,
                                agent_job_id = %row.agent_job_id,
                                "poll_single_host: agent reports JOB_NOT_FOUND — agent likely rebooted and lost in-memory job state"
                            );
                            handle_host_failure(
                                pool,
                                row.id,
                                format!(
                                    "Agent reports job not found (agent may have rebooted): {message}"
                                ),
                            )
                            .await;
                            return;
                        }
                    }

                    // For timeout errors, check if the job has exceeded the
                    // maximum running duration. If so, fail it. Otherwise,
                    // log and wait for the next poll cycle.
                    if matches!(e, pm_agent_client::AgentClientError::Timeout) {
                        tracing::debug!(
                            pjh_id = %row.id,
                            agent_job_id = %row.agent_job_id,
                            "poll_single_host: agent status call timed out (transient)"
                        );
                    } else {
                        tracing::warn!(
                            pjh_id = %row.id,
                            agent_job_id = %row.agent_job_id,
                            error = %e,
                            "poll_single_host: agent status call failed"
                        );
                    }
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
                    .bind(status.output.as_deref().unwrap_or(""))
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
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-upgrade reconciliation — pure decision functions
// ─────────────────────────────────────────────────────────────────────────────

/// Decision returned by [`decide_self_upgrade_poll_action`].
///
/// Captures the decision logic for self-upgrade host polling, independent of
/// database or network I/O. The caller is responsible for executing the
/// side-effects (DB updates, health checks, reconnect confirmation).
#[derive(Debug, PartialEq, Eq)]
enum SelfUpgradePollAction {
    /// Agent reported success — call `health()` to get the new version.
    Succeeded,
    /// Agent reported failure — enter reconnect-confirm (may have restarted).
    FailedThenReconnectConfirm,
    /// Job still in progress — keep polling.
    StillInProgress,
    /// Unexpected status string — log and ignore.
    UnexpectedStatus,
    /// Connection dropped (expected during self-upgrade) — enter reconnect-confirm.
    ConnectionDropped,
}

/// Pure decision function: given the result of polling a self-upgrade host's
/// `job_status()`, determine what action to take.
///
/// **Key invariant:** a dropped connection (`Err`) is NEVER mapped to a
/// failure — it always enters reconnect-confirm mode, because the agent is
/// expected to restart mid-job during a self-upgrade.
fn decide_self_upgrade_poll_action(
    status_result: Result<&str, &AgentClientError>,
) -> SelfUpgradePollAction {
    match status_result {
        Ok(status) => match status {
            "succeeded" | "completed" => SelfUpgradePollAction::Succeeded,
            "failed" => SelfUpgradePollAction::FailedThenReconnectConfirm,
            "running" | "queued" => SelfUpgradePollAction::StillInProgress,
            _ => SelfUpgradePollAction::UnexpectedStatus,
        },
        Err(_) => SelfUpgradePollAction::ConnectionDropped,
    }
}

/// Decision returned by [`decide_self_upgrade_reconnect_result`].
#[derive(Debug, PartialEq, Eq)]
enum SelfUpgradeReconnectResult {
    /// Version matches target (or changed from old) — mark Succeeded.
    Succeeded,
    /// Version unchanged — mark Failed.
    VersionUnchanged,
}

/// Pure decision function: after reconnect-confirm, determine whether the
/// new version constitutes a successful upgrade.
///
/// - If `target_version` is set, the new version must match it.
/// - If `target_version` is not set, the new version must differ from `old_version`.
/// - If neither is available, assume success.
///
/// Version comparison is **normalized**: a leading `v` prefix and a Debian
/// revision suffix (`-N`) are stripped before comparison. This handles the
/// real-world mismatch where `target_version` comes from
/// `repo_packages.version` (e.g. `"1.5.6"`) but `new_version` comes
/// from the agent's `health.version` (e.g. `"1.5.6-1"`). Without
/// normalization, `"1.5.6-1" == "1.5.6"` is false and a successful upgrade
/// is incorrectly marked failed.
fn decide_self_upgrade_reconnect_result(
    new_version: &str,
    target_version: Option<&str>,
    old_version: Option<&str>,
) -> SelfUpgradeReconnectResult {
    let normalize = |v: &str| -> String {
        let v = v.strip_prefix('v').unwrap_or(v);
        v.split('-').next().unwrap_or(v).to_string()
    };
    let new_norm = normalize(new_version);
    let version_ok = match (target_version, old_version) {
        (Some(target), _) => new_norm == normalize(target),
        (None, Some(old)) => new_norm != normalize(old),
        (None, None) => true,
    };
    if version_ok {
        SelfUpgradeReconnectResult::Succeeded
    } else {
        SelfUpgradeReconnectResult::VersionUnchanged
    }
}

/// Decision returned by [`decide_reconnect_error_action`].
#[derive(Debug, PartialEq, Eq)]
enum ReconnectErrorAction {
    /// Agent did not reconnect within the timeout window.
    Timeout,
    /// Unexpected error during reconnect.
    UnexpectedError,
}

/// Pure decision function: given an error from `reconnect_with_backoff`,
/// determine what failure action to take.
fn decide_reconnect_error_action(error: &AgentClientError) -> ReconnectErrorAction {
    match error {
        AgentClientError::ApiError { code, .. } if code == "RECONNECT_TIMEOUT" => {
            ReconnectErrorAction::Timeout
        },
        _ => ReconnectErrorAction::UnexpectedError,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-upgrade reconciliation
// ─────────────────────────────────────────────────────────────────────────────

/// Handle poll results for a `SelfUpgrade` host.
///
/// A dropped connection on a self-upgrade host is the **expected** success path
/// — the agent restarts mid-job, so `job_status()` WILL fail.  Instead of
/// marking the host failed, we enter reconnect-confirm mode:
///
/// 1. Wait for the agent to come back online (bounded by
///    `config.worker.self_upgrade_reconnect_timeout_secs`).
/// 2. Call `system_info()` to get the new `agent_version`.
/// 3. If the version matches the target → mark `Succeeded`, update `hosts.agent_version`.
/// 4. If the version is unchanged → mark `Failed` ("Agent restarted but version unchanged").
/// 5. If reconnect window expires → mark `Failed` ("Agent did not reconnect within timeout").
async fn poll_self_upgrade_host(
    pool: &PgPool,
    config: &Arc<AppConfig>,
    row: &PatchJobHostRunning,
    client: &AgentClient,
    status_result: Result<pm_agent_client::types::AgentJobStatus, AgentClientError>,
) {
    let action = decide_self_upgrade_poll_action(status_result.as_ref().map(|s| s.status.as_str()));

    match action {
        SelfUpgradePollAction::Succeeded => {
            tracing::info!(
                pjh_id = %row.id,
                "poll_self_upgrade_host: agent self-upgrade job succeeded"
            );
            let health = match client.health().await {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(
                        pjh_id = %row.id,
                        error = %e,
                        "poll_self_upgrade_host: job succeeded but health call failed, entering reconnect-confirm"
                    );
                    reconnect_confirm_self_upgrade(pool, config, row, client).await;
                    return;
                },
            };

            let target_version: Option<String> = sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT patch_selection FROM patch_jobs WHERE id = $1",
            )
            .bind(row.job_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .and_then(|v| {
                v.get("target_version")
                    .and_then(|t| t.as_str())
                    .map(String::from)
            });

            let old_version: Option<String> =
                sqlx::query_scalar::<_, String>("SELECT agent_version FROM hosts WHERE id = $1")
                    .bind(row.host_id)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten();

            let new_version = health.version.clone();
            let result = decide_self_upgrade_reconnect_result(
                &new_version,
                target_version.as_deref(),
                old_version.as_deref(),
            );

            match result {
                SelfUpgradeReconnectResult::Succeeded => {
                    tracing::info!(
                        pjh_id = %row.id,
                        new_version = %new_version,
                        old_version = ?old_version,
                        target_version = ?target_version,
                        "poll_self_upgrade_host: version confirmed, marking succeeded"
                    );
                    finish_self_upgrade_success(pool, row, &new_version).await;
                },
                SelfUpgradeReconnectResult::VersionUnchanged => {
                    let reason = match target_version {
                        Some(ref t) => format!(
                            "Agent reported success but version unchanged: expected {t}, got {new_version}"
                        ),
                        None => format!(
                            "Agent reported success but version unchanged: still {new_version}"
                        ),
                    };
                    tracing::warn!(
                        pjh_id = %row.id,
                        new_version = %new_version,
                        old_version = ?old_version,
                        target_version = ?target_version,
                        "poll_self_upgrade_host: agent reported success but no version change, marking failed"
                    );
                    handle_host_failure(pool.clone(), row.id, reason).await;
                },
            }
        },
        SelfUpgradePollAction::FailedThenReconnectConfirm => {
            tracing::info!(
                pjh_id = %row.id,
                "poll_self_upgrade_host: agent reported failure, entering reconnect-confirm"
            );
            reconnect_confirm_self_upgrade(pool, config, row, client).await;
        },
        SelfUpgradePollAction::StillInProgress => {
            tracing::debug!(
                pjh_id = %row.id,
                "poll_self_upgrade_host: job still in progress"
            );
        },
        SelfUpgradePollAction::UnexpectedStatus => {
            let status_str = status_result
                .as_ref()
                .map(|s| s.status.as_str())
                .unwrap_or("");
            tracing::warn!(
                pjh_id = %row.id,
                agent_status = %status_str,
                "poll_self_upgrade_host: unexpected agent status — ignoring"
            );
        },
        SelfUpgradePollAction::ConnectionDropped => {
            tracing::info!(
                pjh_id = %row.id,
                "poll_self_upgrade_host: job_status call failed (expected during self-upgrade), entering reconnect-confirm"
            );
            reconnect_confirm_self_upgrade(pool, config, row, client).await;
        },
    }
}

/// Reconnect-confirm mode for self-upgrade.
///
/// Waits for the agent to come back online, then verifies the new version.
async fn reconnect_confirm_self_upgrade(
    pool: &PgPool,
    config: &Arc<AppConfig>,
    row: &PatchJobHostRunning,
    client: &AgentClient,
) {
    let timeout_secs = config.worker.self_upgrade_reconnect_timeout_secs;

    tracing::info!(
        pjh_id = %row.id,
        timeout_secs,
        "reconnect_confirm_self_upgrade: waiting for agent to come back online"
    );

    // Use the existing reconnect_with_backoff helper which calls system_info()
    // with bounded exponential backoff.
    let sys_info = match pm_agent_client::reconnect_with_backoff(client, timeout_secs).await {
        Ok(info) => info,
        Err(e) => {
            let action = decide_reconnect_error_action(&e);
            match action {
                ReconnectErrorAction::Timeout => {
                    tracing::error!(
                        pjh_id = %row.id,
                        "reconnect_confirm_self_upgrade: agent did not reconnect within timeout"
                    );
                    handle_host_failure(
                        pool.clone(),
                        row.id,
                        "Agent did not reconnect within self-upgrade timeout".to_string(),
                    )
                    .await;
                },
                ReconnectErrorAction::UnexpectedError => {
                    tracing::error!(
                        pjh_id = %row.id,
                        error = %e,
                        "reconnect_confirm_self_upgrade: unexpected error during reconnect"
                    );
                    handle_host_failure(
                        pool.clone(),
                        row.id,
                        format!("Reconnect error during self-upgrade: {e}"),
                    )
                    .await;
                },
            }
            return;
        },
    };

    // Agent is back online. Verify the version change.
    // Fetch the target version from the job's patch_selection.
    let target_version: Option<String> = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT patch_selection FROM patch_jobs WHERE id = $1",
    )
    .bind(row.job_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|v| {
        v.get("target_version")
            .and_then(|t| t.as_str())
            .map(String::from)
    });

    // Fetch the old agent_version from the hosts table.
    let old_version: Option<String> =
        sqlx::query_scalar::<_, String>("SELECT agent_version FROM hosts WHERE id = $1")
            .bind(row.host_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

    // reconnect_with_backoff returns SystemInfoData which has hostname but not
    // the agent version. Call health() to get the new version string.
    let _ = sys_info; // Agent confirmed reachable via system_info; now get version.
    let health = match client.health().await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(
                pjh_id = %row.id,
                error = %e,
                "reconnect_confirm_self_upgrade: agent reconnected but health check failed"
            );
            handle_host_failure(
                pool.clone(),
                row.id,
                "Agent reconnected but health check failed after self-upgrade".to_string(),
            )
            .await;
            return;
        },
    };

    let new_version = health.version;
    tracing::info!(
        pjh_id = %row.id,
        new_version = %new_version,
        old_version = ?old_version,
        target_version = ?target_version,
        "reconnect_confirm_self_upgrade: agent reconnected with new version"
    );

    // M8: Check if agent has repo_config / GPG key configured.
    // Agents enrolled before v2.0.0 won't have repo_config — log for migration tracking.
    // The agent handles fallback to GET /pki/repo-config on its side; this is
    // informational for the manager to track migration status.
    match &health.gpg_key_status {
        Some(status) if status == "valid" => {
            tracing::info!(
                pjh_id = %row.id,
                host_id = %row.host_id,
                "reconnect_confirm_self_upgrade: agent has valid GPG key — repo_config present"
            );
        },
        Some(status) if status == "missing" => {
            tracing::warn!(
                pjh_id = %row.id,
                host_id = %row.host_id,
                "reconnect_confirm_self_upgrade: agent reports GPG key missing — repo_config not provisioned, agent should use GET /pki/repo-config fallback"
            );
        },
        Some(status) => {
            tracing::warn!(
                pjh_id = %row.id,
                host_id = %row.host_id,
                gpg_key_status = %status,
                "reconnect_confirm_self_upgrade: agent GPG key status requires attention"
            );
        },
        None => {
            tracing::debug!(
                pjh_id = %row.id,
                host_id = %row.host_id,
                "reconnect_confirm_self_upgrade: agent did not report GPG key status (pre-v2.0.0 or older agent)"
            );
        },
    }

    // Determine success using the pure decision function.
    let result = decide_self_upgrade_reconnect_result(
        &new_version,
        target_version.as_deref(),
        old_version.as_deref(),
    );

    match result {
        SelfUpgradeReconnectResult::Succeeded => {
            tracing::info!(
                pjh_id = %row.id,
                new_version = %new_version,
                "reconnect_confirm_self_upgrade: version confirmed, marking succeeded"
            );
            finish_self_upgrade_success(pool, row, &new_version).await;
        },
        SelfUpgradeReconnectResult::VersionUnchanged => {
            let reason = match target_version {
                Some(ref t) => {
                    format!(
                        "Agent restarted but version unchanged: expected {t}, got {new_version}"
                    )
                },
                None => format!("Agent restarted but version unchanged: still {new_version}"),
            };
            tracing::warn!(
                pjh_id = %row.id,
                reason = %reason,
                "reconnect_confirm_self_upgrade: version mismatch, marking failed"
            );
            handle_host_failure(pool.clone(), row.id, reason).await;
        },
    }
}

/// Mark a self-upgrade host as succeeded and update `hosts.agent_version`.
async fn finish_self_upgrade_success(pool: &PgPool, row: &PatchJobHostRunning, new_version: &str) {
    // Update the host's agent_version.
    if let Err(e) =
        sqlx::query("UPDATE hosts SET agent_version = $2, updated_at = NOW() WHERE id = $1")
            .bind(row.host_id)
            .bind(new_version)
            .execute(pool)
            .await
    {
        tracing::error!(
            pjh_id = %row.id,
            host_id = %row.host_id,
            error = %e,
            "finish_self_upgrade_success: failed to update hosts.agent_version"
        );
    }

    // Mark the pjh row as succeeded.
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
    .bind(format!(
        "Self-upgrade completed: agent version {new_version}"
    ))
    .execute(pool)
    .await
    {
        tracing::error!(pjh_id = %row.id, error = %e, "finish_self_upgrade_success: update failed");
    }

    sync_job_status(pool, row.job_id).await;
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
            COUNT(*) FILTER (WHERE status = 'waiting_health_check') AS waiting_health_check_count,
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

    if counts.running_count > 0
        || counts.pending_count > 0
        || counts.queued_count > 0
        || counts.waiting_health_check_count > 0
    {
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
            SET    status       = $2::job_status,
                   completed_at = COALESCE(completed_at, NOW())
            WHERE  id = $1
            "#,
        )
        .bind(job_id)
        .bind(new_status)
        .execute(pool)
        .await
    } else {
        sqlx::query("UPDATE patch_jobs SET status = $2::job_status WHERE id = $1")
            .bind(job_id)
            .bind(new_status)
            .execute(pool)
            .await
    };

    if let Err(e) = result {
        tracing::error!(%job_id, error = %e, "sync_job_status: failed to update parent job");
    }

    // Fire job-level pg_notify so the frontend can update the job row.
    let notify_payload = json!({
        "event_type": "job",
        "job_id": job_id.to_string(),
        "host_id": "",
        "status": new_status,
        "succeeded_count": counts.succeeded_count,
        "failed_count": counts.failed_count,
        "host_count": counts.total_count,
    });
    if let Ok(payload_str) = serde_json::to_string(&notify_payload) {
        if let Err(e) = sqlx::query("SELECT pg_notify('job_update', $1)")
            .bind(&payload_str)
            .execute(pool)
            .await
        {
            tracing::error!(%job_id, error = %e, "sync_job_status: job-level pg_notify failed");
        } else {
            tracing::info!(%job_id, status = %new_status, "sync_job_status: job-level pg_notify sent");
        }
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
///
/// Also retries `waiting_health_check` entries whose retry window has elapsed.
pub async fn retry_pending_jobs(pool: PgPool, config: Arc<AppConfig>) {
    let rows: Vec<PatchJobHostPending> = match sqlx::query_as(
        r#"
        SELECT pjh.id, pjh.host_id, pjh.job_id
        FROM   patch_job_hosts pjh
        JOIN   patch_jobs j ON j.id = pjh.job_id
        WHERE  pjh.status IN ('pending', 'waiting_health_check')
          AND  pjh.retry_next_at <= NOW()
          AND  j.status != 'cancelled'
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

// ─────────────────────────────────────────────────────────────────────────────
// fail_timed_out_jobs — catch running jobs that have exceeded the timeout
// ─────────────────────────────────────────────────────────────────────────────

/// Find running `patch_job_hosts` rows whose `started_at` is older than the
/// configured `job_timeout_secs` and mark them as failed.
///
/// This catches jobs that are stuck in `running` because the agent rebooted
/// and lost the in-memory job, or because of a network partition where the
/// agent is unreachable and never returns JOB_NOT_FOUND.
///
/// Self-upgrade jobs are excluded — they have their own reconnect timeout
/// logic in `poll_self_upgrade_host`.
async fn fail_timed_out_jobs(pool: PgPool, config: Arc<AppConfig>) {
    let timeout_secs = config.worker.job_timeout_secs;
    if timeout_secs == 0 {
        return; // 0 = disabled
    }

    #[derive(FromRow)]
    struct TimedOutRow {
        id: Uuid,
        job_id: Uuid,
        agent_job_id: Option<Uuid>,
        started_at: chrono::DateTime<chrono::Utc>,
    }

    let rows: Vec<TimedOutRow> = match sqlx::query_as(
        r#"
        SELECT pjh.id, pjh.job_id, pjh.agent_job_id, pjh.started_at
        FROM   patch_job_hosts pjh
        JOIN   patch_jobs j ON j.id = pjh.job_id
        WHERE  pjh.status = 'running'
          AND  j.kind != 'self_upgrade'
          AND  pjh.started_at IS NOT NULL
          AND  pjh.started_at < NOW() - ($1 || ' seconds')::interval
        "#,
    )
    .bind(timeout_secs.to_string())
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "fail_timed_out_jobs: DB query failed");
            return;
        },
    };

    for row in rows {
        let elapsed = chrono::Utc::now() - row.started_at;
        let err_msg = format!(
            "Job timed out after {} seconds (started at {}). The agent may have rebooted or become unreachable.",
            elapsed.num_seconds(),
            row.started_at
        );

        tracing::warn!(
            pjh_id = %row.id,
            job_id = %row.job_id,
            agent_job_id = ?row.agent_job_id,
            elapsed_secs = elapsed.num_seconds(),
            timeout_secs,
            "fail_timed_out_jobs: marking stuck running job as failed"
        );

        // Mark the pjh as failed directly (not via handle_host_failure, which
        // would schedule a retry — a timed-out job should not be retried
        // automatically because the agent state is unknown).
        if let Err(e) = sqlx::query(
            r#"
            UPDATE patch_job_hosts
            SET    status        = 'failed',
                   error_message = $2,
                   last_error    = $2,
                   completed_at  = NOW()
            WHERE  id = $1
            "#,
        )
        .bind(row.id)
        .bind(&err_msg)
        .execute(&pool)
        .await
        {
            tracing::error!(
                pjh_id = %row.id,
                error = %e,
                "fail_timed_out_jobs: failed to mark pjh as failed"
            );
            continue;
        }

        // Sync the parent job status.
        sync_job_status(&pool, row.job_id).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — self-upgrade reconciliation decision logic
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── decide_self_upgrade_poll_action tests ──────────────────────────────

    /// When `job_status()` fails (connection dropped), the worker must NOT
    /// mark the host as Failed. It should enter reconnect-confirm mode.
    #[test]
    fn test_self_upgrade_dropped_connection_is_not_failure() {
        // Any AgentClientError variant triggers reconnect-confirm, not failure.
        // Test with Tls error (easily constructible) to verify the invariant.
        let err = AgentClientError::Tls("connection dropped".into());
        let result = decide_self_upgrade_poll_action(Err(&err));
        assert_eq!(result, SelfUpgradePollAction::ConnectionDropped);
        // ConnectionDropped is NOT a failure — it triggers reconnect-confirm.
        assert_ne!(result, SelfUpgradePollAction::UnexpectedStatus);
    }

    /// When `job_status()` fails with a timeout, still enter reconnect-confirm.
    #[test]
    fn test_self_upgrade_timeout_is_not_failure() {
        let result = decide_self_upgrade_poll_action(Err(&AgentClientError::Timeout));
        assert_eq!(result, SelfUpgradePollAction::ConnectionDropped);
    }

    /// When `job_status()` fails with a TLS error, still enter reconnect-confirm.
    #[test]
    fn test_self_upgrade_tls_error_is_not_failure() {
        let result =
            decide_self_upgrade_poll_action(Err(&AgentClientError::Tls("TLS error".into())));
        assert_eq!(result, SelfUpgradePollAction::ConnectionDropped);
    }

    /// When `job_status()` succeeds with "succeeded", mark as Succeeded.
    #[test]
    fn test_self_upgrade_agent_reports_succeeded() {
        let result = decide_self_upgrade_poll_action(Ok("succeeded"));
        assert_eq!(result, SelfUpgradePollAction::Succeeded);
    }

    /// When `job_status()` succeeds with "completed", mark as Succeeded.
    #[test]
    fn test_self_upgrade_agent_reports_completed() {
        let result = decide_self_upgrade_poll_action(Ok("completed"));
        assert_eq!(result, SelfUpgradePollAction::Succeeded);
    }

    /// When `job_status()` succeeds with "failed", enter reconnect-confirm
    /// (the agent may have restarted with the new version despite reporting failure).
    #[test]
    fn test_self_upgrade_agent_reports_failed_then_reconnect() {
        let result = decide_self_upgrade_poll_action(Ok("failed"));
        assert_eq!(result, SelfUpgradePollAction::FailedThenReconnectConfirm);
    }

    /// When `job_status()` returns "running", keep polling.
    #[test]
    fn test_self_upgrade_agent_reports_running() {
        let result = decide_self_upgrade_poll_action(Ok("running"));
        assert_eq!(result, SelfUpgradePollAction::StillInProgress);
    }

    /// When `job_status()` returns "queued", keep polling.
    #[test]
    fn test_self_upgrade_agent_reports_queued() {
        let result = decide_self_upgrade_poll_action(Ok("queued"));
        assert_eq!(result, SelfUpgradePollAction::StillInProgress);
    }

    /// When `job_status()` returns an unexpected status, ignore it.
    #[test]
    fn test_self_upgrade_agent_reports_unexpected_status() {
        let result = decide_self_upgrade_poll_action(Ok("unknown_status"));
        assert_eq!(result, SelfUpgradePollAction::UnexpectedStatus);
    }

    // ── decide_self_upgrade_reconnect_result tests ─────────────────────────

    /// After reconnect-confirm, if the new version matches the target, mark Succeeded.
    #[test]
    fn test_self_upgrade_reconnect_version_match_succeeds() {
        let result = decide_self_upgrade_reconnect_result("2.0.0", Some("2.0.0"), Some("1.0.0"));
        assert_eq!(result, SelfUpgradeReconnectResult::Succeeded);
    }

    /// After reconnect-confirm, if the new version matches the target even
    /// without an old version baseline, mark Succeeded.
    #[test]
    fn test_self_upgrade_reconnect_version_match_succeeds_no_old() {
        let result = decide_self_upgrade_reconnect_result("2.0.0", Some("2.0.0"), None);
        assert_eq!(result, SelfUpgradeReconnectResult::Succeeded);
    }

    /// After reconnect-confirm, if the new version does NOT match the target,
    /// mark VersionUnchanged (failed).
    #[test]
    fn test_self_upgrade_reconnect_version_unchanged_fails() {
        let result = decide_self_upgrade_reconnect_result("1.0.0", Some("2.0.0"), Some("1.0.0"));
        assert_eq!(result, SelfUpgradeReconnectResult::VersionUnchanged);
    }

    /// After reconnect-confirm, with no target_version, if the new version
    /// differs from the old version, mark Succeeded.
    #[test]
    fn test_self_upgrade_reconnect_version_changed_no_target() {
        let result = decide_self_upgrade_reconnect_result("2.0.0", None, Some("1.0.0"));
        assert_eq!(result, SelfUpgradeReconnectResult::Succeeded);
    }

    /// After reconnect-confirm, with no target_version, if the new version
    /// is the same as the old version, mark VersionUnchanged (failed).
    #[test]
    fn test_self_upgrade_reconnect_version_same_no_target() {
        let result = decide_self_upgrade_reconnect_result("1.0.0", None, Some("1.0.0"));
        assert_eq!(result, SelfUpgradeReconnectResult::VersionUnchanged);
    }

    /// After reconnect-confirm, with no target_version and no old_version,
    /// assume success (no baseline to compare).
    #[test]
    fn test_self_upgrade_reconnect_no_baseline_assumes_success() {
        let result = decide_self_upgrade_reconnect_result("1.0.0", None, None);
        assert_eq!(result, SelfUpgradeReconnectResult::Succeeded);
    }

    /// Agent reports debian-style version with revision suffix (e.g. "2.0.0-1")
    /// but target_version is the bare upstream version ("2.0.0"). The upgrade
    /// actually succeeded — normalization must treat them as equal.
    #[test]
    fn test_self_upgrade_reconnect_debian_revision_suffix_normalized() {
        let result =
            decide_self_upgrade_reconnect_result("2.0.0-1", Some("2.0.0"), Some("1.0.0-1"));
        assert_eq!(result, SelfUpgradeReconnectResult::Succeeded);
    }

    /// Agent reports version with leading 'v' (e.g. "v2.0.0-1") but
    /// target_version is bare ("2.0.0"). Strip the 'v' prefix before compare.
    #[test]
    fn test_self_upgrade_reconnect_v_prefix_normalized() {
        let result =
            decide_self_upgrade_reconnect_result("v2.0.0-1", Some("2.0.0"), Some("v1.0.0-1"));
        assert_eq!(result, SelfUpgradeReconnectResult::Succeeded);
    }

    /// Old version has revision suffix, new version doesn't, no target.
    /// They differ in upstream version → succeeded.
    #[test]
    fn test_self_upgrade_reconnect_old_revision_suffix_normalized() {
        let result = decide_self_upgrade_reconnect_result("2.0.0", None, Some("1.0.0-1"));
        assert_eq!(result, SelfUpgradeReconnectResult::Succeeded);
    }

    /// Same upstream version, different revision suffix, no target.
    /// "1.5.6-1" vs "1.5.6-2" → after normalization both are "1.5.6" →
    /// VersionUnchanged (a revision-only bump is not a real upgrade from
    /// the manager's perspective, which tracks upstream versions).
    #[test]
    fn test_self_upgrade_reconnect_revision_only_bump_is_unchanged() {
        let result = decide_self_upgrade_reconnect_result("1.5.6-2", None, Some("1.5.6-1"));
        assert_eq!(result, SelfUpgradeReconnectResult::VersionUnchanged);
    }

    // ── decide_reconnect_error_action tests ─────────────────────────────────

    /// If reconnect_with_backoff returns RECONNECT_TIMEOUT, mark as timeout failure.
    #[test]
    fn test_self_upgrade_reconnect_timeout_fails() {
        let err = AgentClientError::ApiError {
            code: "RECONNECT_TIMEOUT".to_string(),
            message: "Agent did not come back online within 600s".to_string(),
        };
        let action = decide_reconnect_error_action(&err);
        assert_eq!(action, ReconnectErrorAction::Timeout);
    }

    /// If reconnect_with_backoff returns a non-timeout API error, mark as unexpected.
    #[test]
    fn test_self_upgrade_reconnect_api_error_unexpected() {
        let err = AgentClientError::ApiError {
            code: "INTERNAL_ERROR".to_string(),
            message: "Something went wrong".to_string(),
        };
        let action = decide_reconnect_error_action(&err);
        assert_eq!(action, ReconnectErrorAction::UnexpectedError);
    }

    /// If reconnect_with_backoff returns a connection error, mark as unexpected.
    #[test]
    fn test_self_upgrade_reconnect_tls_error_unexpected() {
        let err = AgentClientError::Tls("TLS handshake failed".into());
        let action = decide_reconnect_error_action(&err);
        assert_eq!(action, ReconnectErrorAction::UnexpectedError);
    }
}
