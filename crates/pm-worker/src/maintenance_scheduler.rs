//! Maintenance window scheduler.
//!
//! Polls every 60 seconds and performs two tasks:
//!
//! 1. **Auto-apply**: For each enabled maintenance window with `auto_apply = true`
//!    that is currently open, if the host has pending patches and no existing
//!    patch_apply job queued/running for that window, automatically creates one.
//!
//! 2. **Dispatch**: For each open window, dispatch any queued non-immediate
//!    patch jobs associated with the window's host.
//!
//! A window is considered "open" when:
//! - `once`    — `start_at <= NOW() < start_at + duration_minutes * '1 minute'`
//! - `daily`   — current UTC time-of-day is within the window's daily slot
//! - `weekly`  — same as daily, but only on the matching `recurrence_day` (0=Sun)
//! - `monthly` — same as daily, but only on the matching `recurrence_day` (1-31)

use std::sync::Arc;

use pm_core::config::AppConfig;
use sqlx::{FromRow, PgPool};
use tokio::time;
use uuid::Uuid;

use crate::job_executor::process_job;

// ─────────────────────────────────────────────────────────────────────────────
// Internal types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, FromRow)]
struct OpenWindowHost {
    host_id: Uuid,
}

#[derive(Debug, FromRow)]
struct QueuedJobId {
    job_id: Uuid,
}

#[derive(Debug, FromRow)]
struct AutoApplyWindow {
    window_id: Uuid,
    host_id: Uuid,
}

#[derive(Debug, FromRow)]
struct PendingPatchHost {
    host_id: Uuid,
    patch_count: i32,
}

#[derive(Debug, FromRow)]
struct InsertedJobId {
    job_id: Uuid,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run the maintenance scheduler indefinitely.
/// Spawned by `pm-worker/src/main.rs` alongside the job executor.
pub async fn run_maintenance_scheduler(pool: PgPool, config: Arc<AppConfig>) {
    tracing::info!("Maintenance scheduler started");

    // First tick fires immediately; consume it to align with job_executor.
    let mut ticker = time::interval(std::time::Duration::from_secs(60));
    ticker.tick().await;

    loop {
        ticker.tick().await;
        tracing::debug!("Maintenance scheduler: checking open windows");

        // Step 1: Auto-create patch_apply jobs for windows with auto_apply=true
        auto_create_patch_jobs(pool.clone(), config.clone()).await;

        // Step 2: Dispatch any queued non-immediate jobs for open windows
        dispatch_open_window_jobs(pool.clone(), config.clone()).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1: Auto-create patch_apply jobs
// ─────────────────────────────────────────────────────────────────────────────

/// For each enabled maintenance window that is currently open AND has
/// `auto_apply = true`, check if the host has pending patches and no
/// existing patch_apply job for this window cycle. If so, create one.
async fn auto_create_patch_jobs(pool: PgPool, _config: Arc<AppConfig>) {
    // Find all open windows with auto_apply=true
    let auto_windows: Vec<AutoApplyWindow> = match sqlx::query_as(
        r#"
        SELECT mw.id AS window_id, mw.host_id
        FROM   maintenance_windows mw
        WHERE  mw.enabled = TRUE
          AND  mw.auto_apply = TRUE
          AND (
            (   mw.recurrence = 'once'
             AND mw.start_at <= NOW()
             AND NOW() < mw.start_at + (mw.duration_minutes * INTERVAL '1 minute')
            )
            OR
            (   mw.recurrence = 'daily'
             AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
             AND (NOW() AT TIME ZONE 'UTC')::time <  ((mw.start_at AT TIME ZONE 'UTC')::time
                                                       + (mw.duration_minutes * INTERVAL '1 minute'))
            )
            OR
            (   mw.recurrence = 'weekly'
             AND EXTRACT(DOW FROM NOW() AT TIME ZONE 'UTC') = mw.recurrence_day
             AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
             AND (NOW() AT TIME ZONE 'UTC')::time <  ((mw.start_at AT TIME ZONE 'UTC')::time
                                                       + (mw.duration_minutes * INTERVAL '1 minute'))
            )
            OR
            (   mw.recurrence = 'monthly'
             AND EXTRACT(DAY FROM NOW() AT TIME ZONE 'UTC') = mw.recurrence_day
             AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
             AND (NOW() AT TIME ZONE 'UTC')::time <  ((mw.start_at AT TIME ZONE 'UTC')::time
                                                       + (mw.duration_minutes * INTERVAL '1 minute'))
            )
          )
        "#,
    )
    .fetch_all(&pool)
    .await
    {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(error = %e, "auto_create_patch_jobs: open-windows query failed");
            return;
        }
    };

    if auto_windows.is_empty() {
        tracing::debug!("auto_create: no open auto-apply windows this cycle");
        return;
    }

    tracing::info!(
        auto_window_count = auto_windows.len(),
        "auto_create: found open auto-apply windows"
    );

    for win in &auto_windows {
        // Check if host has pending patches
        let pending: Option<PendingPatchHost> = match sqlx::query_as(
            r#"
            SELECT host_id, patch_count
            FROM   host_patch_data
            WHERE  host_id = $1 AND patch_count > 0
            "#,
        )
        .bind(win.host_id)
        .fetch_optional(&pool)
        .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    host_id = %win.host_id,
                    "auto_create: patch data query failed"
                );
                continue;
            },
        };

        let Some(pending) = pending else {
            tracing::debug!(
                host_id = %win.host_id,
                "auto_create: no pending patches, skipping"
            );
            continue;
        };

        // Check if there's already a queued/running patch_apply job for this host
        // that was created during this window cycle (within the window's time range).
        // We use a simpler check: any non-completed patch_apply job for this host
        // that references this maintenance window, OR any non-immediate job without
        // a window that was created since the window opened.
        let existing_job: bool = match sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM patch_jobs pj
                JOIN   patch_job_hosts pjh ON pj.id = pjh.job_id
                WHERE  pjh.host_id = $1
                  AND  pj.status IN ('queued', 'running', 'pending')
                  AND  pj.kind = 'patch_apply'
                  AND (
                    pj.maintenance_window_id = $2
                    OR
                    (pj.immediate = FALSE AND pj.created_at >=
                        (SELECT start_at - INTERVAL '5 minutes' FROM maintenance_windows WHERE id = $2)
                    )
                  )
            )
            "#,
        )
        .bind(win.host_id)
        .bind(win.window_id)
        .fetch_one(&pool)
        .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    host_id = %win.host_id,
                    "auto_create: existing job check failed"
                );
                continue;
            }
        };

        if existing_job {
            tracing::debug!(
                host_id = %win.host_id,
                window_id = %win.window_id,
                "auto_create: existing job already queued/running, skipping"
            );
            continue;
        }

        // Create a new patch_apply job for this host, linked to the window.
        let job: Option<InsertedJobId> = match sqlx::query_as(
            r#"
            WITH new_job AS (
                INSERT INTO patch_jobs
                    (kind, status, maintenance_window_id, immediate, patch_selection, notes)
                VALUES
                    ('patch_apply', 'queued', $1, FALSE, '[]'::jsonb,
                     'Auto-created by maintenance window scheduler')
                RETURNING id AS job_id
            )
            INSERT INTO patch_job_hosts (job_id, host_id, status)
            SELECT new_job.job_id, $2, 'queued'
            FROM   new_job
            RETURNING job_id
            "#,
        )
        .bind(win.window_id)
        .bind(win.host_id)
        .fetch_optional(&pool)
        .await
        {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    host_id = %win.host_id,
                    window_id = %win.window_id,
                    "auto_create: job insert failed"
                );
                continue;
            },
        };

        if let Some(job) = job {
            tracing::info!(
                job_id = %job.job_id,
                host_id = %win.host_id,
                window_id = %win.window_id,
                patch_count = pending.patch_count,
                "auto_create: created patch_apply job for host in maintenance window"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2: Dispatch queued non-immediate jobs
// ─────────────────────────────────────────────────────────────────────────────

/// Find all hosts with a currently-open maintenance window, then for each,
/// find their queued non-immediate job entries and dispatch them.
async fn dispatch_open_window_jobs(pool: PgPool, config: Arc<AppConfig>) {
    // ── 1. Find all host_ids with an open window right now ─────────────────
    let open_hosts: Vec<OpenWindowHost> = match sqlx::query_as(
        r#"
        SELECT DISTINCT mw.host_id
        FROM   maintenance_windows mw
        WHERE  mw.enabled = TRUE
          AND (
            -- One-time: absolute window
            (   mw.recurrence = 'once'
             AND mw.start_at <= NOW()
             AND NOW() < mw.start_at + (mw.duration_minutes * INTERVAL '1 minute')
            )
            OR
            -- Daily: time-of-day slot, any day
            (   mw.recurrence = 'daily'
             AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
             AND (NOW() AT TIME ZONE 'UTC')::time <  ((mw.start_at AT TIME ZONE 'UTC')::time
                                                       + (mw.duration_minutes * INTERVAL '1 minute'))
            )
            OR
            -- Weekly: matching day-of-week + time-of-day slot
            (   mw.recurrence = 'weekly'
             AND EXTRACT(DOW FROM NOW() AT TIME ZONE 'UTC') = mw.recurrence_day
             AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
             AND (NOW() AT TIME ZONE 'UTC')::time <  ((mw.start_at AT TIME ZONE 'UTC')::time
                                                       + (mw.duration_minutes * INTERVAL '1 minute'))
            )
            OR
            -- Monthly: matching day-of-month + time-of-day slot
            (   mw.recurrence = 'monthly'
             AND EXTRACT(DAY FROM NOW() AT TIME ZONE 'UTC') = mw.recurrence_day
             AND (NOW() AT TIME ZONE 'UTC')::time >= (mw.start_at AT TIME ZONE 'UTC')::time
             AND (NOW() AT TIME ZONE 'UTC')::time <  ((mw.start_at AT TIME ZONE 'UTC')::time
                                                       + (mw.duration_minutes * INTERVAL '1 minute'))
            )
          )
        "#,
    )
    .fetch_all(&pool)
    .await
    {
        Ok(hosts) => hosts,
        Err(e) => {
            tracing::error!(error = %e, "dispatch_open_window_jobs: open-hosts query failed");
            return;
        }
    };

    if open_hosts.is_empty() {
        tracing::debug!("Maintenance scheduler: no open windows this cycle");
        return;
    }

    tracing::info!(
        open_host_count = open_hosts.len(),
        "Maintenance scheduler: found hosts with open windows"
    );

    // ── 2. For each open host, find distinct queued non-immediate job IDs ──
    for host in open_hosts {
        let job_ids: Vec<QueuedJobId> = match sqlx::query_as(
            r#"
            SELECT DISTINCT pjh.job_id
            FROM   patch_job_hosts pjh
            JOIN   patch_jobs      j   ON j.id = pjh.job_id
            WHERE  pjh.host_id     = $1
              AND  pjh.status      = 'queued'
              AND  j.immediate     = FALSE
              AND  j.status       != 'cancelled'
              AND  (pjh.retry_next_at IS NULL OR pjh.retry_next_at <= NOW())
            "#,
        )
        .bind(host.host_id)
        .fetch_all(&pool)
        .await
        {
            Ok(ids) => ids,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    host_id = %host.host_id,
                    "dispatch_open_window_jobs: queued jobs query failed"
                );
                continue;
            },
        };

        for job in job_ids {
            tracing::info!(
                job_id = %job.job_id,
                host_id = %host.host_id,
                "Maintenance scheduler: dispatching non-immediate job (window open)"
            );

            let (p, c) = (pool.clone(), config.clone());
            let job_id = job.job_id;
            tokio::spawn(async move {
                process_job(p, c, job_id).await;
            });
        }
    }
}
