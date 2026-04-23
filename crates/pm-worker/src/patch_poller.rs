//! Periodic patch-data poller for all registered hosts.
//!
//! Polls every host via the agent `/patches` and `/packages` endpoints on
//! each tick of `patch_poll_interval_secs`, with bounded concurrency
//! controlled by a [`tokio::sync::Semaphore`].

use std::sync::Arc;

use pm_agent_client::AgentClient;
use pm_core::config::AppConfig;
use sqlx::{FromRow, PgPool};
use tokio::{
    sync::Semaphore,
    time,
};
use uuid::Uuid;

use crate::agent_loader::load_agent_certs;

/// Minimal host projection fetched for each poll cycle.
#[derive(Debug, FromRow)]
struct HostRow {
    id: Uuid,
    ip_address: String,
    agent_port: i32,
}

/// Run the patch poller loop indefinitely.
///
/// On each tick all registered hosts are queried concurrently (up to
/// `max_concurrent_agent_calls` in-flight at once). Results are persisted
/// to `host_patch_data` and `hosts.last_patch_at` is updated.
pub async fn run_patch_poller(pool: PgPool, config: Arc<AppConfig>) {
    let interval_secs = config.worker.patch_poll_interval_secs;
    let mut ticker = time::interval(std::time::Duration::from_secs(interval_secs));

    tracing::info!(
        interval_secs,
        "Patch poller started"
    );

    loop {
        ticker.tick().await;

        let certs = match load_agent_certs(&config.security) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "Patch poller: failed to load agent certs — skipping cycle");
                continue;
            }
        };

        let client_cert = Arc::new(certs.client_cert);
        let client_key = Arc::new(certs.client_key);
        let ca_cert = Arc::new(certs.ca_cert);

        let hosts: Vec<HostRow> = match sqlx::query_as(
            "SELECT id, ip_address::text AS ip_address, agent_port FROM hosts ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "Patch poller: failed to fetch hosts");
                continue;
            }
        };

        if hosts.is_empty() {
            tracing::debug!("Patch poller: no hosts registered, skipping cycle");
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
                poll_host_patches(pool, host, &cert, &key, &ca).await
            });

            handles.push(handle);
        }

        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for handle in handles {
            match handle.await {
                Ok(true) => succeeded += 1,
                Ok(false) => failed += 1,
                Err(e) => {
                    tracing::error!(error = %e, "Patch poller task panicked");
                    failed += 1;
                }
            }
        }

        tracing::info!(
            total,
            succeeded,
            failed,
            "Patch poll cycle complete"
        );
    }
}

/// Poll a single host for patch and package data, persist the result.
/// Returns `true` on success, `false` on any error.
async fn poll_host_patches(
    pool: PgPool,
    host: HostRow,
    client_cert: &[u8],
    client_key: &[u8],
    ca_cert: &[u8],
) -> bool {
    let client = match AgentClient::new(
        &host.ip_address,
        host.agent_port as u16,
        client_cert,
        client_key,
        ca_cert,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(host_id = %host.id, error = %e, "Patch poller: failed to build AgentClient");
            return false;
        }
    };

    // Fetch patches and packages concurrently.
    let (patches_result, packages_result) =
        tokio::join!(client.patches(), client.packages_upgradable());

    let patches_data = match patches_result {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(host_id = %host.id, error = %e, "Patch poller: patches() failed");
            return false;
        }
    };

    let packages_data = match packages_result {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(host_id = %host.id, error = %e, "Patch poller: packages_upgradable() failed");
            return false;
        }
    };

    let available_patches = serde_json::to_value(&patches_data.patches).unwrap_or_default();
    let installed_packages = serde_json::to_value(&packages_data.packages).unwrap_or_default();
    let patch_count = patches_data.total as i32;
    let cve_count = patches_data
        .patches
        .iter()
        .filter(|p| !p.cve_ids.is_empty())
        .count() as i32;

    // Insert into host_patch_data.
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO host_patch_data
            (host_id, available_patches, installed_packages, patch_count, cve_count)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(host.id)
    .bind(&available_patches)
    .bind(&installed_packages)
    .bind(patch_count)
    .bind(cve_count)
    .execute(&pool)
    .await
    {
        tracing::error!(host_id = %host.id, error = %e, "Patch poller: failed to insert patch data");
        return false;
    }

    // Update hosts.last_patch_at.
    if let Err(e) = sqlx::query(
        "UPDATE hosts SET last_patch_at = NOW() WHERE id = $1",
    )
    .bind(host.id)
    .execute(&pool)
    .await
    {
        tracing::error!(host_id = %host.id, error = %e, "Patch poller: failed to update last_patch_at");
    }

    tracing::debug!(
        host_id = %host.id,
        patch_count,
        cve_count,
        "Patch data collected"
    );

    true
}
