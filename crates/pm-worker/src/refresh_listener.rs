//! On-demand refresh listener.
//!
//! Listens on the PostgreSQL `refresh_requested` NOTIFY channel. When a
//! notification arrives the payload is expected to be a host UUID string.
//! The listener immediately polls that host for health and patch data and
//! persists the results — bypassing the normal poll intervals.

use std::sync::Arc;

use pm_agent_client::{AgentClient, AgentClientError};
use pm_core::{
    config::AppConfig,
    models::HostHealthStatus,
};
use sqlx::{FromRow, PgPool};
use tokio::time;
use uuid::Uuid;

use crate::agent_loader::load_agent_certs;

/// Minimal host row used for on-demand refresh.
#[derive(Debug, FromRow)]
struct HostRow {
    id: Uuid,
    ip_address: String,
    agent_port: i32,
}

/// Run the LISTEN/NOTIFY refresh listener indefinitely.
///
/// Automatically reconnects if the underlying PostgreSQL connection drops.
pub async fn run_refresh_listener(pool: PgPool, config: Arc<AppConfig>) {
    tracing::info!("Refresh listener started — listening on 'refresh_requested'");

    loop {
        if let Err(e) = listen_loop(&pool, &config).await {
            tracing::error!(
                error = %e,
                "Refresh listener disconnected, reconnecting in 5s"
            );
            time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

/// Inner loop — returns `Err` only on a fatal listener error so the outer
/// loop can reconnect.
async fn listen_loop(pool: &PgPool, config: &AppConfig) -> anyhow::Result<()> {
    let mut listener =
        sqlx::postgres::PgListener::connect(&config.database.url).await?;

    listener.listen("refresh_requested").await?;

    tracing::debug!("Refresh listener connected and listening");

    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload().to_string();

        tracing::info!(payload, "Refresh notification received");

        let host_id = match payload.parse::<Uuid>() {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    payload,
                    error = %e,
                    "Refresh listener: invalid UUID in notification payload"
                );
                continue;
            }
        };

        // Fetch the host from the database.
        let host: Option<HostRow> = sqlx::query_as(
            "SELECT id, ip_address::text AS ip_address, agent_port FROM hosts WHERE id = $1",
        )
        .bind(host_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

        let host = match host {
            Some(h) => h,
            None => {
                tracing::warn!(%host_id, "Refresh listener: host not found");
                continue;
            }
        };

        // Load certs for this refresh.
        let certs = match load_agent_certs(&config.security) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    %host_id,
                    error = %e,
                    "Refresh listener: failed to load agent certs"
                );
                continue;
            }
        };

        // Spawn the actual work so the listener loop is not blocked.
        let pool_clone = pool.clone();
        let cert = certs.client_cert;
        let key = certs.client_key;
        let ca = certs.ca_cert;

        tokio::spawn(async move {
            refresh_host(pool_clone, host, &cert, &key, &ca).await;
        });
    }
}

/// Perform a full health + patch refresh for one host and persist results.
async fn refresh_host(
    pool: PgPool,
    host: HostRow,
    client_cert: &[u8],
    client_key: &[u8],
    ca_cert: &[u8],
) {
    let client = match AgentClient::new(
        &host.ip_address,
        host.agent_port as u16,
        client_cert,
        client_key,
        ca_cert,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                host_id = %host.id,
                error = %e,
                "Refresh: failed to build AgentClient"
            );
            persist_health_unreachable(&pool, host.id).await;
            return;
        }
    };

    // ── Health ────────────────────────────────────────────────────────────
    let (health_status, health_payload) = match client.health().await {
        Ok(data) => {
            let payload = serde_json::to_value(&data).unwrap_or_default();
            (HostHealthStatus::Healthy, payload)
        }
        Err(AgentClientError::Timeout) | Err(AgentClientError::Connect(_)) => {
            tracing::warn!(host_id = %host.id, "Refresh: agent unreachable");
            (HostHealthStatus::Unreachable, serde_json::Value::Object(Default::default()))
        }
        Err(e) => {
            tracing::warn!(host_id = %host.id, error = %e, "Refresh: health error");
            (HostHealthStatus::Degraded, serde_json::Value::Object(Default::default()))
        }
    };

    persist_health(&pool, host.id, &health_status, &health_payload).await;

    // ── Patch data ────────────────────────────────────────────────────────
    let (patches_result, packages_result) =
        tokio::join!(client.patches(), client.packages_upgradable());

    match (patches_result, packages_result) {
        (Ok(patches_data), Ok(packages_data)) => {
            let available_patches =
                serde_json::to_value(&patches_data.patches).unwrap_or_default();
            let installed_packages =
                serde_json::to_value(&packages_data.packages).unwrap_or_default();
            let patch_count = patches_data.total as i32;
            let cve_count = patches_data
                .patches
                .iter()
                .filter(|p| !p.cve_ids.is_empty())
                .count() as i32;

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
                tracing::error!(
                    host_id = %host.id,
                    error = %e,
                    "Refresh: failed to insert patch data"
                );
            } else {
                let _ = sqlx::query(
                    "UPDATE hosts SET last_patch_at = NOW() WHERE id = $1",
                )
                .bind(host.id)
                .execute(&pool)
                .await;

                tracing::info!(
                    host_id = %host.id,
                    patch_count,
                    cve_count,
                    "On-demand refresh complete"
                );
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(
                host_id = %host.id,
                error = %e,
                "Refresh: failed to collect patch data"
            );
        }
    }
}

async fn persist_health_unreachable(pool: &PgPool, host_id: Uuid) {
    let status = HostHealthStatus::Unreachable;
    let payload = serde_json::Value::Object(Default::default());
    persist_health(pool, host_id, &status, &payload).await;
}

async fn persist_health(
    pool: &PgPool,
    host_id: Uuid,
    status: &HostHealthStatus,
    payload: &serde_json::Value,
) {
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO host_health_data (host_id, status, payload)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(host_id)
    .bind(status)
    .bind(payload)
    .execute(pool)
    .await
    {
        tracing::error!(
            %host_id,
            error = %e,
            "Refresh: failed to insert health data"
        );
    }

    if let Err(e) = sqlx::query(
        "UPDATE hosts SET health_status = $2, last_health_at = NOW() WHERE id = $1",
    )
    .bind(host_id)
    .bind(status)
    .execute(pool)
    .await
    {
        tracing::error!(%host_id, error = %e, "Refresh: failed to update host health_status");
    }
}
