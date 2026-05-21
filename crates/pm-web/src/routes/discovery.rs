//! CIDR auto-discovery routes.
//!
//! POST /api/v1/discovery/cidr         — start a CIDR scan
//! GET  /api/v1/discovery/:scan_id     — get scan results
//! POST /api/v1/discovery/:id/register — register a discovered host

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use pm_auth::rbac::AuthUser;
use pm_core::{
    audit::{log_event, AuditAction},
    models::{DiscoveryCidrRequest, DiscoveryResult, RegisterDiscoveredRequest},
};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, TcpStream},
    time::Duration,
};
use tokio::{sync::Semaphore, task};
use uuid::Uuid;

use crate::AppState;

/// Maximum concurrent TCP probes during CIDR scan.
const MAX_CONCURRENT_PROBES: usize = 128;
/// TCP connect timeout per probe.
const PROBE_TIMEOUT_SECS: u64 = 2;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/cidr", post(start_cidr_scan))
        .route("/{scan_id}", get(get_scan_results))
        .route("/{id}/register", post(register_discovered_host))
}

// ── POST /api/v1/discovery/cidr ───────────────────────────────────────────────

async fn start_cidr_scan(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<DiscoveryCidrRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }

    let cidr: ipnet::IpNet = req.cidr.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "bad_request", "message": "Invalid CIDR range" } })),
        )
    })?;

    let agent_port = req.agent_port.unwrap_or(12443) as u16;
    let scan_id = Uuid::new_v4();

    // Clear previous results for this type of scan and start async scan
    let pool = state.db.clone();
    let scan_id_clone = scan_id;
    let cidr_str = req.cidr.clone();

    // Spawn non-blocking background scan
    task::spawn(async move {
        run_cidr_scan(pool, scan_id_clone, cidr, agent_port).await;
    });

    log_event(
        &state.db,
        AuditAction::DiscoveryScanStarted,
        Some(auth.user_id),
        Some(&auth.username),
        Some("discovery"),
        Some(&scan_id.to_string()),
        json!({ "cidr": cidr_str }),
        None,
        None,
    )
    .await;

    tracing::info!(scan_id = %scan_id, cidr = %req.cidr, "CIDR scan started");
    Ok(Json(
        json!({ "scan_id": scan_id, "message": "Discovery scan started", "cidr": req.cidr }),
    ))
}

/// Background CIDR scanner.
async fn run_cidr_scan(pool: sqlx::PgPool, scan_id: Uuid, cidr: ipnet::IpNet, port: u16) {
    let semaphore = std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES));
    let hosts: Vec<IpAddr> = cidr.hosts().collect();
    let total = hosts.len();

    tracing::info!(scan_id = %scan_id, total = total, "CIDR scan probing {} hosts", total);

    let mut handles = Vec::new();
    for ip in hosts {
        let sem = semaphore.clone();
        let pool_clone = pool.clone();
        let h = task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            probe_and_store(pool_clone, scan_id, ip, port).await
        });
        handles.push(h);
    }

    for h in handles {
        let _ = h.await;
    }

    tracing::info!(scan_id = %scan_id, "CIDR scan complete");
}

/// Probe a single IP:port and store the result if the port is open.
async fn probe_and_store(pool: sqlx::PgPool, scan_id: Uuid, ip: IpAddr, port: u16) -> Option<()> {
    let addr = format!("{ip}:{port}");

    // TCP connect probe (blocking, run in thread pool)
    // TCP connect probe (blocking, run in thread pool)
    let addr_clone = addr.clone();
    let open = task::spawn_blocking(move || {
        TcpStream::connect_timeout(
            &match addr_clone.parse() {
                Ok(a) => a,
                Err(_) => return false,
            },
            Duration::from_secs(PROBE_TIMEOUT_SECS),
        )
        .is_ok()
    })
    .await
    .unwrap_or(false);

    if !open {
        return None;
    }

    // Reverse DNS lookup (best-effort)
    let ip_clone = ip;
    let fqdn = task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        let addr = format!("{ip_clone}:{port}");
        addr.to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .and_then(|_| dns_lookup_for_ip(ip_clone))
    })
    .await
    .ok()
    .flatten();

    let _ = sqlx::query(
        r#"INSERT INTO discovery_results (scan_id, ip_address, fqdn, agent_port)
           VALUES ($1, $2::inet, $3, $4)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(scan_id)
    .bind(ip.to_string())
    .bind(fqdn)
    .bind(port as i32)
    .execute(&pool)
    .await;

    tracing::debug!(ip = %ip, port = port, "Discovered agent");
    Some(())
}

/// Simple reverse DNS lookup.
fn dns_lookup_for_ip(ip: IpAddr) -> Option<String> {
    use std::net::{SocketAddr, ToSocketAddrs};
    let _addr = SocketAddr::new(ip, 0);
    // Standard library doesn't have reverse lookup; use getaddrinfo via format
    let host = format!("{ip}");
    // Best-effort: try to resolve numeric address to hostname
    (host + ":0")
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|a| a.ip().to_string())
        .filter(|s| s != &ip.to_string())
}

// ── GET /api/v1/discovery/:scan_id ────────────────────────────────────────────

async fn get_scan_results(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<Vec<DiscoveryResult>>, (StatusCode, Json<Value>)> {
    sqlx::query_as::<_, DiscoveryResult>(
        r#"SELECT id, scan_id, host(ip_address)::text AS ip_address, fqdn,
                  agent_version, os_name, agent_port, discovered_at, registered
           FROM discovery_results
           WHERE scan_id = $1
           ORDER BY ip_address"#,
    )
    .bind(scan_id)
    .fetch_all(&state.db)
    .await
    .map(Json)
    .map_err(|e| {
        tracing::error!(error = %e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": "Database error" } })),
        )
    })
}

// ── POST /api/v1/discovery/:id/register ──────────────────────────────────────

async fn register_discovered_host(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<RegisterDiscoveredRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !auth.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "forbidden", "message": "Write access required" } })),
        ));
    }

    // Fetch discovery result
    let result: Option<DiscoveryResult> = sqlx::query_as(
        r#"SELECT id, scan_id, host(ip_address)::text AS ip_address, fqdn,
                  agent_version, os_name, agent_port, discovered_at, registered
           FROM discovery_results WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "internal_error", "message": e.to_string() } })),
        )
    })?;

    let result = result.ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": { "code": "not_found", "message": "Discovery result not found" } }))
    ))?;

    let fqdn = result.fqdn.as_deref().unwrap_or(&result.ip_address);
    let display_name = req.display_name.as_deref().unwrap_or(fqdn);

    let host_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO hosts (fqdn, ip_address, display_name, agent_port)
           VALUES ($1, $2::inet, $3, $4)
           ON CONFLICT DO NOTHING
           RETURNING id"#,
    )
    .bind(fqdn)
    .bind(&result.ip_address)
    .bind(display_name)
    .bind(result.agent_port)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": { "code": "conflict", "message": e.to_string() } })),
        )
    })?;

    // Assign to groups
    if let Some(group_ids) = &req.group_ids {
        for gid in group_ids {
            let _ = sqlx::query("INSERT INTO host_groups (host_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(host_id).bind(gid).execute(&state.db).await;
        }
    }

    // Mark as registered
    let _ = sqlx::query("UPDATE discovery_results SET registered = TRUE WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await;

    log_event(
        &state.db,
        AuditAction::HostRegistered,
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&host_id.to_string()),
        json!({ "from_discovery": true, "ip": result.ip_address }),
        None,
        None,
    )
    .await;

    Ok(Json(
        json!({ "host_id": host_id, "message": "Host registered from discovery" }),
    ))
}
