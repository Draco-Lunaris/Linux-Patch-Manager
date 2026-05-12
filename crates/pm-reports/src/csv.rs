//! CSV report generation for pm-reports.

use crate::{ReportParams, ReportType};
use anyhow::Context;

/// Generate a CSV report and return the raw bytes.
pub async fn generate_csv(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    match params.report_type {
        ReportType::Compliance => compliance_csv(pool, params).await,
        ReportType::PatchHistory => patch_history_csv(pool, params).await,
        ReportType::Vulnerability => vulnerability_csv(pool, params).await,
        ReportType::Audit => audit_csv(pool, params).await,
    }
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

async fn compliance_csv(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    let rows = if let Some(gid) = params.group_id {
        sqlx::query(
            "
SELECT
    h.id::text            AS host_id,
    h.display_name,
    h.fqdn,
    h.health_status::text AS health_status,
    h.last_patch_at,
    COALESCE(jsonb_array_length(pd.installed_packages), 0)  AS total_packages,
    COALESCE(pd.patch_count, 0) AS pending_patches,
    (CASE WHEN COALESCE(jsonb_array_length(pd.installed_packages), 0) = 0 THEN 100.0
          ELSE ROUND(CAST((1.0 - pd.patch_count::float / NULLIF(jsonb_array_length(pd.installed_packages), 0)) * 100 AS numeric), 1)
    END)::float8 AS compliance_pct,
    COALESCE(string_agg(DISTINCT g.name, ', '), '') AS group_names
FROM hosts h
LEFT JOIN host_patch_data pd ON pd.host_id = h.id
LEFT JOIN host_groups hg ON hg.host_id = h.id
LEFT JOIN groups g ON g.id = hg.group_id
WHERE h.id IN (
    SELECT host_id FROM host_groups WHERE group_id = $1
)
 GROUP BY h.id, h.health_status, pd.installed_packages, pd.patch_count
ORDER BY compliance_pct ASC
",
        )
        .bind(gid)
        .fetch_all(pool)
        .await
        .context("compliance query (group filter) failed")?
    } else {
        sqlx::query(
            "
SELECT
    h.id::text            AS host_id,
    h.display_name,
    h.fqdn,
    h.health_status::text AS health_status,
    h.last_patch_at,
    COALESCE(jsonb_array_length(pd.installed_packages), 0)  AS total_packages,
    COALESCE(pd.patch_count, 0) AS pending_patches,
    (CASE WHEN COALESCE(jsonb_array_length(pd.installed_packages), 0) = 0 THEN 100.0
          ELSE ROUND(CAST((1.0 - pd.patch_count::float / NULLIF(jsonb_array_length(pd.installed_packages), 0)) * 100 AS numeric), 1)
    END)::float8 AS compliance_pct,
    COALESCE(string_agg(DISTINCT g.name, ', '), '') AS group_names
FROM hosts h
LEFT JOIN host_patch_data pd ON pd.host_id = h.id
LEFT JOIN host_groups hg ON hg.host_id = h.id
LEFT JOIN groups g ON g.id = hg.group_id
 GROUP BY h.id, h.health_status, pd.installed_packages, pd.patch_count
ORDER BY compliance_pct ASC
",
        )
        .fetch_all(pool)
        .await
        .context("compliance query failed")?
    };

    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&[
        "host_id",
        "display_name",
        "fqdn",
        "group_names",
        "total_packages",
        "pending_patches",
        "compliance_pct",
        "last_patch_at",
        "health_status",
    ])?;

    for row in &rows {
        use sqlx::Row;
        let host_id: String = row.try_get("host_id").unwrap_or_default();
        let display_name: String = row.try_get("display_name").unwrap_or_default();
        let fqdn: String = row.try_get("fqdn").unwrap_or_default();
        let group_names: String = row.try_get("group_names").unwrap_or_default();
        let total_packages: i64 = row.try_get("total_packages").unwrap_or(0);
        let pending_patches: i64 = row.try_get("pending_patches").unwrap_or(0);
        let compliance_pct: f64 = row.try_get("compliance_pct").unwrap_or(0.0);
        let last_patch_at: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("last_patch_at").unwrap_or(None);
        let health_status: String = row.try_get("health_status").unwrap_or_default();

        wtr.write_record(&[
            host_id,
            display_name,
            fqdn,
            group_names,
            total_packages.to_string(),
            pending_patches.to_string(),
            format!("{:.1}", compliance_pct),
            last_patch_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
            health_status,
        ])?;
    }

    Ok(wtr.into_inner().context("csv flush failed")?)
}

// ---------------------------------------------------------------------------
// Patch history
// ---------------------------------------------------------------------------

async fn patch_history_csv(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    let rows = sqlx::query(
        "
SELECT
    pj.id::text        AS job_id,
    pj.kind::text      AS job_kind,
    pj.status::text    AS job_status,
    h.display_name,
    h.fqdn,
    jsonb_array_length(COALESCE(pj.patch_selection->'packages', '[]'::jsonb)) AS package_count,
    pjh.started_at,
    pjh.completed_at,
    EXTRACT(EPOCH FROM (pjh.completed_at - pjh.started_at))::bigint AS duration_seconds,
    COALESCE(u.username, 'system') AS operator
FROM patch_job_hosts pjh
JOIN patch_jobs pj ON pj.id = pjh.job_id
JOIN hosts h ON h.id = pjh.host_id
LEFT JOIN users u ON u.id = pj.created_by_user_id
WHERE ($1::timestamptz IS NULL OR pjh.started_at >= $1)
  AND ($2::timestamptz IS NULL OR pjh.started_at <= $2)
ORDER BY pjh.started_at DESC
",
    )
    .bind(params.from)
    .bind(params.to)
    .fetch_all(pool)
    .await
    .context("patch history query failed")?;

    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&[
        "job_id",
        "job_kind",
        "job_status",
        "host_display_name",
        "host_fqdn",
        "package_count",
        "started_at",
        "completed_at",
        "duration_seconds",
        "operator",
    ])?;

    for row in &rows {
        use sqlx::Row;
        let job_id: String = row.try_get("job_id").unwrap_or_default();
        let job_kind: String = row.try_get("job_kind").unwrap_or_default();
        let job_status: String = row.try_get("job_status").unwrap_or_default();
        let display_name: String = row.try_get("display_name").unwrap_or_default();
        let fqdn: String = row.try_get("fqdn").unwrap_or_default();
        let package_count: i64 = row.try_get("package_count").unwrap_or(0);
        let started_at: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("started_at").unwrap_or(None);
        let completed_at: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("completed_at").unwrap_or(None);
        let duration_seconds: Option<i64> = row.try_get("duration_seconds").unwrap_or(None);
        let operator: String = row.try_get("operator").unwrap_or_default();

        wtr.write_record(&[
            job_id,
            job_kind,
            job_status,
            display_name,
            fqdn,
            package_count.to_string(),
            started_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
            completed_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
            duration_seconds.unwrap_or(0).to_string(),
            operator,
        ])?;
    }

    Ok(wtr.into_inner().context("csv flush failed")?)
}

// ---------------------------------------------------------------------------
// Vulnerability
// ---------------------------------------------------------------------------

async fn vulnerability_csv(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&[
        "host_id",
        "display_name",
        "fqdn",
        "cve_id",
        "package_name",
        "severity",
        "available_version",
        "last_seen_at",
    ])?;

    let result = sqlx::query(
        "
SELECT
    h.id::text        AS host_id,
    h.display_name,
    h.fqdn,
    cve_id,
    patch->>'name'    AS package_name,
    patch->>'severity' AS severity,
    patch->>'available_version' AS available_version,
    pd.polled_at      AS last_seen_at
FROM hosts h
JOIN host_patch_data pd ON pd.host_id = h.id
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(pd.available_patches, '[]'::jsonb)) AS patch
CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(patch->'cve_ids', '[]'::jsonb)) AS cve_id
WHERE ($1::timestamptz IS NULL OR pd.polled_at >= $1)
  AND ($2::timestamptz IS NULL OR pd.polled_at <= $2)
ORDER BY
    CASE patch->>'severity'
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        ELSE 4
    END,
    h.display_name
",
    )
    .bind(params.from)
    .bind(params.to)
    .fetch_all(pool)
    .await;

    match result {
        Ok(rows) => {
            for row in &rows {
                use sqlx::Row;
                let host_id: String = row.try_get("host_id").unwrap_or_default();
                let display_name: String = row.try_get("display_name").unwrap_or_default();
                let fqdn: String = row.try_get("fqdn").unwrap_or_default();
                let cve_id: String = row.try_get("cve_id").unwrap_or_default();
                let package_name: String = row.try_get("package_name").unwrap_or_default();
                let severity: String = row.try_get("severity").unwrap_or_default();
                let available_version: String =
                    row.try_get("available_version").unwrap_or_default();
                let last_seen_at: Option<chrono::DateTime<chrono::Utc>> =
                    row.try_get("last_seen_at").unwrap_or(None);

                wtr.write_record(&[
                    host_id,
                    display_name,
                    fqdn,
                    cve_id,
                    package_name,
                    severity,
                    available_version,
                    last_seen_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
                ])?;
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "vulnerability query failed — returning header-only CSV");
            // Return header-only CSV (no invalid comment rows)
        },
    }

    Ok(wtr.into_inner().context("csv flush failed")?)
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

async fn audit_csv(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    let rows = sqlx::query(
        "
SELECT
    id::text            AS id,
    created_at,
    action::text        AS action,
    actor_username,
    target_type,
    target_id,
    ip_address::text    AS ip_address,
    request_id
FROM audit_log
WHERE ($1::timestamptz IS NULL OR created_at >= $1)
  AND ($2::timestamptz IS NULL OR created_at <= $2)
ORDER BY created_at DESC
LIMIT 10000
",
    )
    .bind(params.from)
    .bind(params.to)
    .fetch_all(pool)
    .await
    .context("audit query failed")?;

    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&[
        "id",
        "created_at",
        "action",
        "actor_username",
        "target_type",
        "target_id",
        "ip_address",
        "request_id",
    ])?;

    for row in &rows {
        use sqlx::Row;
        let id: String = row.try_get("id").unwrap_or_default();
        let created_at: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("created_at").unwrap_or(None);
        let action: String = row.try_get("action").unwrap_or_default();
        let actor_username: String = row.try_get("actor_username").unwrap_or_default();
        let target_type: String = row.try_get("target_type").unwrap_or_default();
        let target_id: String = row.try_get("target_id").unwrap_or_default();
        let ip_address: String = row.try_get("ip_address").unwrap_or_default();
        let request_id: String = row.try_get("request_id").unwrap_or_default();

        wtr.write_record(&[
            id,
            created_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
            action,
            actor_username,
            target_type,
            target_id,
            ip_address,
            request_id,
        ])?;
    }

    Ok(wtr.into_inner().context("csv flush failed")?)
}
