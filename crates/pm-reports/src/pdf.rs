//! PDF report generation for pm-reports.
//!
//! Uses printpdf for document structure and plotters + image for embedded charts.

use crate::{ReportParams, ReportType};
use anyhow::Context;
use plotters::prelude::*;
use printpdf::{
    BuiltinFont, ColorBits, ColorSpace, Image, ImageTransform, ImageXObject, IndirectFontRef, Mm,
    PdfDocument, PdfLayerIndex, PdfLayerReference, PdfPageIndex, Px,
};

const PAGE_W: f32 = 297.0; // A4 landscape width  (mm)
const PAGE_H: f32 = 210.0; // A4 landscape height (mm)
const MARGIN: f32 = 10.0;
const ROW_H: f32 = 6.0;
const HEADER_Y_START: f32 = 190.0;
const NEW_PAGE_THRESHOLD: f32 = 20.0;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Generate a PDF report and return the raw bytes.
pub async fn generate_pdf(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    match params.report_type {
        ReportType::Compliance => compliance_pdf(pool, params).await,
        ReportType::PatchHistory => patch_history_pdf(pool, params).await,
        ReportType::Vulnerability => vulnerability_pdf(pool, params).await,
        ReportType::Audit => audit_pdf(pool, params).await,
    }
}

// ---------------------------------------------------------------------------
// Chart helper
// ---------------------------------------------------------------------------

/// Render a bar chart to an in-memory PNG and return the raw PNG bytes.
fn render_bar_chart(
    labels: &[String],
    values: &[f64],
    title: &str,
) -> anyhow::Result<(Vec<u8>, u32, u32)> {
    const W: u32 = 800;
    const H: u32 = 400;

    let mut pixel_buf = vec![0u8; (W * H * 3) as usize];

    {
        let root = BitMapBackend::with_buffer(&mut pixel_buf, (W, H)).into_drawing_area();
        root.fill(&WHITE)?;

        let max_val = values.iter().cloned().fold(0.0_f64, f64::max).max(1.0);
        let n = labels.len().max(1);

        let mut chart = ChartBuilder::on(&root)
            .caption(title, ("sans-serif", 20).into_font())
            .margin(20u32)
            .x_label_area_size(60u32)
            .y_label_area_size(50u32)
            .build_cartesian_2d(0..n, 0.0..max_val * 1.1)?;

        chart
            .configure_mesh()
            .x_labels(n.min(20))
            .x_label_formatter(&|idx| {
                labels
                    .get(*idx)
                    .map(|s| {
                        if s.len() > 12 {
                            s[..12].to_string()
                        } else {
                            s.clone()
                        }
                    })
                    .unwrap_or_default()
            })
            .y_desc("Value")
            .draw()?;

        chart.draw_series((0..n).map(|i| {
            let v = values.get(i).copied().unwrap_or(0.0);
            let color = if v >= 90.0 {
                RGBColor(76, 175, 80)
            } else if v >= 70.0 {
                RGBColor(255, 193, 7)
            } else {
                RGBColor(244, 67, 54)
            };
            Rectangle::new([(i, 0.0), (i + 1, v)], color.filled())
        }))?;

        root.present()?;
    }

    // Return raw RGB pixels + dimensions for direct PDF embedding
    Ok((pixel_buf, W, H))
}

// ---------------------------------------------------------------------------
// PDF builder
// ---------------------------------------------------------------------------

struct PdfBuilder {
    doc: printpdf::PdfDocumentReference,
    font: IndirectFontRef,
    font_bold: IndirectFontRef,
    page_idx: PdfPageIndex,
    layer_idx: PdfLayerIndex,
    current_y: f32,
}

impl PdfBuilder {
    fn new(title: &str) -> anyhow::Result<Self> {
        let doc = PdfDocument::empty(title);
        let (page_idx, layer_idx) = doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
        Ok(Self {
            doc,
            font,
            font_bold,
            page_idx,
            layer_idx,
            current_y: HEADER_Y_START,
        })
    }

    fn layer(&self) -> PdfLayerReference {
        self.doc.get_page(self.page_idx).get_layer(self.layer_idx)
    }

    fn write_text(&self, s: &str, font_size: f32, x: f32, y: f32, bold: bool) {
        let f = if bold { &self.font_bold } else { &self.font };
        self.layer().use_text(s, font_size, Mm(x), Mm(y), f);
    }

    fn new_page(&mut self) {
        let (pi, li) = self.doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
        self.page_idx = pi;
        self.layer_idx = li;
        self.current_y = HEADER_Y_START;
    }

    fn ensure_space(&mut self, needed: f32) {
        if self.current_y - needed < NEW_PAGE_THRESHOLD {
            self.new_page();
        }
    }

    fn table_row(&mut self, cells: &[&str], col_x: &[f32], font_size: f32, bold: bool) {
        self.ensure_space(ROW_H);
        let y = self.current_y;
        for (i, cell) in cells.iter().enumerate() {
            let x = col_x.get(i).copied().unwrap_or(MARGIN);
            let s = if cell.len() > 30 { &cell[..30] } else { cell };
            self.write_text(s, font_size, x, y, bold);
        }
        self.current_y -= ROW_H;
    }

    fn embed_image(
        &self,
        raw_rgb: Vec<u8>,
        img_w: u32,
        img_h: u32,
        x_mm: f32,
        y_mm: f32,
        scale_x: f32,
        scale_y: f32,
    ) -> anyhow::Result<()> {
        let xobj = ImageXObject {
            width: Px(img_w as usize),
            height: Px(img_h as usize),
            color_space: ColorSpace::Rgb,
            bits_per_component: ColorBits::Bit8,
            interpolate: true,
            image_data: raw_rgb,
            image_filter: None,
            smask: None,
            clipping_bbox: None,
        };
        let pdf_img = Image::from(xobj);
        pdf_img.add_to_layer(
            self.layer(),
            ImageTransform {
                translate_x: Some(Mm(x_mm)),
                translate_y: Some(Mm(y_mm)),
                scale_x: Some(scale_x),
                scale_y: Some(scale_y),
                dpi: Some(150.0),
                ..Default::default()
            },
        );
        Ok(())
    }

    fn save(self) -> anyhow::Result<Vec<u8>> {
        Ok(self.doc.save_to_bytes()?)
    }
}

// ---------------------------------------------------------------------------
// Title page helper
// ---------------------------------------------------------------------------

fn write_title_page(pdf: &mut PdfBuilder, title: &str, params: &ReportParams) {
    pdf.write_text(title, 24.0, MARGIN, 160.0, true);
    pdf.write_text(
        &format!(
            "Generated: {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
        ),
        11.0,
        MARGIN,
        148.0,
        false,
    );
    if let Some(from) = params.from {
        pdf.write_text(
            &format!("From: {}", from.format("%Y-%m-%d")),
            10.0,
            MARGIN,
            140.0,
            false,
        );
    }
    if let Some(to) = params.to {
        pdf.write_text(
            &format!("To:   {}", to.format("%Y-%m-%d")),
            10.0,
            MARGIN,
            134.0,
            false,
        );
    }
    if let Some(gid) = params.group_id {
        pdf.write_text(&format!("Group: {}", gid), 10.0, MARGIN, 128.0, false);
    }
    pdf.new_page();
}

// ---------------------------------------------------------------------------
// Compliance PDF
// ---------------------------------------------------------------------------

async fn compliance_pdf(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    use sqlx::Row;
    let rows = if let Some(gid) = params.group_id {
        sqlx::query(
            "
SELECT h.display_name, h.fqdn,
    COALESCE(pd.total_packages,0) AS total_packages,
    COALESCE(pd.pending_patches,0) AS pending_patches,
    CASE WHEN COALESCE(pd.total_packages,0)=0 THEN 100.0
         ELSE ROUND((1.0-pd.pending_patches::float/NULLIF(pd.total_packages,0))*100,1)
    END AS compliance_pct,
    h.health_status::text AS health_status
FROM hosts h LEFT JOIN host_patch_data pd ON pd.host_id=h.id
WHERE h.id IN (SELECT host_id FROM host_groups WHERE group_id=$1)
GROUP BY h.id,pd.total_packages,pd.pending_patches
ORDER BY compliance_pct ASC",
        )
        .bind(gid)
        .fetch_all(pool)
        .await
        .context("compliance PDF query (group) failed")?
    } else {
        sqlx::query(
            "
SELECT h.display_name, h.fqdn,
    COALESCE(pd.total_packages,0) AS total_packages,
    COALESCE(pd.pending_patches,0) AS pending_patches,
    CASE WHEN COALESCE(pd.total_packages,0)=0 THEN 100.0
         ELSE ROUND((1.0-pd.pending_patches::float/NULLIF(pd.total_packages,0))*100,1)
    END AS compliance_pct,
    h.health_status::text AS health_status
FROM hosts h LEFT JOIN host_patch_data pd ON pd.host_id=h.id
GROUP BY h.id,pd.total_packages,pd.pending_patches
ORDER BY compliance_pct ASC",
        )
        .fetch_all(pool)
        .await
        .context("compliance PDF query failed")?
    };
    let labels: Vec<String> = rows
        .iter()
        .map(|r| r.try_get::<String, _>("display_name").unwrap_or_default())
        .collect();
    let values: Vec<f64> = rows
        .iter()
        .map(|r| r.try_get::<f64, _>("compliance_pct").unwrap_or(0.0))
        .collect();
    let mut pdf = PdfBuilder::new("Compliance Report")?;
    write_title_page(&mut pdf, "Compliance Report", params);
    let col_x: &[f32] = &[MARGIN, 65.0, 130.0, 165.0, 200.0, 235.0];
    pdf.table_row(
        &[
            "Host",
            "FQDN",
            "Total Pkgs",
            "Pending",
            "Compliance %",
            "Status",
        ],
        col_x,
        9.0,
        true,
    );
    for row in &rows {
        let name: String = row.try_get("display_name").unwrap_or_default();
        let fqdn: String = row.try_get("fqdn").unwrap_or_default();
        let total: i64 = row.try_get("total_packages").unwrap_or(0);
        let pend: i64 = row.try_get("pending_patches").unwrap_or(0);
        let pct: f64 = row.try_get("compliance_pct").unwrap_or(0.0);
        let status: String = row.try_get("health_status").unwrap_or_default();
        pdf.table_row(
            &[
                &name,
                &fqdn,
                &total.to_string(),
                &pend.to_string(),
                &format!("{:.1}%", pct),
                &status,
            ],
            col_x,
            8.0,
            false,
        );
    }
    if !labels.is_empty() {
        match render_bar_chart(&labels, &values, "Compliance % by Host") {
            Ok((raw, w, h)) => {
                pdf.new_page();
                pdf.write_text("Compliance Chart", 16.0, MARGIN, 200.0, true);
                if let Err(e) = pdf.embed_image(raw, w, h, MARGIN, 10.0, 0.18, 0.18) {
                    tracing::warn!(error = %e, "chart embed failed");
                }
            },
            Err(e) => tracing::warn!(error = %e, "chart render failed"),
        }
    }
    pdf.save()
}

// ---------------------------------------------------------------------------
// Patch history PDF
// ---------------------------------------------------------------------------

async fn patch_history_pdf(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    use sqlx::Row;
    let rows = sqlx::query(
        "
SELECT pj.kind::text AS job_kind, pj.status::text AS job_status,
    h.display_name, h.fqdn, pjh.started_at, pjh.completed_at,
    EXTRACT(EPOCH FROM (pjh.completed_at-pjh.started_at))::bigint AS duration_seconds,
    COALESCE(u.username,'system') AS operator
FROM patch_job_hosts pjh
JOIN patch_jobs pj ON pj.id=pjh.job_id
JOIN hosts h ON h.id=pjh.host_id
LEFT JOIN users u ON u.id=pj.created_by_user_id
WHERE ($1::timestamptz IS NULL OR pjh.started_at>=$1)
  AND ($2::timestamptz IS NULL OR pjh.started_at<=$2)
ORDER BY pjh.started_at DESC",
    )
    .bind(params.from)
    .bind(params.to)
    .fetch_all(pool)
    .await
    .context("patch history PDF query failed")?;
    let mut dc: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    for row in &rows {
        if let Ok(Some(s)) = row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("started_at") {
            *dc.entry(s.format("%Y-%m-%d").to_string()).or_insert(0.0) += 1.0;
        }
    }
    let cl: Vec<String> = dc.keys().cloned().collect();
    let cv: Vec<f64> = dc.values().cloned().collect();
    let mut pdf = PdfBuilder::new("Patch History Report")?;
    write_title_page(&mut pdf, "Patch History Report", params);
    let col_x: &[f32] = &[MARGIN, 45.0, 80.0, 115.0, 155.0, 200.0, 245.0, 270.0];
    pdf.table_row(
        &[
            "Kind",
            "Status",
            "Host",
            "FQDN",
            "Started",
            "Completed",
            "Dur(s)",
            "Operator",
        ],
        col_x,
        9.0,
        true,
    );
    for row in &rows {
        let kind: String = row.try_get("job_kind").unwrap_or_default();
        let status: String = row.try_get("job_status").unwrap_or_default();
        let name: String = row.try_get("display_name").unwrap_or_default();
        let fqdn: String = row.try_get("fqdn").unwrap_or_default();
        let started: String = row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("started_at")
            .unwrap_or(None)
            .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        let completed: String = row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at")
            .unwrap_or(None)
            .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        let dur: i64 = row.try_get("duration_seconds").unwrap_or(0);
        let op: String = row.try_get("operator").unwrap_or_default();
        pdf.table_row(
            &[
                &kind,
                &status,
                &name,
                &fqdn,
                &started,
                &completed,
                &dur.to_string(),
                &op,
            ],
            col_x,
            8.0,
            false,
        );
    }
    if !cl.is_empty() {
        match render_bar_chart(&cl, &cv, "Jobs per Day") {
            Ok((raw, w, h)) => {
                pdf.new_page();
                pdf.write_text("Patch Activity Chart", 16.0, MARGIN, 200.0, true);
                if let Err(e) = pdf.embed_image(raw, w, h, MARGIN, 10.0, 0.18, 0.18) {
                    tracing::warn!(error = %e, "chart embed failed");
                }
            },
            Err(e) => tracing::warn!(error = %e, "chart render failed"),
        }
    }
    pdf.save()
}

// ---------------------------------------------------------------------------
// Vulnerability PDF
// ---------------------------------------------------------------------------

async fn vulnerability_pdf(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    use sqlx::Row;
    // Query DB FIRST (before creating any non-Send PdfBuilder)
    let query_result = sqlx::query("
SELECT h.display_name, h.fqdn,
    cve.cve_id, cve.package_name, cve.severity, cve.available_version,
    pd.updated_at AS last_seen_at
FROM hosts h JOIN host_patch_data pd ON pd.host_id=h.id
CROSS JOIN LATERAL jsonb_to_recordset(COALESCE(pd.cve_data,'[]'::jsonb))
  AS cve(cve_id text,package_name text,severity text,available_version text)
WHERE ($1::timestamptz IS NULL OR pd.updated_at>=$1)
  AND ($2::timestamptz IS NULL OR pd.updated_at<=$2)
ORDER BY CASE cve.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
    h.display_name")
        .bind(params.from).bind(params.to).fetch_all(pool).await;
    // Now create PdfBuilder (non-Send Rc types) after all awaits
    let mut pdf = PdfBuilder::new("Vulnerability Report")?;
    write_title_page(&mut pdf, "Vulnerability Exposure Report", params);
    let col_x: &[f32] = &[MARGIN, 55.0, 100.0, 130.0, 175.0, 215.0, 255.0];
    pdf.table_row(
        &[
            "Host",
            "FQDN",
            "CVE ID",
            "Package",
            "Severity",
            "Fix Version",
            "Last Seen",
        ],
        col_x,
        9.0,
        true,
    );
    match query_result {
        Ok(rows) => {
            for row in &rows {
                let name: String = row.try_get("display_name").unwrap_or_default();
                let fqdn: String = row.try_get("fqdn").unwrap_or_default();
                let cve: String = row.try_get("cve_id").unwrap_or_default();
                let pkg: String = row.try_get("package_name").unwrap_or_default();
                let sev: String = row.try_get("severity").unwrap_or_default();
                let fix: String = row.try_get("available_version").unwrap_or_default();
                let seen: String = row
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_seen_at")
                    .unwrap_or(None)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default();
                pdf.table_row(
                    &[&name, &fqdn, &cve, &pkg, &sev, &fix, &seen],
                    col_x,
                    8.0,
                    false,
                );
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "vulnerability PDF query failed");
            let y = pdf.current_y;
            pdf.write_text(&format!("No data: {}", e), 10.0, MARGIN, y, false);
        },
    }
    pdf.save()
}

async fn audit_pdf(pool: &sqlx::PgPool, params: &ReportParams) -> anyhow::Result<Vec<u8>> {
    use sqlx::Row;
    let rows = sqlx::query(
        "
SELECT id::text AS id, created_at, action::text AS action,
    actor_username, target_type, target_id,
    ip_address::text AS ip_address, request_id
FROM audit_log
WHERE ($1::timestamptz IS NULL OR created_at>=$1)
  AND ($2::timestamptz IS NULL OR created_at<=$2)
ORDER BY created_at DESC LIMIT 10000",
    )
    .bind(params.from)
    .bind(params.to)
    .fetch_all(pool)
    .await
    .context("audit PDF query failed")?;
    let mut pdf = PdfBuilder::new("Audit Trail Report")?;
    write_title_page(&mut pdf, "Audit Trail Report", params);
    let col_x: &[f32] = &[MARGIN, 50.0, 95.0, 135.0, 175.0, 215.0, 255.0];
    pdf.table_row(
        &[
            "Timestamp",
            "Action",
            "Actor",
            "Target Type",
            "Target ID",
            "IP",
            "Request ID",
        ],
        col_x,
        9.0,
        true,
    );
    for row in &rows {
        let created: String = row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("created_at")
            .unwrap_or(None)
            .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        let action: String = row.try_get("action").unwrap_or_default();
        let actor: String = row.try_get("actor_username").unwrap_or_default();
        let ttype: String = row.try_get("target_type").unwrap_or_default();
        let tid: String = row.try_get("target_id").unwrap_or_default();
        let ip: String = row.try_get("ip_address").unwrap_or_default();
        let req: String = row.try_get("request_id").unwrap_or_default();
        pdf.table_row(
            &[&created, &action, &actor, &ttype, &tid, &ip, &req],
            col_x,
            8.0,
            false,
        );
    }
    pdf.save()
}
    if let Some(gid) = params.group_id {
        pdf.write_text(
            &format!("Group: {}", gid),
            10.0, MARGIN, 128.0, false,
        );
    }
    pdf.new_page();
}

// ---------------------------------------------------------------------------
// Compliance PDF
// ---------------------------------------------------------------------------

async fn compliance_pdf(
    pool: &sqlx::PgPool,
    params: &ReportParams,
) -> anyhow::Result<Vec<u8>> {
    use sqlx::Row;

    let rows = if let Some(gid) = params.group_id {
        sqlx::query("
SELECT h.display_name, h.fqdn,
    COALESCE(pd.total_packages, 0)  AS total_packages,
    COALESCE(pd.pending_patches, 0) AS pending_patches,
    CASE WHEN COALESCE(pd.total_packages,0) = 0 THEN 100.0
         ELSE ROUND((1.0 - pd.pending_patches::float / NULLIF(pd.total_packages,0)) * 100, 1)
    END AS compliance_pct,
    h.health_status::text AS health_status
FROM hosts h
LEFT JOIN host_patch_data pd ON pd.host_id = h.id
WHERE h.id IN (SELECT host_id FROM host_groups WHERE group_id = $1)
GROUP BY h.id, pd.total_packages, pd.pending_patches
ORDER BY compliance_pct ASC")
            .bind(gid).fetch_all(pool).await
            .context("compliance PDF query (group) failed")?
    } else {
        sqlx::query("
SELECT h.display_name, h.fqdn,
    COALESCE(pd.total_packages, 0)  AS total_packages,
    COALESCE(pd.pending_patches, 0) AS pending_patches,
    CASE WHEN COALESCE(pd.total_packages,0) = 0 THEN 100.0
         ELSE ROUND((1.0 - pd.pending_patches::float / NULLIF(pd.total_packages,0)) * 100, 1)
    END AS compliance_pct,
    h.health_status::text AS health_status
FROM hosts h
LEFT JOIN host_patch_data pd ON pd.host_id = h.id
GROUP BY h.id, pd.total_packages, pd.pending_patches
ORDER BY compliance_pct ASC")
            .fetch_all(pool).await
            .context("compliance PDF query failed")?
    };

    let labels: Vec<String> = rows.iter()
        .map(|r| r.try_get::<String, _>("display_name").unwrap_or_default())
        .collect();
    let values: Vec<f64> = rows.iter()
        .map(|r| r.try_get::<f64, _>("compliance_pct").unwrap_or(0.0))
        .collect();

    let mut pdf = PdfBuilder::new("Compliance Report")?;
    write_title_page(&mut pdf, "Compliance Report", params);

    let col_x: &[f32] = &[MARGIN, 65.0, 130.0, 165.0, 195.0, 230.0];
    pdf.table_row(&["Host", "FQDN", "Total Pkgs", "Pending", "Compliance %", "Status"], col_x, 9.0, true);
    for row in &rows {
        let name: String   = row.try_get("display_name").unwrap_or_default();
        let fqdn: String   = row.try_get("fqdn").unwrap_or_default();
        let total: i64     = row.try_get("total_packages").unwrap_or(0);
        let pending: i64   = row.try_get("pending_patches").unwrap_or(0);
        let pct: f64       = row.try_get("compliance_pct").unwrap_or(0.0);
        let status: String = row.try_get("health_status").unwrap_or_default();
        pdf.table_row(
            &[&name, &fqdn, &total.to_string(), &pending.to_string(), &format!("{:.1}%", pct), &status],
            col_x, 8.0, false,
        );
    }
    if !labels.is_empty() {
        match render_bar_chart(&labels, &values, "Compliance % by Host") {
            Ok(png) => {
                pdf.new_page();
                pdf.write_text("Compliance Chart", 16.0, MARGIN, 200.0, true);
                if let Err(e) = pdf.embed_image(&png, MARGIN, 10.0, 0.18, 0.18) {
                    tracing::warn!(error = %e, "compliance chart embed failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "compliance chart render failed"),
        }
    }
    pdf.save()
}

// ---------------------------------------------------------------------------
// Patch history PDF
// ---------------------------------------------------------------------------

async fn patch_history_pdf(
    pool: &sqlx::PgPool,
    params: &ReportParams,
) -> anyhow::Result<Vec<u8>> {
    use sqlx::Row;

    let rows = sqlx::query("
SELECT pj.kind::text AS job_kind, pj.status::text AS job_status,
    h.display_name, h.fqdn, pjh.started_at, pjh.completed_at,
    EXTRACT(EPOCH FROM (pjh.completed_at - pjh.started_at))::bigint AS duration_seconds,
    COALESCE(u.username, 'system') AS operator
FROM patch_job_hosts pjh
JOIN patch_jobs pj ON pj.id = pjh.job_id
JOIN hosts h ON h.id = pjh.host_id
LEFT JOIN users u ON u.id = pj.created_by_user_id
WHERE ($1::timestamptz IS NULL OR pjh.started_at >= $1)
  AND ($2::timestamptz IS NULL OR pjh.started_at <= $2)
ORDER BY pjh.started_at DESC")
        .bind(params.from).bind(params.to)
        .fetch_all(pool).await
        .context("patch history PDF query failed")?;

    let mut day_counts: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    for row in &rows {
        if let Ok(Some(started)) = row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("started_at") {
            *day_counts.entry(started.format("%Y-%m-%d").to_string()).or_insert(0.0) += 1.0;
        }
    }
    let chart_labels: Vec<String> = day_counts.keys().cloned().collect();
    let chart_values: Vec<f64>    = day_counts.values().cloned().collect();

    let mut pdf = PdfBuilder::new("Patch History Report")?;
    write_title_page(&mut pdf, "Patch History Report", params);

    let col_x: &[f32] = &[MARGIN, 45.0, 80.0, 115.0, 155.0, 200.0, 245.0, 270.0];
    pdf.table_row(&["Kind","Status","Host","FQDN","Started","Completed","Dur(s)","Operator"], col_x, 9.0, true);
    for row in &rows {
        let kind: String   = row.try_get("job_kind").unwrap_or_default();
        let status: String = row.try_get("job_status").unwrap_or_default();
        let name: String   = row.try_get("display_name").unwrap_or_default();
        let fqdn: String   = row.try_get("fqdn").unwrap_or_default();
        let started: String = row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("started_at")
            .unwrap_or(None).map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default();
        let completed: String = row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at")
            .unwrap_or(None).map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default();
        let dur: i64   = row.try_get("duration_seconds").unwrap_or(0);
        let op: String = row.try_get("operator").unwrap_or_default();
        pdf.table_row(&[&kind,&status,&name,&fqdn,&started,&completed,&dur.to_string(),&op], col_x, 8.0, false);
    }
    if !chart_labels.is_empty() {
        match render_bar_chart(&chart_labels, &chart_values, "Jobs per Day") {
            Ok(png) => {
                pdf.new_page();
                pdf.write_text("Patch Activity Chart", 16.0, MARGIN, 200.0, true);
                if let Err(e) = pdf.embed_image(&png, MARGIN, 10.0, 0.18, 0.18) {
                    tracing::warn!(error = %e, "patch history chart embed failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "patch history chart render failed"),
        }
    }
    pdf.save()
}

// ---------------------------------------------------------------------------
// Vulnerability PDF
// ---------------------------------------------------------------------------

async fn vulnerability_pdf(
    pool: &sqlx::PgPool,
    params: &ReportParams,
) -> anyhow::Result<Vec<u8>> {
    use sqlx::Row;

    let mut pdf = PdfBuilder::new("Vulnerability Report")?;
    write_title_page(&mut pdf, "Vulnerability Exposure Report", params);

    let col_x: &[f32] = &[MARGIN, 55.0, 100.0, 130.0, 175.0, 215.0, 255.0];
    pdf.table_row(&["Host","FQDN","CVE ID","Package","Severity","Fix Version","Last Seen"], col_x, 9.0, true);

    match sqlx::query("
SELECT h.display_name, h.fqdn,
    cve.cve_id, cve.package_name, cve.severity, cve.available_version,
    pd.updated_at AS last_seen_at
FROM hosts h
JOIN host_patch_data pd ON pd.host_id = h.id
CROSS JOIN LATERAL jsonb_to_recordset(COALESCE(pd.cve_data, '[]'::jsonb))
  AS cve(cve_id text, package_name text, severity text, available_version text)
WHERE ($1::timestamptz IS NULL OR pd.updated_at >= $1)
  AND ($2::timestamptz IS NULL OR pd.updated_at <= $2)
ORDER BY CASE cve.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, h.display_name")
        .bind(params.from).bind(params.to)
        .fetch_all(pool).await
    {
        Ok(rows) => {
            for row in &rows {
                let name: String   = row.try_get("display_name").unwrap_or_default();
                let fqdn: String   = row.try_get("fqdn").unwrap_or_default();
                let cve_id: String = row.try_get("cve_id").unwrap_or_default();
                let pkg: String    = row.try_get("package_name").unwrap_or_default();
                let sev: String    = row.try_get("severity").unwrap_or_default();
                let fix: String    = row.try_get("available_version").unwrap_or_default();
                let seen: String   = row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_seen_at")
                    .unwrap_or(None).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default();
                pdf.table_row(&[&name,&fqdn,&cve_id,&pkg,&sev,&fix,&seen], col_x, 8.0, false);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "vulnerability PDF query failed");
            let y = pdf.current_y;
            pdf.write_text(&format!("No data available: {}", e), 10.0, MARGIN, y, false);
        }
    }
    pdf.save()
}
