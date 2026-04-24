//! Report generation endpoints.
//!
//! GET /api/v1/reports/compliance?format=csv|pdf&from=...&to=...&group_id=...
//! GET /api/v1/reports/patch-history?format=csv|pdf&from=...&to=...
//! GET /api/v1/reports/vulnerability?format=csv|pdf&from=...&to=...
//! GET /api/v1/reports/audit?format=csv|pdf&from=...&to=...

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use pm_reports::{ReportParams, ReportType};

use crate::AppState;

#[derive(serde::Deserialize)]
struct ReportQuery {
    /// "csv" or "pdf" (defaults to "csv")
    format: Option<String>,
    from: Option<chrono::DateTime<chrono::Utc>>,
    to: Option<chrono::DateTime<chrono::Utc>>,
    group_id: Option<uuid::Uuid>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/compliance", get(compliance_report))
        .route("/patch-history", get(patch_history_report))
        .route("/vulnerability", get(vulnerability_report))
        .route("/audit", get(audit_report))
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

async fn run_report(
    db: sqlx::PgPool,
    params: ReportParams,
    use_pdf: bool,
    csv_name: &'static str,
    pdf_name: &'static str,
) -> Response {
    let (ct, disposition, result) = if use_pdf {
        let disp = format!("attachment; filename=\"{}\"", pdf_name);
        let data = pm_reports::generate_pdf(&db, &params).await;
        ("application/pdf", disp, data)
    } else {
        let disp = format!("attachment; filename=\"{}\"", csv_name);
        let data = pm_reports::generate_csv(&db, &params).await;
        ("text/csv; charset=utf-8", disp, data)
    };

    match result {
        Ok(bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition)
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            (headers, Bytes::from(bytes)).into_response()
        },
        Err(e) => {
            tracing::error!(error = %e, "report generation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Report error: {}", e),
            )
                .into_response()
        },
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn compliance_report(
    State(state): State<AppState>,
    Query(q): Query<ReportQuery>,
) -> Response {
    let params = ReportParams {
        report_type: ReportType::Compliance,
        from: q.from,
        to: q.to,
        group_id: q.group_id,
    };
    let use_pdf = matches!(q.format.as_deref(), Some("pdf"));
    run_report(
        state.db,
        params,
        use_pdf,
        "compliance-report.csv",
        "compliance-report.pdf",
    )
    .await
}

async fn patch_history_report(
    State(state): State<AppState>,
    Query(q): Query<ReportQuery>,
) -> Response {
    let params = ReportParams {
        report_type: ReportType::PatchHistory,
        from: q.from,
        to: q.to,
        group_id: q.group_id,
    };
    let use_pdf = matches!(q.format.as_deref(), Some("pdf"));
    run_report(
        state.db,
        params,
        use_pdf,
        "patch-history-report.csv",
        "patch-history-report.pdf",
    )
    .await
}

async fn vulnerability_report(
    State(state): State<AppState>,
    Query(q): Query<ReportQuery>,
) -> Response {
    let params = ReportParams {
        report_type: ReportType::Vulnerability,
        from: q.from,
        to: q.to,
        group_id: q.group_id,
    };
    let use_pdf = matches!(q.format.as_deref(), Some("pdf"));
    run_report(
        state.db,
        params,
        use_pdf,
        "vulnerability-report.csv",
        "vulnerability-report.pdf",
    )
    .await
}

async fn audit_report(State(state): State<AppState>, Query(q): Query<ReportQuery>) -> Response {
    let params = ReportParams {
        report_type: ReportType::Audit,
        from: q.from,
        to: q.to,
        group_id: q.group_id,
    };
    let use_pdf = matches!(q.format.as_deref(), Some("pdf"));
    run_report(
        state.db,
        params,
        use_pdf,
        "audit-report.csv",
        "audit-report.pdf",
    )
    .await
}
