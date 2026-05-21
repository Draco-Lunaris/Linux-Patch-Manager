//! pm-reports — CSV and PDF report generation.
//!
//! Uses printpdf + plotters for in-process PDF with charts.
pub mod csv;
pub mod pdf;

pub use csv::generate_csv;
pub use pdf::generate_pdf;

/// The type of report to generate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportType {
    Compliance,
    PatchHistory,
    Vulnerability,
    Audit,
}

/// Parameters controlling report generation.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ReportParams {
    pub report_type: ReportType,
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    pub group_id: Option<uuid::Uuid>,
}
