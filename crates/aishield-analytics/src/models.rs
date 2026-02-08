use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub api_key_hash: String,
}

/// Request payload for scan ingestion
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngestScanRequest {
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    pub repo_id: Option<String>,
    pub repo_name: String,
    pub branch: Option<String>,
    pub commit_sha: Option<String>,
    pub target_path: String,
    pub cli_version: Option<String>,
    pub ci_run_id: Option<String>,
    pub user_email: Option<String>,
    pub scan_result: ScanResultSummary,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanResultSummary {
    pub total_findings: i32,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
    pub ai_estimated_count: i32,
    pub scan_duration_ms: Option<i32>,
    pub files_scanned: Option<i32>,
    pub rules_loaded: Option<i32>,
    #[serde(default)]
    pub findings: Vec<FindingDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FindingDetail {
    pub rule_id: String,
    pub rule_title: Option<String>,
    pub severity: String,
    pub file_path: String,
    pub line_number: Option<i32>,
    pub snippet: Option<String>,
    pub ai_confidence: Option<f32>,
    pub ai_tendency: Option<String>,
    pub fix_suggestion: Option<String>,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
}

/// Response for successful scan ingestion
#[derive(Debug, Serialize)]
pub struct IngestScanResponse {
    pub scan_id: Uuid,
    pub ingested_at: String,
    pub findings_stored: usize,
}

/// Analytics summary response
#[derive(Debug, Serialize)]
pub struct AnalyticsSummary {
    pub period: String,
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    pub summary: SummaryStats,
    pub trend: Option<TrendStats>,
    pub time_series: Vec<TimeSeriesPoint>,
    pub top_rules: Vec<TopRule>,
    pub top_repos: Vec<TopRepo>,
}

#[derive(Debug, Serialize)]
pub struct SummaryStats {
    pub total_scans: i64,
    pub total_findings: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    pub ai_estimated: i64,
    pub ai_ratio: f64,
}

#[derive(Debug, Serialize)]
pub struct TrendStats {
    pub findings_delta_pct: Option<f64>,
    pub ai_ratio_delta_pct: Option<f64>,
    pub scans_delta_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct TimeSeriesPoint {
    pub date: String,
    pub scans: i64,
    pub findings: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    pub ai_estimated: i64,
    pub high_or_above: i64,
    pub ai_ratio: f64,
}

#[derive(Debug, Serialize)]
pub struct TopRule {
    pub rule_id: String,
    pub rule_title: Option<String>,
    pub count: i64,
    pub severity: String,
}

#[derive(Debug, Serialize)]
pub struct TopRepo {
    pub repo_id: String,
    pub repo_name: String,
    pub scans: i64,
    pub findings: i64,
    pub ai_ratio: f64,
}

/// Query parameters for analytics endpoints
#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    pub repo_id: Option<String>,
    #[serde(default = "default_days")]
    pub days: i32,
    #[serde(default = "default_limit")]
    pub limit: i32,
}

fn default_days() -> i32 {
    30
}

fn default_limit() -> i32 {
    10
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub service: String,
    pub version: String,
}
