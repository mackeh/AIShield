use crate::{auth, db, models::*};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use csv::Writer;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Custom error type for API handlers
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.message
        });
        (self.status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        error!("Database error: {}", err);
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Database error".to_string(),
        }
    }
}

/// Extract and verify API key from headers
fn verify_auth(headers: &HeaderMap, expected_hash: &str) -> Result<(), ApiError> {
    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError {
            status: StatusCode::UNAUTHORIZED,
            message: "Missing x-api-key header".to_string(),
        })?;

    if !auth::verify_api_key(api_key, expected_hash) {
        warn!("Invalid API key attempt");
        return Err(ApiError {
            status: StatusCode::UNAUTHORIZED,
            message: "Invalid API key".to_string(),
        });
    }

    Ok(())
}

/// Health check endpoint (no authentication required)
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "aishield-analytics".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// POST /api/v1/scans/ingest - Ingest a scan result
pub async fn ingest_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<IngestScanRequest>,
) -> Result<Json<IngestScanResponse>, ApiError> {
    // Verify authentication
    verify_auth(&headers, &state.api_key_hash)?;

    debug!(
        "Ingesting scan for repo: {}, findings: {}",
        payload.repo_name, payload.scan_result.total_findings
    );

    // Insert scan record
    let scan_id = db::insert_scan(&state.db_pool, &payload).await?;

    // Insert findings (if any)
    let findings_count = if !payload.scan_result.findings.is_empty() {
        db::insert_findings(&state.db_pool, &scan_id, &payload.scan_result.findings).await?
    } else {
        0
    };

    info!(
        "Scan ingested: scan_id={}, repo={}, findings={}",
        scan_id, payload.repo_name, findings_count
    );

    Ok(Json(IngestScanResponse {
        scan_id,
        ingested_at: chrono::Utc::now().to_rfc3339(),
        findings_stored: findings_count,
    }))
}

/// GET /api/v1/analytics/summary - Get analytics summary
pub async fn get_analytics_summary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<AnalyticsSummary>, ApiError> {
    // Verify authentication
    verify_auth(&headers, &state.api_key_hash)?;

    debug!(
        "Getting analytics summary: org={:?}, team={:?}, repo={:?}, days={}",
        query.org_id, query.team_id, query.repo_id, query.days
    );

    // Get current period summary
    let summary = db::get_summary(
        &state.db_pool,
        query.org_id.as_deref(),
        query.team_id.as_deref(),
        query.repo_id.as_deref(),
        query.days,
    )
    .await?;

    // Compare against previous window with same size.
    let previous = db::get_summary_for_window(
        &state.db_pool,
        query.org_id.as_deref(),
        query.team_id.as_deref(),
        query.repo_id.as_deref(),
        query.days * 2,
        query.days,
    )
    .await?;

    // Get time series
    let time_series = db::get_time_series(
        &state.db_pool,
        query.org_id.as_deref(),
        query.team_id.as_deref(),
        query.repo_id.as_deref(),
        query.days,
    )
    .await
    .unwrap_or_default();

    // Get top rules
    let top_rules = db::get_top_rules_list(
        &state.db_pool,
        query.org_id.as_deref(),
        query.team_id.as_deref(),
        query.repo_id.as_deref(),
        query.days,
        query.limit,
    )
    .await
    .unwrap_or_default();

    // Get top repos
    let top_repos = db::get_top_repos_list(
        &state.db_pool,
        query.org_id.as_deref(),
        query.team_id.as_deref(),
        query.repo_id.as_deref(),
        query.days,
        query.limit,
    )
    .await
    .unwrap_or_default();

    let trend = TrendStats {
        findings_delta_pct: percent_change(
            summary.total_findings as f64,
            previous.total_findings as f64,
        ),
        ai_ratio_delta_pct: percent_change(summary.ai_ratio * 100.0, previous.ai_ratio * 100.0),
        scans_delta_pct: percent_change(summary.total_scans as f64, previous.total_scans as f64),
    };

    Ok(Json(AnalyticsSummary {
        period: format!("{} days", query.days),
        org_id: query.org_id,
        team_id: query.team_id,
        summary,
        trend: Some(trend),
        time_series,
        top_rules,
        top_repos,
    }))
}

/// GET /api/v1/analytics/trends - Get time-series trends
pub async fn get_trends(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<Vec<TimeSeriesPoint>>, ApiError> {
    // Verify authentication
    verify_auth(&headers, &state.api_key_hash)?;

    let time_series = db::get_time_series(
        &state.db_pool,
        query.org_id.as_deref(),
        query.team_id.as_deref(),
        query.repo_id.as_deref(),
        query.days,
    )
    .await?;

    Ok(Json(time_series))
}

/// GET /api/v1/analytics/top-rules - Get top security rules
pub async fn get_top_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<Vec<TopRule>>, ApiError> {
    // Verify authentication
    verify_auth(&headers, &state.api_key_hash)?;

    let top_rules = db::get_top_rules_list(
        &state.db_pool,
        query.org_id.as_deref(),
        query.team_id.as_deref(),
        query.repo_id.as_deref(),
        query.days,
        query.limit,
    )
    .await?;

    Ok(Json(top_rules))
}

fn percent_change(current: f64, previous: f64) -> Option<f64> {
    if previous <= 0.0 {
        if current <= 0.0 {
            return Some(0.0);
        }
        return None;
    }
    Some(((current - previous) / previous * 1000.0).round() / 10.0)
}

/// GET /api/v1/scans - List scans
#[derive(Debug, serde::Deserialize)]
pub struct ScanListQuery {
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    pub repo_id: Option<String>,
    pub branch: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_scans(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ScanListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    verify_auth(&headers, &state.api_key_hash)?;

    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    let rows = sqlx::query(
        r#"
        SELECT
            scan_id::text as scan_id,
            org_id,
            team_id,
            repo_id,
            repo_name,
            branch,
            commit_sha,
            timestamp as scanned_at,
            total_findings,
            critical_count as critical,
            high_count as high,
            medium_count as medium,
            low_count as low,
            info_count as info,
            ai_estimated_count
        FROM scans
        WHERE ($1::TEXT IS NULL OR org_id = $1)
            AND ($2::TEXT IS NULL OR team_id = $2)
            AND ($3::TEXT IS NULL OR repo_id = $3)
            AND ($4::TEXT IS NULL OR branch = $4)
        ORDER BY timestamp DESC
        LIMIT $5 OFFSET $6
        "#,
    )
    .bind(&params.org_id)
    .bind(&params.team_id)
    .bind(&params.repo_id)
    .bind(&params.branch)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db_pool)
    .await?;

    let scans: Vec<serde_json::Value> = rows.iter().map(|row| {
        use sqlx::Row;
        serde_json::json!({
            "scan_id": row.get::<String, _>("scan_id"),
            "org_id": row.get::<Option<String>, _>("org_id"),
            "team_id": row.get::<Option<String>, _>("team_id"),
            "repo_id": row.get::<Option<String>, _>("repo_id"),
            "repo_name": row.get::<Option<String>, _>("repo_name"),
            "branch": row.get::<Option<String>, _>("branch"),
            "commit_sha": row.get::<Option<String>, _>("commit_sha"),
            "scanned_at": row.get::<chrono::DateTime<chrono::Utc>, _>("scanned_at").to_rfc3339(),
            "total_findings": row.get::<i32, _>("total_findings"),
            "critical": row.get::<i32, _>("critical"),
            "high": row.get::<i32, _>("high"),
            "medium": row.get::<i32, _>("medium"),
            "low": row.get::<i32, _>("low"),
            "info": row.get::<i32, _>("info"),
            "ai_estimated_count": row.get::<i32, _>("ai_estimated_count"),
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "scans": scans,
        "limit": limit,
        "offset": offset,
    })))
}

// ============================================================
// AI METRICS ENDPOINT
// ============================================================

#[derive(Debug, serde::Deserialize)]
pub struct AIMetricsQuery {
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    pub days: Option<i32>,
}

#[derive(Debug, serde::Serialize)]
pub struct AIMetricsResponse {
    pub summary: AIMetricsSummary,
    pub by_tool: Vec<ToolBreakdown>,
    pub by_pattern: Vec<PatternBreakdown>,
    pub confidence_distribution: ConfidenceDistribution,
}

#[derive(Debug, serde::Serialize)]
pub struct AIMetricsSummary {
    pub total_ai_findings: i64,
    pub ai_percentage: f64,
    pub total_findings: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct ToolBreakdown {
    pub tool: String,
    pub findings: i64,
    pub percentage: f64,
    pub avg_confidence: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct PatternBreakdown {
    pub pattern_id: String,
    pub description: String,
    pub count: i64,
    pub tool: Option<String>,
    pub avg_confidence: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct ConfidenceDistribution {
    pub high: i64,   // 80-100%
    pub medium: i64, // 60-80%
    pub low: i64,    // <60%
}

pub async fn ai_metrics(
    State(state): State<Arc<crate::models::AppState>>,
    headers: HeaderMap,
    Query(params): Query<AIMetricsQuery>,
) -> Result<Json<AIMetricsResponse>, ApiError> {
    verify_auth(&headers, &state.api_key_hash)?;

    let days = params.days.unwrap_or(30);
    info!("Fetching AI metrics for {} days", days);

    // Treat ai_confidence >= 0.6 as AI-generated for stable, schema-compatible metrics.
    let summary_query = r#"
        SELECT 
            COUNT(*) FILTER (WHERE COALESCE(f.ai_confidence, 0) >= 0.6) as ai_count,
            COUNT(*) as total_count
        FROM findings f
        INNER JOIN scans s ON f.scan_id = s.scan_id
        WHERE s.timestamp >= NOW() - INTERVAL '1 day' * $1
            AND ($2::text IS NULL OR s.org_id = $2)
            AND ($3::text IS NULL OR s.team_id = $3)
    "#;

    let summary_row: (i64, i64) = sqlx::query_as(summary_query)
        .bind(days)
        .bind(&params.org_id)
        .bind(&params.team_id)
        .fetch_one(&state.db_pool)
        .await?;

    let (ai_count, total_count) = summary_row;
    let ai_percentage = if total_count > 0 {
        (ai_count as f64 / total_count as f64) * 100.0
    } else {
        0.0
    };

    // Get tool breakdown
    let tool_query = r#"
        SELECT 
            CASE
                WHEN COALESCE(f.ai_tendency, '') ILIKE '%copilot%' THEN 'GitHub Copilot'
                WHEN COALESCE(f.ai_tendency, '') ILIKE '%chatgpt%' THEN 'ChatGPT'
                WHEN COALESCE(f.ai_tendency, '') ILIKE '%claude%' THEN 'Claude'
                ELSE 'AI-assisted'
            END as tool,
            COUNT(*) as count,
            AVG(COALESCE(f.ai_confidence, 0.0) * 100.0) as avg_confidence
        FROM findings f
        INNER JOIN scans s ON f.scan_id = s.scan_id
        WHERE s.timestamp >= NOW() - INTERVAL '1 day' * $1
            AND COALESCE(f.ai_confidence, 0) >= 0.6
            AND ($2::text IS NULL OR s.org_id = $2)
            AND ($3::text IS NULL OR s.team_id = $3)
        GROUP BY 1
        ORDER BY count DESC
        LIMIT 10
    "#;

    let tool_rows: Vec<(String, i64, f64)> = sqlx::query_as(tool_query)
        .bind(days)
        .bind(&params.org_id)
        .bind(&params.team_id)
        .fetch_all(&state.db_pool)
        .await?;

    let by_tool: Vec<ToolBreakdown> = tool_rows
        .into_iter()
        .map(|(tool, count, avg_conf)| {
            let percentage = if ai_count > 0 {
                (count as f64 / ai_count as f64) * 100.0
            } else {
                0.0
            };
            ToolBreakdown {
                tool,
                findings: count,
                percentage,
                avg_confidence: avg_conf,
            }
        })
        .collect();

    // Get pattern breakdown
    let pattern_query = r#"
        SELECT 
            f.rule_id as pattern_id,
            COALESCE(f.rule_title, f.rule_id) as description,
            COUNT(*) as count,
            CASE
                WHEN COALESCE(f.ai_tendency, '') ILIKE '%copilot%' THEN 'GitHub Copilot'
                WHEN COALESCE(f.ai_tendency, '') ILIKE '%chatgpt%' THEN 'ChatGPT'
                WHEN COALESCE(f.ai_tendency, '') ILIKE '%claude%' THEN 'Claude'
                ELSE 'AI-assisted'
            END as tool,
            AVG(COALESCE(f.ai_confidence, 0.0) * 100.0) as avg_confidence
        FROM findings f
        INNER JOIN scans s ON f.scan_id = s.scan_id
        WHERE s.timestamp >= NOW() - INTERVAL '1 day' * $1
            AND COALESCE(f.ai_confidence, 0) >= 0.6
            AND ($2::text IS NULL OR s.org_id = $2)
            AND ($3::text IS NULL OR s.team_id = $3)
        GROUP BY 1, 2, 4
        ORDER BY count DESC
        LIMIT 10
    "#;

    let pattern_rows: Vec<(String, String, i64, Option<String>, f64)> =
        sqlx::query_as(pattern_query)
            .bind(days)
            .bind(&params.org_id)
            .bind(&params.team_id)
            .fetch_all(&state.db_pool)
            .await?;

    let by_pattern: Vec<PatternBreakdown> = pattern_rows
        .into_iter()
        .map(
            |(pattern_id, desc, count, tool, avg_conf)| PatternBreakdown {
                pattern_id,
                description: desc,
                count,
                tool,
                avg_confidence: avg_conf,
            },
        )
        .collect();

    // Get confidence distribution
    let conf_query = r#"
        SELECT 
            COUNT(*) FILTER (WHERE f.ai_confidence >= 0.8) as high,
            COUNT(*) FILTER (WHERE f.ai_confidence >= 0.6 AND f.ai_confidence < 0.8) as medium,
            COUNT(*) FILTER (WHERE f.ai_confidence > 0 AND f.ai_confidence < 0.6) as low
        FROM findings f
        INNER JOIN scans s ON f.scan_id = s.scan_id
        WHERE s.timestamp >= NOW() - INTERVAL '1 day' * $1
            AND ($2::text IS NULL OR s.org_id = $2)
            AND ($3::text IS NULL OR s.team_id = $3)
    "#;

    let (high, medium, low): (i64, i64, i64) = sqlx::query_as(conf_query)
        .bind(days)
        .bind(&params.org_id)
        .bind(&params.team_id)
        .fetch_one(&state.db_pool)
        .await?;

    Ok(Json(AIMetricsResponse {
        summary: AIMetricsSummary {
            total_ai_findings: ai_count,
            ai_percentage,
            total_findings: total_count,
        },
        by_tool,
        by_pattern,
        confidence_distribution: ConfidenceDistribution { high, medium, low },
    }))
}

// ============================================================
// COMPLIANCE REPORT ENDPOINT
// ============================================================

// COMPLIANCE REPORT CSV export
// Appended to handlers.rs

#[derive(Debug, serde::Deserialize)]
pub struct ComplianceReportQuery {
    pub org_id: String, // Required
    pub format: String, //CSV format
    pub start_date: Option<String>,
    pub end_date: Option<String>,
}

pub async fn generate_compliance_report(
    State(state): State<Arc<crate::models::AppState>>,
    headers: HeaderMap,
    Query(params): Query<ComplianceReportQuery>,
) -> Result<Response, ApiError> {
    verify_auth(&headers, &state.api_key_hash)?;

    let requested_format = params.format.to_lowercase();
    if requested_format != "csv" && requested_format != "pdf" {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            message: "Unsupported format. Allowed values: csv, pdf".to_string(),
        });
    }

    info!("Generating compliance report for org: {}", params.org_id);

    // Default date range
    let end_date = params
        .end_date
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    let start_date = params.start_date.unwrap_or_else(|| {
        (chrono::Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string()
    });

    // Fetch scan data
    let query = r#"
        SELECT 
            s.org_id,
            COALESCE(s.team_id, 'N/A') as team_id,
            COALESCE(s.repo_id, 'N/A') as repo_id,
            s.timestamp as scanned_at,
            COUNT(f.id) as total_findings,
            COUNT(f.id) FILTER (WHERE f.severity = 'critical') as critical,
            COUNT(f.id) FILTER (WHERE f.severity = 'high') as high,
            COUNT(f.id) FILTER (WHERE f.severity = 'medium') as medium,
            COUNT(f.id) FILTER (WHERE f.severity = 'low') as low,
            COALESCE((
                SELECT f2.cwe_id
                FROM findings f2
                WHERE f2.scan_id = s.scan_id
                    AND f2.cwe_id IS NOT NULL
                    AND f2.cwe_id <> ''
                GROUP BY f2.cwe_id
                ORDER BY COUNT(*) DESC, f2.cwe_id ASC
                LIMIT 1
            ), 'N/A') as top_cwe,
            COALESCE((
                SELECT f3.owasp_category
                FROM findings f3
                WHERE f3.scan_id = s.scan_id
                    AND f3.owasp_category IS NOT NULL
                    AND f3.owasp_category <> ''
                GROUP BY f3.owasp_category
                ORDER BY COUNT(*) DESC, f3.owasp_category ASC
                LIMIT 1
            ), 'N/A') as top_owasp
        FROM scans s
        LEFT JOIN findings f ON s.scan_id = f.scan_id
        WHERE s.org_id = $1
            AND s.timestamp >= $2::date
            AND s.timestamp <= $3::date + INTERVAL '1 day'
        GROUP BY s.scan_id, s.org_id, s.team_id, s.repo_id, s.timestamp
        ORDER BY s.timestamp DESC
    "#;

    let rows: Vec<(
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        i64,
        i64,
        i64,
        i64,
        i64,
        String,
        String,
    )> = sqlx::query_as(query)
        .bind(&params.org_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&state.db_pool)
        .await?;

    // Generate CSV
    let mut wtr = Writer::from_writer(vec![]);

    wtr.write_record(&[
        "Organization",
        "Team",
        "Repository",
        "Scan Date",
        "Total Findings",
        "Critical",
        "High",
        "Medium",
        "Low",
        "Top CWE",
        "Top OWASP",
        "Compliance Score",
    ])
    .map_err(|e| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("CSV error: {}", e),
    })?;

    for row in rows {
        let (org, team, repo, date, total, critical, high, medium, low, top_cwe, top_owasp) = row;
        let compliance_score = if total > 0 {
            let penalty = (critical * 10 + high * 5 + medium * 2 + low * 1) as f64;
            format!("{:.1}%", (100.0 - (penalty / total as f64).min(100.0)))
        } else {
            "100.0%".to_string()
        };

        wtr.write_record(&[
            org,
            team,
            repo,
            date.format("%Y-%m-%d %H:%M:%S").to_string(),
            total.to_string(),
            critical.to_string(),
            high.to_string(),
            medium.to_string(),
            low.to_string(),
            top_cwe,
            top_owasp,
            compliance_score,
        ])
        .map_err(|e| ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("CSV error: {}", e),
        })?;
    }

    let data = wtr.into_inner().map_err(|e| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("CSV error: {}", e),
    })?;
    let filename = if requested_format == "pdf" {
        format!(
            "compliance-report-{}.txt",
            chrono::Utc::now().format("%Y%m%d")
        )
    } else {
        format!(
            "compliance-report-{}.csv",
            chrono::Utc::now().format("%Y%m%d")
        )
    };
    let content_type = if requested_format == "pdf" {
        "text/plain"
    } else {
        "text/csv"
    };

    Ok((
        StatusCode::OK,
        [
            ("Content-Type", content_type),
            (
                "Content-Disposition",
                &format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        data,
    )
        .into_response())
}
