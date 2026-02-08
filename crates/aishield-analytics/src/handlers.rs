use crate::{auth, db, models::*};
use std::sync::Arc;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
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
        "Getting analytics summary: org={:?}, team={:?}, days={}",
        query.org_id, query.team_id, query.days
    );

    // Get current period summary
    let summary = db::get_summary(
        &state.db_pool,
        query.org_id.as_deref(),
        query.team_id.as_deref(),
        query.days,
    )
    .await?;

    // Get time series
    let time_series = db::get_time_series(&state.db_pool, query.org_id.as_deref(), query.days)
        .await
        .unwrap_or_default();

    // Get top rules
    let top_rules =
        db::get_top_rules_list(&state.db_pool, query.org_id.as_deref(), query.days, query.limit)
            .await
            .unwrap_or_default();

    // Get top repos
    let top_repos =
        db::get_top_repos_list(&state.db_pool, query.org_id.as_deref(), query.days, query.limit)
            .await
            .unwrap_or_default();

    Ok(Json(AnalyticsSummary {
        period: format!("{} days", query.days),
        org_id: query.org_id,
        team_id: query.team_id,
        summary,
        trend: None, // TODO: Calculate trend vs previous period
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

    let time_series = db::get_time_series(&state.db_pool, query.org_id.as_deref(), query.days)
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

    let top_rules =
        db::get_top_rules_list(&state.db_pool, query.org_id.as_deref(), query.days, query.limit)
            .await?;

    Ok(Json(top_rules))
}
