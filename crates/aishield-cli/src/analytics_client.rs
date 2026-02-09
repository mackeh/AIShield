use crate::config::AnalyticsConfig;
use crate::git_utils::RepoMetadata;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// Metadata for a scan
#[derive(Debug, Clone, Serialize)]
pub struct ScanMetadata {
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    pub repo_id: String,
    pub repo_name: String,
    pub branch: String,
    pub commit_sha: String,
    pub target_path: String,
    pub cli_version: String,
}

/// Scan result summary for analytics
#[derive(Debug, Clone, Serialize)]
pub struct ScanResultSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub ai_estimated_count: usize,
    pub scan_duration_ms: u64,
    pub files_scanned: usize,
    pub rules_loaded: usize,
    pub findings: Vec<FindingDetail>,
}

/// Individual finding detail
#[derive(Debug, Clone, Serialize)]
pub struct FindingDetail {
    pub rule_id: String,
    pub rule_title: String,
    pub severity: String,
    pub file_path: String,
    pub line_number: Option<usize>,
    pub snippet: Option<String>,
    pub ai_confidence: Option<f32>,
    pub ai_tendency: Option<String>,
    pub fix_suggestion: Option<String>,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
}

/// Analytics API client
pub struct AnalyticsClient {
    http_client: Client,
    base_url: String,
    api_key: String,
}

#[derive(Debug, Clone)]
pub struct AnalyticsQuery {
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    pub repo_id: Option<String>,
    pub days: i32,
    pub limit: i32,
}

impl AnalyticsClient {
    /// Create a new analytics client
    pub fn new(config: &AnalyticsConfig) -> Result<Self, String> {
        let base_url = config
            .url
            .as_ref()
            .ok_or("Analytics URL not configured")?
            .clone();

        let api_key = config
            .api_key
            .as_ref()
            .ok_or("Analytics API key not configured")?
            .clone();

        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            http_client,
            base_url,
            api_key,
        })
    }

    /// Test connection to analytics API
    pub async fn health_check(&self) -> Result<bool, String> {
        let url = format!("{}/api/health", self.base_url);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Health check failed: {}", e))?;

        Ok(response.status().is_success())
    }

    /// Push scan result to analytics API
    pub async fn push_scan_result(
        &self,
        scan_result: &ScanResultSummary,
        metadata: &ScanMetadata,
    ) -> Result<String, String> {
        let url = format!("{}/api/v1/scans/ingest", self.base_url);

        let request_body = serde_json::json!({
            "org_id": metadata.org_id,
            "team_id": metadata.team_id,
            "repo_id": metadata.repo_id,
            "repo_name": metadata.repo_name,
            "branch": metadata.branch,
            "commit_sha": metadata.commit_sha,
            "target_path": metadata.target_path,
            "cli_version": metadata.cli_version,
            "scan_result": scan_result,
        });

        // Retry logic: 2 attempts with exponential backoff
        let mut last_error = String::new();

        for attempt in 0..=2 {
            if attempt > 0 {
                // Exponential backoff: 1s, 2s
                let delay = Duration::from_secs(2u64.pow(attempt as u32 - 1));
                tokio::time::sleep(delay).await;
            }

            match self.try_push(&url, &request_body).await {
                Ok(scan_id) => return Ok(scan_id),
                Err(e) => {
                    last_error = e;
                    // Don't retry on auth errors
                    if last_error.contains("401") || last_error.contains("Unauthorized") {
                        break;
                    }
                }
            }
        }

        Err(last_error)
    }

    /// Attempt to push scan (single try)
    async fn try_push(&self, url: &str, body: &serde_json::Value) -> Result<String, String> {
        let response = self
            .http_client
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        let status = response.status();

        if status.is_success() {
            #[derive(Deserialize)]
            struct IngestResponse {
                scan_id: String,
            }

            let resp: IngestResponse = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse response: {}", e))?;

            Ok(resp.scan_id)
        } else {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            Err(format!("API error ({}): {}", status, error_body))
        }
    }

    pub async fn fetch_summary(&self, query: &AnalyticsQuery) -> Result<Value, String> {
        let url = self.build_url_with_query("/api/v1/analytics/summary", query)?;
        self.get_json(&url).await
    }

    pub async fn fetch_compliance_gaps(&self, query: &AnalyticsQuery) -> Result<Value, String> {
        let url = self.build_url_with_query("/api/v1/analytics/compliance-gaps", query)?;
        self.get_json(&url).await
    }

    fn build_url_with_query(
        &self,
        endpoint: &str,
        query: &AnalyticsQuery,
    ) -> Result<reqwest::Url, String> {
        let base = self.base_url.trim_end_matches('/');
        let mut url = reqwest::Url::parse(&format!("{base}{endpoint}"))
            .map_err(|e| format!("Invalid analytics URL: {}", e))?;

        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("days", &query.days.to_string());
            pairs.append_pair("limit", &query.limit.to_string());
            if let Some(org_id) = query.org_id.as_deref() {
                pairs.append_pair("org_id", org_id);
            }
            if let Some(team_id) = query.team_id.as_deref() {
                pairs.append_pair("team_id", team_id);
            }
            if let Some(repo_id) = query.repo_id.as_deref() {
                pairs.append_pair("repo_id", repo_id);
            }
        }

        Ok(url)
    }

    async fn get_json(&self, url: &reqwest::Url) -> Result<Value, String> {
        let response = self
            .http_client
            .get(url.as_str())
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("API error ({}): {}", status, error_body));
        }

        response
            .json::<Value>()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    }
}

impl ScanMetadata {
    /// Create scan metadata from repository and config
    pub fn from_repo(
        repo_metadata: &RepoMetadata,
        target_path: String,
        config: &AnalyticsConfig,
    ) -> Self {
        Self {
            org_id: config.org_id.clone(),
            team_id: config.team_id.clone(),
            repo_id: repo_metadata.repo_id.clone(),
            repo_name: repo_metadata.repo_name.clone(),
            branch: repo_metadata.branch.clone(),
            commit_sha: repo_metadata.commit_sha.clone(),
            target_path,
            cli_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}
