use crate::models::*;
use chrono::Utc;
use sha2::Digest;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Insert a scan into the database
pub async fn insert_scan(pool: &PgPool, request: &IngestScanRequest) -> Result<Uuid, sqlx::Error> {
    let scan_id = Uuid::new_v4();
    let now = Utc::now();

    let _result = sqlx::query(
        r#"
        INSERT INTO scans (
            scan_id, timestamp, org_id, team_id, repo_id, repo_name,
            target_path, branch, commit_sha, ci_run_id, cli_version,
            total_findings, critical_count, high_count, medium_count,
            low_count, info_count, ai_estimated_count,
            scan_duration_ms, files_scanned, rules_loaded, user_email
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
        )
        "#,
    )
    .bind(&scan_id)
    .bind(&now)
    .bind(&request.org_id)
    .bind(&request.team_id)
    .bind(&request.repo_id)
    .bind(&request.repo_name)
    .bind(&request.target_path)
    .bind(&request.branch)
    .bind(&request.commit_sha)
    .bind(&request.ci_run_id)
    .bind(&request.cli_version)
    .bind(request.scan_result.total_findings)
    .bind(request.scan_result.critical)
    .bind(request.scan_result.high)
    .bind(request.scan_result.medium)
    .bind(request.scan_result.low)
    .bind(request.scan_result.info)
    .bind(request.scan_result.ai_estimated_count)
    .bind(request.scan_result.scan_duration_ms)
    .bind(request.scan_result.files_scanned)
    .bind(request.scan_result.rules_loaded)
    .bind(&request.user_email)
    .execute(pool)
    .await?;

    Ok(scan_id)
}

/// Insert findings for a scan
pub async fn insert_findings(
    pool: &PgPool,
    scan_id: &Uuid,
    findings: &[FindingDetail],
) -> Result<usize, sqlx::Error> {
    if findings.is_empty() {
        return Ok(0);
    }

    for finding in findings {
        // Create deterministic hash
        let hash_input = format!(
            "{}::{}::{}::{}",
            scan_id,
            finding.file_path,
            finding.line_number.unwrap_or(0),
            finding.rule_id
        );
        let finding_hash = format!("{:x}", sha2::Sha256::digest(hash_input.as_bytes()));

        sqlx::query(
            r#"
            INSERT INTO findings (
                scan_id, finding_hash, rule_id, rule_title, severity,
                file_path, line_number, snippet, ai_confidence, ai_tendency,
                fix_suggestion, cwe_id, owasp_category
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
            )
            ON CONFLICT (scan_id, finding_hash) DO UPDATE SET
                last_seen = NOW(),
                times_seen = findings.times_seen + 1
            "#,
        )
        .bind(scan_id)
        .bind(&finding_hash)
        .bind(&finding.rule_id)
        .bind(&finding.rule_title)
        .bind(&finding.severity)
        .bind(&finding.file_path)
        .bind(finding.line_number)
        .bind(&finding.snippet)
        .bind(finding.ai_confidence)
        .bind(&finding.ai_tendency)
        .bind(&finding.fix_suggestion)
        .bind(&finding.cwe_id)
        .bind(&finding.owasp_category)
        .execute(pool)
        .await?;
    }

    Ok(findings.len())
}

/// Get analytics summary for the rolling `days` window.
pub async fn get_summary(
    pool: &PgPool,
    org_id: Option<&str>,
    team_id: Option<&str>,
    repo_id: Option<&str>,
    days: i32,
) -> Result<SummaryStats, sqlx::Error> {
    get_summary_for_window(pool, org_id, team_id, repo_id, days, 0).await
}

/// Get analytics summary between `window_start_days_ago` and `window_end_days_ago`.
pub async fn get_summary_for_window(
    pool: &PgPool,
    org_id: Option<&str>,
    team_id: Option<&str>,
    repo_id: Option<&str>,
    window_start_days_ago: i32,
    window_end_days_ago: i32,
) -> Result<SummaryStats, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(DISTINCT scan_id) as total_scans,
            COALESCE(SUM(total_findings), 0) as total_findings,
            COALESCE(SUM(critical_count), 0) as critical,
            COALESCE(SUM(high_count), 0) as high,
            COALESCE(SUM(medium_count), 0) as medium,
            COALESCE(SUM(low_count), 0) as low,
            COALESCE(SUM(info_count), 0) as info,
            COALESCE(SUM(ai_estimated_count), 0) as ai_estimated,
            CASE
                WHEN SUM(total_findings) > 0
                THEN CAST(SUM(ai_estimated_count) AS FLOAT) / CAST(SUM(total_findings) AS FLOAT)
                ELSE 0
            END as ai_ratio
        FROM scans
        WHERE timestamp > NOW() - $1 * INTERVAL '1 day'
            AND timestamp <= NOW() - $2 * INTERVAL '1 day'
            AND ($3::TEXT IS NULL OR org_id = $3)
            AND ($4::TEXT IS NULL OR team_id = $4)
            AND ($5::TEXT IS NULL OR repo_id = $5)
        "#,
    )
    .bind(window_start_days_ago)
    .bind(window_end_days_ago)
    .bind(org_id)
    .bind(team_id)
    .bind(repo_id)
    .fetch_one(pool)
    .await?;

    Ok(SummaryStats {
        total_scans: row.get("total_scans"),
        total_findings: row.get("total_findings"),
        critical: row.get("critical"),
        high: row.get("high"),
        medium: row.get("medium"),
        low: row.get("low"),
        info: row.get("info"),
        ai_estimated: row.get("ai_estimated"),
        ai_ratio: row.get::<f64, _>("ai_ratio"),
    })
}

/// Get time-series data
pub async fn get_time_series(
    pool: &PgPool,
    org_id: Option<&str>,
    team_id: Option<&str>,
    repo_id: Option<&str>,
    days: i32,
) -> Result<Vec<TimeSeriesPoint>, sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT
            DATE(timestamp) as date,
            COUNT(DISTINCT scan_id) as scans,
            COALESCE(SUM(total_findings), 0) as findings,
            COALESCE(SUM(critical_count), 0) as critical,
            COALESCE(SUM(high_count), 0) as high,
            COALESCE(SUM(medium_count), 0) as medium,
            COALESCE(SUM(low_count), 0) as low,
            COALESCE(SUM(info_count), 0) as info,
            COALESCE(SUM(ai_estimated_count), 0) as ai_estimated,
            COALESCE(SUM(critical_count), 0) + COALESCE(SUM(high_count), 0) as high_or_above,
            CASE
                WHEN SUM(total_findings) > 0
                THEN CAST(SUM(ai_estimated_count) AS FLOAT) / CAST(SUM(total_findings) AS FLOAT)
                ELSE 0
            END as ai_ratio
        FROM scans
        WHERE timestamp > NOW() - $1 * INTERVAL '1 day'
            AND ($2::TEXT IS NULL OR org_id = $2)
            AND ($3::TEXT IS NULL OR team_id = $3)
            AND ($4::TEXT IS NULL OR repo_id = $4)
        GROUP BY DATE(timestamp)
        ORDER BY date ASC
        "#,
    )
    .bind(days)
    .bind(org_id)
    .bind(team_id)
    .bind(repo_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| TimeSeriesPoint {
            date: row.get::<chrono::NaiveDate, _>("date").to_string(),
            scans: row.get("scans"),
            findings: row.get("findings"),
            critical: row.get("critical"),
            high: row.get("high"),
            medium: row.get("medium"),
            low: row.get("low"),
            info: row.get("info"),
            ai_estimated: row.get("ai_estimated"),
            high_or_above: row.get("high_or_above"),
            ai_ratio: row.get("ai_ratio"),
        })
        .collect())
}

/// Get top rules
pub async fn get_top_rules_list(
    pool: &PgPool,
    org_id: Option<&str>,
    team_id: Option<&str>,
    repo_id: Option<&str>,
    days: i32,
    limit: i32,
) -> Result<Vec<TopRule>, sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT
            f.rule_id,
            f.rule_title,
            f.severity,
            COUNT(*) as count
        FROM findings f
        JOIN scans s ON f.scan_id = s.scan_id
        WHERE s.timestamp > NOW() - $1 * INTERVAL '1 day'
            AND ($2::TEXT IS NULL OR s.org_id = $2)
            AND ($3::TEXT IS NULL OR s.team_id = $3)
            AND ($4::TEXT IS NULL OR s.repo_id = $4)
        GROUP BY f.rule_id, f.rule_title, f.severity
        ORDER BY count DESC
        LIMIT $5
        "#,
    )
    .bind(days)
    .bind(org_id)
    .bind(team_id)
    .bind(repo_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| TopRule {
            rule_id: row.get("rule_id"),
            rule_title: row.get("rule_title"),
            severity: row.get("severity"),
            count: row.get("count"),
        })
        .collect())
}

/// Get top repos
pub async fn get_top_repos_list(
    pool: &PgPool,
    org_id: Option<&str>,
    team_id: Option<&str>,
    repo_id: Option<&str>,
    days: i32,
    limit: i32,
) -> Result<Vec<TopRepo>, sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT
            repo_id,
            repo_name,
            COUNT(DISTINCT scan_id) as scans,
            SUM(total_findings) as findings,
            AVG(ai_ratio) as ai_ratio
        FROM scans
        WHERE timestamp > NOW() - $1 * INTERVAL '1 day'
            AND ($2::TEXT IS NULL OR org_id = $2)
            AND ($3::TEXT IS NULL OR team_id = $3)
            AND ($4::TEXT IS NULL OR repo_id = $4)
            AND repo_id IS NOT NULL
        GROUP BY repo_id, repo_name
        ORDER BY findings DESC
        LIMIT $5
        "#,
    )
    .bind(days)
    .bind(org_id)
    .bind(team_id)
    .bind(repo_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| TopRepo {
            repo_id: row.get("repo_id"),
            repo_name: row.get("repo_name"),
            scans: row.get("scans"),
            findings: row.get("findings"),
            ai_ratio: row.get::<f64, _>("ai_ratio"),
        })
        .collect())
}
