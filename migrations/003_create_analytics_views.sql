-- Migration: Create materialized views for analytics dashboards
-- Pre-computed aggregations for fast dashboard queries

-- Top rules aggregation (daily rollup)
CREATE MATERIALIZED VIEW top_rules_daily AS
SELECT
  s.org_id,
  s.team_id,
  date_trunc('day', s.timestamp) AS day,
  f.rule_id,
  f.rule_title,
  f.severity,
  count(DISTINCT s.scan_id) AS scans_with_rule,
  count(f.id) AS total_occurrences,
  avg(f.ai_confidence) AS avg_ai_confidence,
  count(DISTINCT f.file_path) AS unique_files_affected
FROM scans s
JOIN findings f ON s.scan_id = f.scan_id
GROUP BY s.org_id, s.team_id, day, f.rule_id, f.rule_title, f.severity;

CREATE INDEX idx_top_rules_org_day ON top_rules_daily (org_id, day DESC);
CREATE INDEX idx_top_rules_team_day ON top_rules_daily (org_id, team_id, day DESC);
CREATE INDEX idx_top_rules_severity ON top_rules_daily (severity, day DESC);

COMMENT ON MATERIALIZED VIEW top_rules_daily IS 'Daily aggregation of top security rules by org/team';

-- Repository health summary (daily rollup)
CREATE MATERIALIZED VIEW repo_health_daily AS
SELECT
  s.org_id,
  s.repo_id,
  s.repo_name,
  date_trunc('day', s.timestamp) AS day,
  count(DISTINCT s.scan_id) AS total_scans,
  sum(s.total_findings) AS total_findings,
  sum(s.critical_count) AS critical_findings,
  sum(s.high_count) AS high_findings,
  sum(s.medium_count) AS medium_findings,
  sum(s.low_count) AS low_findings,
  avg(s.ai_ratio) AS avg_ai_ratio,
  avg(s.scan_duration_ms) AS avg_scan_duration_ms
FROM scans s
GROUP BY s.org_id, s.repo_id, s.repo_name, day;

CREATE INDEX idx_repo_health_org_day ON repo_health_daily (org_id, day DESC);
CREATE INDEX idx_repo_health_repo ON repo_health_daily (repo_id, day DESC);

COMMENT ON MATERIALIZED VIEW repo_health_daily IS 'Daily health metrics per repository';

-- Team leaderboard (weekly rollup)
CREATE MATERIALIZED VIEW team_leaderboard_weekly AS
SELECT
  s.org_id,
  s.team_id,
  date_trunc('week', s.timestamp) AS week,
  count(DISTINCT s.scan_id) AS scans_performed,
  sum(s.total_findings) AS total_findings,
  sum(s.critical_count + s.high_count) AS high_severity_count,
  avg(s.ai_ratio) AS avg_ai_ratio,
  -- Calculate "security score" (lower is better)
  CASE 
    WHEN sum(s.critical_count + s.high_count) = 0 THEN 100
    ELSE GREATEST(0, 100 - (sum(s.critical_count) * 10 + sum(s.high_count) * 3))
  END AS security_score
FROM scans s
WHERE s.team_id IS NOT NULL
GROUP BY s.org_id, s.team_id, week;

CREATE INDEX idx_team_leaderboard_org_week ON team_leaderboard_weekly (org_id, week DESC);
CREATE INDEX idx_team_leaderboard_score ON team_leaderboard_weekly (org_id, week DESC, security_score DESC);

COMMENT ON MATERIALIZED VIEW team_leaderboard_weekly IS 'Weekly team security performance leaderboard';

-- Vulnerability trend (hourly for recent data, daily for historical)
CREATE MATERIALIZED VIEW vulnerability_trend_hourly AS
SELECT
  s.org_id,
  date_trunc('hour', s.timestamp) AS hour,
  count(DISTINCT s.scan_id) AS scans,
  sum(s.total_findings) AS findings,
  sum(s.critical_count) AS critical,
  sum(s.high_count) AS high,
  sum(s.medium_count) AS medium,
  avg(s.ai_ratio) AS ai_ratio
FROM scans s
WHERE s.timestamp > NOW() - INTERVAL '7 days'  -- Only last 7 days hourly
GROUP BY s.org_id, hour;

CREATE INDEX idx_vuln_trend_hourly ON vulnerability_trend_hourly (org_id, hour DESC);

COMMENT ON MATERIALIZED VIEW vulnerability_trend_hourly IS 'Hourly vulnerability trend for last 7 days';

-- Refresh policies (auto-refresh materialized views)
-- Note: These use pg_cron (optional extension), or can be refreshed manually/via scheduled job

-- Function to refresh all materialized views
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY top_rules_daily;
  REFRESH MATERIALIZED VIEW CONCURRENTLY repo_health_daily;
  REFRESH MATERIALIZED VIEW CONCURRENTLY team_leaderboard_weekly;
  REFRESH MATERIALIZED VIEW CONCURRENTLY vulnerability_trend_hourly;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION refresh_analytics_views() IS 'Refresh all analytics materialized views';

-- Create unique indexes for CONCURRENTLY refresh support
CREATE UNIQUE INDEX idx_top_rules_daily_unique ON top_rules_daily (org_id, COALESCE(team_id, ''), day, rule_id);
CREATE UNIQUE INDEX idx_repo_health_daily_unique ON repo_health_daily (org_id, repo_id, day);
CREATE UNIQUE INDEX idx_team_leaderboard_weekly_unique ON team_leaderboard_weekly (org_id, team_id, week);
CREATE UNIQUE INDEX idx_vuln_trend_hourly_unique ON vulnerability_trend_hourly (org_id, hour);
