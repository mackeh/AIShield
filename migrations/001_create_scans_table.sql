-- Migration: Create scans hypertable for time-series analytics
-- Requires: TimescaleDB extension

-- Enable TimescaleDB extension (if not already enabled)
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Create scans table (will be converted to hypertable)
CREATE TABLE scans (
  -- Primary key
  id                 BIGSERIAL PRIMARY KEY,
  scan_id            UUID NOT NULL DEFAULT gen_random_uuid(),
  
  -- Time dimension (hypertable partitioning key)
  timestamp          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  -- Organization/Team dimensions
  org_id             TEXT,          -- GitHub org, GitLab group, etc.
  team_id            TEXT,          -- Team slug within org
  repo_id            TEXT,          -- Repository identifier (e.g., "github.com/owner/repo")
  repo_name          TEXT,          -- Human-readable name
  
  -- Scan context
  target_path        TEXT NOT NULL, -- Path scanned (e.g., "src/", ".")
  branch             TEXT,          -- Git branch
  commit_sha         TEXT,          -- Git commit SHA
  ci_run_id          TEXT,          -- CI/CD job ID (GitHub Actions run ID, etc.)
  cli_version        TEXT,          -- AIShield version
  
  -- Aggregated finding counts
  total_findings     INTEGER NOT NULL DEFAULT 0,
  critical_count     INTEGER NOT NULL DEFAULT 0,
  high_count         INTEGER NOT NULL DEFAULT 0,
  medium_count       INTEGER NOT NULL DEFAULT 0,
  low_count          INTEGER NOT NULL DEFAULT 0,
  info_count         INTEGER NOT NULL DEFAULT 0,
  
  -- AI-specific metrics
  ai_estimated_count INTEGER NOT NULL DEFAULT 0,  -- Findings with ai_confidence > 0.7
  ai_ratio           REAL GENERATED ALWAYS AS (
    CASE WHEN total_findings > 0 
         THEN ai_estimated_count::REAL / total_findings 
         ELSE 0 
    END
  ) STORED,
  
  -- Performance metrics
  scan_duration_ms   INTEGER,
  files_scanned      INTEGER,
  rules_loaded       INTEGER,
  
  -- Metadata
  user_email         TEXT,          -- (Optional) For attribution
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  -- Constraints
  CONSTRAINT scan_id_unique UNIQUE (scan_id),
  CONSTRAINT valid_findings CHECK (total_findings >= 0),
  CONSTRAINT valid_severity_counts CHECK (
    critical_count >= 0 AND 
    high_count >= 0 AND 
    medium_count >= 0 AND 
    low_count >= 0 AND 
    info_count >= 0
  ),
  CONSTRAINT valid_ai_count CHECK (ai_estimated_count >= 0 AND ai_estimated_count <= total_findings)
);

-- Convert to TimescaleDB hypertable (partition by timestamp, 7-day chunks)
SELECT create_hypertable('scans', 'timestamp', chunk_time_interval => INTERVAL '7 days');

-- Create indexes for common query patterns
CREATE INDEX idx_scans_org_time ON scans (org_id, team_id, timestamp DESC);
CREATE INDEX idx_scans_repo_time ON scans (repo_id, timestamp DESC);
CREATE INDEX idx_scans_branch ON scans (repo_id, branch, timestamp DESC) WHERE branch IS NOT NULL;
CREATE INDEX idx_scans_ci_run ON scans (ci_run_id) WHERE ci_run_id IS NOT NULL;
CREATE INDEX idx_scans_scan_id ON scans (scan_id);

-- Add compression policy (compress chunks older than 30 days)
SELECT add_compression_policy('scans', INTERVAL '30 days');

-- Add retention policy (drop chunks older than 2 years)
SELECT add_retention_policy('scans', INTERVAL '2 years');

-- Create table comment
COMMENT ON TABLE scans IS 'Time-series scan results for AIShield analytics';
COMMENT ON COLUMN scans.scan_id IS 'Unique identifier for this scan (UUID)';
COMMENT ON COLUMN scans.timestamp IS 'When the scan was performed (partition key)';
COMMENT ON COLUMN scans.ai_ratio IS 'Ratio of AI-generated findings to total findings (computed column)';
