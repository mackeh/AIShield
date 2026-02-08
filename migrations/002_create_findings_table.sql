-- Migration: Create findings detail table
-- Stores individual finding details for drill-down analysis

CREATE TABLE findings (
  -- Primary key
  id               BIGSERIAL PRIMARY KEY,
  
  -- Foreign key to scans table
  scan_id          UUID NOT NULL,
  
  -- Finding identification
  finding_hash     TEXT NOT NULL,  -- Deterministic hash: SHA256(repo_id || file_path || line_number || rule_id)
  
  -- Finding details
  rule_id          TEXT NOT NULL,
  rule_title       TEXT,
  severity         TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  file_path        TEXT NOT NULL,
  line_number      INTEGER,
  snippet          TEXT,           -- Code snippet (optional, max 500 chars)
  
  -- AI classification
  ai_confidence    REAL CHECK (ai_confidence >= 0.0 AND ai_confidence <= 1.0),
  ai_tendency      TEXT,           -- Why AI generated this pattern
  
  -- Fix information
  fix_suggestion   TEXT,
  cwe_id           TEXT,           -- CWE identifier (e.g., "CWE-89")
  owasp_category   TEXT,           -- OWASP category (e.g., "A03:2021")
  
  -- Temporal tracking
  first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  times_seen       INTEGER NOT NULL DEFAULT 1,
  is_fixed         BOOLEAN DEFAULT FALSE,
  fixed_at         TIMESTAMPTZ,
  
  -- Constraints
  CONSTRAINT valid_line_number CHECK (line_number > 0),
  CONSTRAINT valid_times_seen CHECK (times_seen > 0),
  CONSTRAINT fixed_at_requires_is_fixed CHECK (
    (is_fixed = TRUE AND fixed_at IS NOT NULL) OR 
    (is_fixed = FALSE AND fixed_at IS NULL)
  )
);

-- Foreign key constraint (ON DELETE CASCADE: if scan is deleted, delete findings)
ALTER TABLE findings 
  ADD CONSTRAINT fk_findings_scan 
  FOREIGN KEY (scan_id) 
  REFERENCES scans(scan_id) 
  ON DELETE CASCADE;

-- Indexes for common query patterns
CREATE INDEX idx_findings_scan ON findings (scan_id);
CREATE INDEX idx_findings_hash ON findings (finding_hash);
CREATE INDEX idx_findings_rule ON findings (rule_id, last_seen DESC);
CREATE INDEX idx_findings_severity ON findings (severity, last_seen DESC) WHERE is_fixed = FALSE;
CREATE INDEX idx_findings_file ON findings (file_path, last_seen DESC);
CREATE INDEX idx_findings_ai_confidence ON findings (ai_confidence DESC) WHERE ai_confidence > 0.7;

-- Create unique index on finding_hash + scan_id to prevent duplicates within same scan
CREATE UNIQUE INDEX idx_findings_unique_per_scan ON findings (scan_id, finding_hash);

-- Table comments
COMMENT ON TABLE findings IS 'Individual security finding details for drill-down analysis';
COMMENT ON COLUMN findings.finding_hash IS 'Deterministic hash for tracking finding across scans';
COMMENT ON COLUMN findings.times_seen IS 'Number of times this finding has been seen across scans';
COMMENT ON COLUMN findings.is_fixed IS 'Whether this finding has been resolved';
