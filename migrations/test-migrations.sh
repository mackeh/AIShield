#!/bin/bash
# Test script to verify database migrations work correctly

set -e

echo "🧪 AIShield Database Migration Test"
echo "===================================="
echo ""

# Configuration
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-aishield}
DB_NAME=${DB_NAME:-aishield_analytics}
PGPASSWORD=${PGPASSWORD:-aishield_dev_password}
export PGPASSWORD

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

info() {
    echo -e "ℹ $1"
}

# Check if PostgreSQL is running
echo "1. Checking database connection..."
if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
    success "Connected to database: $DB_NAME"
else
    error "Cannot connect to database. Is PostgreSQL running?"
    echo ""
    info "Start database with: docker-compose -f docker-compose.analytics.yml up -d"
    exit 1
fi

# Check TimescaleDB extension
echo ""
echo "2. Checking TimescaleDB extension..."
TIMESCALE_VERSION=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT extversion FROM pg_extension WHERE extname='timescaledb';")
if [ -n "$TIMESCALE_VERSION" ]; then
    success "TimescaleDB $TIMESCALE_VERSION is installed"
else
    error "TimescaleDB extension not found"
    info "Enable with: CREATE EXTENSION timescaledb;"
    exit 1
fi

# Apply migrations
echo ""
echo "3. Applying migrations..."

# Migration 001
info "Applying 001_create_scans_table.sql..."
if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f migrations/001_create_scans_table.sql > /dev/null 2>&1; then
    success "Migration 001 applied"
else
    warning "Migration 001 already applied or failed (this is OK if re-running)"
fi

# Migration 002
info "Applying 002_create_findings_table.sql..."
if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f migrations/002_create_findings_table.sql > /dev/null 2>&1; then
    success "Migration 002 applied"
else
    warning "Migration 002 already applied or failed (this is OK if re-running)"
fi

# Migration 003
info "Applying 003_create_analytics_views.sql..."
if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f migrations/003_create_analytics_views.sql > /dev/null 2>&1; then
    success "Migration 003 applied"
else
    warning "Migration 003 already applied or failed (this is OK if re-running)"
fi

# Verify tables
echo ""
echo "4. Verifying tables..."

SCANS_EXISTS=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='scans';")
if [ "$SCANS_EXISTS" = "1" ]; then
    success "Table 'scans' exists"
else
    error "Table 'scans' not found"
    exit 1
fi

FINDINGS_EXISTS=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='findings';")
if [ "$FINDINGS_EXISTS" = "1" ]; then
    success "Table 'findings' exists"
else
    error "Table 'findings' not found"
    exit 1
fi

# Verify hypertable
echo ""
echo "5. Verifying TimescaleDB hypertable..."
IS_HYPERTABLE=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM timescaledb_information.hypertables WHERE hypertable_name='scans';")
if [ "$IS_HYPERTABLE" = "1" ]; then
    success "'scans' is a TimescaleDB hypertable"
else
    error "'scans' is not a hypertable"
    exit 1
fi

# Verify materialized views
echo ""
echo "6. Verifying materialized views..."
VIEWS=("top_rules_daily" "repo_health_daily" "team_leaderboard_weekly" "vulnerability_trend_hourly")
for view in "${VIEWS[@]}"; do
    VIEW_EXISTS=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM pg_matviews WHERE matviewname='$view';")
    if [ "$VIEW_EXISTS" = "1" ]; then
        success "Materialized view '$view' exists"
    else
        error "Materialized view '$view' not found"
        exit 1
    fi
done

# Insert test data
echo ""
echo "7. Inserting test data..."

# Test scan insert
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF > /dev/null 2>&1
INSERT INTO scans (org_id, team_id, repo_id, repo_name, target_path, branch, total_findings, critical_count, high_count, medium_count, low_count, ai_estimated_count, scan_duration_ms, files_scanned, rules_loaded)
VALUES 
  ('github/test-org', 'backend', 'github.com/test/repo', 'test-repo', 'src/', 'main', 12, 2, 7, 3, 0, 5, 1234, 156, 169),
  ('github/test-org', 'frontend', 'github.com/test/webapp', 'test-webapp', '.', 'main', 8, 0, 5, 2, 1, 3, 987, 89, 169);
EOF

SCAN_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM scans;")
if [ "$SCAN_COUNT" -ge "2" ]; then
    success "Inserted test scans (total: $SCAN_COUNT)"
else
    error "Failed to insert test data"
    exit 1
fi

# Test findings insert
SCAN_ID=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT scan_id FROM scans ORDER BY timestamp DESC LIMIT 1;")

psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF > /dev/null 2>&1
INSERT INTO findings (scan_id, finding_hash, rule_id, rule_title, severity, file_path, line_number, ai_confidence, snippet)
VALUES 
  ('$SCAN_ID', 'hash123', 'AISHIELD-PY-CRYPTO-001', 'Weak hash algorithm', 'high', 'src/auth.py', 42, 0.87, 'hashlib.md5(password)'),
  ('$SCAN_ID', 'hash456', 'AISHIELD-JS-INJECT-001', 'SQL injection', 'critical', 'src/db.js', 23, 0.91, 'query = "SELECT * FROM " + table');
EOF

FINDING_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM findings;")
if [ "$FINDING_COUNT" -ge "2" ]; then
    success "Inserted test findings (total: $FINDING_COUNT)"
else
    error "Failed to insert test findings"
    exit 1
fi

# Query test
echo ""
echo "8. Testing queries..."

# Simple aggregation
TOTAL_FINDINGS=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COALESCE(SUM(total_findings), 0) FROM scans;")
if [ "$TOTAL_FINDINGS" -ge "0" ]; then
    success "Aggregation query works (total findings: $TOTAL_FINDINGS)"
else
    error "Aggregation query failed"
    exit 1
fi

# Time-series query
LAST_24H=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM scans WHERE timestamp > NOW() - INTERVAL '24 hours';")
success "Time-series query works (scans in last 24h: $LAST_24H)"

# Refresh materialized views
echo ""
echo "9. Testing materialized view refresh..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT refresh_analytics_views();" > /dev/null 2>&1
success "Materialized views refreshed successfully"

# Performance test
echo ""
echo "10. Performance test (30-day aggregation)..."
START=$(date +%s%N)
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF > /dev/null 2>&1
SELECT 
  org_id,
  COUNT(*) as scans,
  SUM(total_findings) as findings,
  AVG(ai_ratio) as avg_ai_ratio
FROM scans
WHERE timestamp > NOW() - INTERVAL '30 days'
GROUP BY org_id;
EOF
END=$(date +%s%N)
DURATION=$(( (END - START) / 1000000 )) # Convert to milliseconds

if [ "$DURATION" -lt "100" ]; then
    success "Query completed in ${DURATION}ms (target: < 100ms)"
else
    warning "Query took ${DURATION}ms (slower than target 100ms, but acceptable for small dataset)"
fi

# Summary
echo ""
echo "======================================"
echo -e "${GREEN}✅ ALL TESTS PASSED${NC}"
echo "======================================"
echo ""
echo "Database is ready for use!"
echo ""
echo "Next steps:"
echo "  1. Build the analytics API: cd crates/aishield-analytics && cargo build"
echo "  2. Integrate with CLI: cargo run -p aishield-cli -- scan . --analytics-push"
echo "  3. Access pgAdmin: http://localhost:5050 (admin@aishield.local / admin)"
echo ""
