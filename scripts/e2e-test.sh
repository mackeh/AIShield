#!/bin/bash
set -e

echo "🧪 AIShield End-to-End Testing Script"
echo "======================================"
echo ""

# Configuration
export DATABASE_URL="postgres://aishield:aishield_dev_password@localhost:5432/aishield_analytics"
export AISHIELD_API_KEY="test_key_e2e_12345"
export ANALYTICS_URL="http://localhost:8080"

# Test data configuration
ORGS=("acme-corp" "widgets-inc" "techstart")
TEAMS_ACME=("security" "devops" "platform")
TEAMS_WIDGETS=("engineering" "qa")
TEAMS_TECHSTART=("fullstack")
REPOS=("api-gateway" "web-app" "mobile-app" "backend-services" "data-pipeline")

echo "📋 Test Configuration:"
echo "  - Organizations: ${#ORGS[@]}"
echo "  - Total teams: $((${#TEAMS_ACME[@]} + ${#TEAMS_WIDGETS[@]} + ${#TEAMS_TECHSTART[@]}))"
echo "  - Repositories: ${#REPOS[@]}"
echo ""

# Check if PostgreSQL is running
echo "🔍 Checking PostgreSQL..."
if ! pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
    echo "❌ PostgreSQL is not running on localhost:5432"
    echo "   Please start PostgreSQL first"
    exit 1
fi
echo "✅ PostgreSQL is running"
echo ""

# Check if database exists
echo "🔍 Checking database..."
if ! psql "$DATABASE_URL" -c "SELECT 1;" > /dev/null 2>&1; then
    echo "❌ Database 'aishield_analytics' does not exist or is not accessible"
    echo "   Run migrations first: cd crates/aishield-analytics && sqlx migrate run"
    exit 1
fi
echo "✅ Database accessible"
echo ""

# Build CLI if needed
echo "🔨 Building AIShield CLI..."
cargo build -p aishield-cli --release --quiet
if [ $? -ne 0 ]; then
    echo "❌ CLI build failed"
    exit 1
fi
echo "✅ CLI built successfully"
echo ""

# Generate test data function
generate_scan_data() {
    local org=$1
    local team=$2
    local repo=$3
    local scan_num=$4
    
    echo "  📊 Generating scan: org=$org, team=$team, repo=$repo (#$scan_num)"
    
    # Create a temp directory for this scan
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Create sample files with varying severity
    mkdir -p src
    
    # Add some hardcoded secrets (high severity)
    if [ $((RANDOM % 3)) -eq 0 ]; then
        echo 'const API_KEY = "sk_live_1234567890abcdef";' > src/config.js
        echo 'password = "admin123"' > src/auth.py
    fi
    
    # Add some suspicious patterns (medium/low)
    echo 'eval(user_input)' > src/eval_code.js
    echo 'subprocess.call(cmd, shell=True)' > src/executor.py
    echo '# TODO: fix SQL injection' > src/database.py
    
    # Run scan with analytics push
    ../../target/release/aishield scan . \
        --format json \
        --output scan.json \
        --analytics-push \
        --org-id "$org" \
        --team-id "$team" \
        --repo-id "$repo" \
        2>&1 | grep -E "(Scan complete|pushed|error)" || true
    
    cd - > /dev/null
    rm -rf "$temp_dir"
}

echo "📦 Generating multi-org scan data..."
echo ""

scan_count=0

# ACME Corp scans
for team in "${TEAMS_ACME[@]}"; do
    for repo in "${REPOS[@]:0:3}"; do  # 3 repos per team
        scan_count=$((scan_count + 1))
        generate_scan_data "acme-corp" "$team" "$repo" "$scan_count"
    done
done

# Widgets Inc scans
for team in "${TEAMS_WIDGETS[@]}"; do
    for repo in "${REPOS[@]:2:2}"; do  # 2 repos per team
        scan_count=$((scan_count + 1))
        generate_scan_data "widgets-inc" "$team" "$repo" "$scan_count"
    done
done

# TechStart scans
for team in "${TEAMS_TECHSTART[@]}"; do
    for repo in "${REPOS[@]:0:2}"; do  # 2 repos
        scan_count=$((scan_count + 1))
        generate_scan_data "techstart" "$team" "$repo" "$scan_count"
    done
done

echo ""
echo "✅ Generated $scan_count scans across ${#ORGS[@]} organizations"
echo ""

# Verify data in database
echo "🔍 Verifying data in database..."
scan_db_count=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM scans;" 2>/dev/null || echo "0")
echo "  Database contains: $scan_db_count scans"

if [ "$scan_db_count" -lt "$scan_count" ]; then
    echo "⚠️  Warning: Expected $scan_count scans but found $scan_db_count in database"
else
    echo "✅ All scans recorded in database"
fi
echo ""

echo "📊 Database Summary:"
psql "$DATABASE_URL" -c "
SELECT 
    org_id,
    COUNT(DISTINCT team_id) as teams,
    COUNT(DISTINCT repo_id) as repos,
    COUNT(*) as scans,
    SUM(total_findings) as total_findings,
    SUM(critical) as critical,
    SUM(high) as high
FROM scans 
GROUP BY org_id 
ORDER BY org_id;
" 2>/dev/null || echo "  Could not query database stats"

echo ""
echo "✅ Test data generation complete!"
echo ""
echo "🚀 Next steps:"
echo "  1. Start analytics API: cd crates/aishield-analytics && cargo run"
echo "  2. Start dashboard: cd dashboard && node server.js"
echo "  3. Open http://localhost:3000"
echo "  4. Configure API settings with:"
echo "     - URL: http://localhost:8080"
echo "     - Key: test_key_e2e_12345"
echo ""
