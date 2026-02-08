#!/bin/bash
set -e

# Configuration
API_URL="${AISHIELD_API_URL:-http://localhost:8080}"
API_KEY="${AISHIELD_API_KEY:-test_key_e2e_12345}"

echo "🌱 Seeding AI Metrics Data..."

# Function to generate a random AI finding
generate_ai_finding() {
  local tools=("GitHub Copilot" "ChatGPT" "Tabnine" "Amazon CodeWhisperer")
  local tool=${tools[$((RANDOM % ${#tools[@]}))]}
  local confidence=$((50 + RANDOM % 51)) # 50-100%
  local rule_id="AISHIELD-AI-${tool// /-}-$((RANDOM % 5))"
  
  # Format metadata for the findings table (if supported by ingest)
  # Note: The current ingest endpoint might not accept direct column mapping for ai_tool yet 
  # unless we updated the ingest handler. 
  # If ingest doesn't support it, we might need to update via SQL or rely on the migration backfill.
  # Let's check handlers.rs ingest_scan to see if it parses ai_metadata.
  
  echo "{\"rule_id\": \"$rule_id\", \"severity\": \"medium\", \"file\": \"src/app.js\", \"line\": $((RANDOM % 100)), \"message\": \"Potential AI generated code issue\", \"metadata\": {\"ai_tool\": \"$tool\", \"confidence\": $confidence}}"
}

# Payload with custom metadata
# We'll send a scan and then manually update the DB for this test if the ingest handler 
# doesn't automatically map metadata -> columns (which I suspect it might not without checking).
# Actually, the migration said: "UPDATE findings SET is_ai_generated = true WHERE ai_metadata IS NOT NULL"
# So if we send "ai_metadata", it should work if we run the update command or if the handler parses it.

# Let's just use SQL to insert precise test data for verification to be sure.
# accessing DB directly via psql would be best if available, or just use the app's existing capabilities.

# Checking if 'psql' is available
if command -v psql &> /dev/null; then
    echo "Using psql to insert rich test data..."
    export PGPASSWORD=postgres
    
    # Org ID: test_org_ai
    # Team: DataScience
    
    psql -h localhost -U postgres -d aishield_analytics -c "
      INSERT INTO scans (id, org_id, team_id, repo_id, branch, commit_hash, status, scanned_at)
      VALUES 
        ('scan-ai-1', 'test_org_ai', 'DataScience', 'ml-model-v1', 'main', 'hash1', 'completed', NOW() - INTERVAL '2 days'),
        ('scan-ai-2', 'test_org_ai', 'FrontendTeam', 'web-app', 'dev', 'hash2', 'completed', NOW() - INTERVAL '1 day');

      INSERT INTO findings (id, scan_id, rule_id, severity, file_path, line_number, description, ai_tool, confidence_score, is_ai_generated)
      VALUES
        ('f-ai-1', 'scan-ai-1', 'AI-SECRET', 'high', 'config.py', 10, 'Hardcoded secret in AI code', 'GitHub Copilot', 95.5, true),
        ('f-ai-2', 'scan-ai-1', 'AI-BOILERPLATE', 'low', 'utils.py', 45, 'Inefficient loop', 'ChatGPT', 78.2, true),
        ('f-ai-3', 'scan-ai-1', 'AI-HALLUCINATION', 'medium', 'api.js', 102, 'Non-existent import', 'GitHub Copilot', 60.0, true),
        ('f-ai-4', 'scan-ai-2', 'AI-STYLE', 'low', 'style.css', 10, 'Generated CSS', 'Tabnine', 55.0, true),
        ('f-ai-5', 'scan-ai-2', 'AI-SECURITY', 'critical', 'auth.js', 12, 'Unsafe eval', 'Amazon CodeWhisperer', 99.9, true);
    "
    echo "✅ Test data inserted via SQL."
else
    echo "⚠️ psql not found, skipping direct SQL insert."
fi

echo "Done."
