#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AISHIELD_ANALYTICS_URL:-${1:-http://localhost:8080}}"
API_KEY="${AISHIELD_API_KEY:-${2:-test_key_e2e_12345}}"
ORG_ID="${AISHIELD_ORG_ID:-${3:-test_org_1}}"
DAYS="${AISHIELD_DAYS:-30}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required"
  exit 1
fi

HAS_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAS_JQ=1
fi

request_json() {
  local name="$1"
  local url="$2"
  local out_file="$TMP_DIR/$name.json"

  local status
  if ! status="$(curl -sS -o "$out_file" -w "%{http_code}" \
    -H "x-api-key: $API_KEY" \
    "$url")"; then
    echo "fail: $name -> request failed"
    echo "hint: ensure analytics API is running at $BASE_URL"
    return 1
  fi

  if [[ "$status" != "200" ]]; then
    echo "fail: $name -> HTTP $status"
    echo "body:"
    cat "$out_file"
    echo
    return 1
  fi

  echo "pass: $name -> HTTP 200"
  if [[ "$HAS_JQ" == "1" ]]; then
    jq . "$out_file" >/dev/null
    echo "      valid JSON"
  fi
}

request_file() {
  local name="$1"
  local url="$2"
  local out_file="$TMP_DIR/$name.out"

  local status
  if ! status="$(curl -sS -o "$out_file" -w "%{http_code}" \
    -H "x-api-key: $API_KEY" \
    "$url")"; then
    echo "fail: $name -> request failed"
    echo "hint: ensure analytics API is running at $BASE_URL"
    return 1
  fi

  if [[ "$status" != "200" ]]; then
    echo "fail: $name -> HTTP $status"
    echo "body:"
    cat "$out_file"
    echo
    return 1
  fi

  if [[ ! -s "$out_file" ]]; then
    echo "fail: $name -> empty response body"
    return 1
  fi

  if [[ "$name" == "compliance-report" ]]; then
    local header
    header="$(head -n 1 "$out_file" || true)"
    if [[ "$header" != *"Top CWE"* || "$header" != *"Top OWASP"* || "$header" != *"Compliance Score"* ]]; then
      echo "fail: $name -> expected CSV header columns missing"
      echo "header: $header"
      return 1
    fi

    if [[ -n "${SMOKE_REPO_ID:-}" ]]; then
      local row
      row="$(grep -F "$SMOKE_REPO_ID" "$out_file" | head -n 1 || true)"
      if [[ -z "$row" ]]; then
        echo "fail: $name -> expected smoke repo row not found: $SMOKE_REPO_ID"
        return 1
      fi
      if [[ "$row" != *"CWE-79"* || "$row" != *"A03:2021 - Injection"* ]]; then
        echo "fail: $name -> metadata aggregation mismatch for $SMOKE_REPO_ID"
        echo "row: $row"
        return 1
      fi
      echo "      metadata mapping verified for $SMOKE_REPO_ID"
    fi
  fi

  echo "pass: $name -> HTTP 200, non-empty body"
}

ingest_smoke_scan() {
  SMOKE_REPO_ID="smoke-metadata-$(date +%s)"
  local payload="$TMP_DIR/ingest-smoke.json"
  cat >"$payload" <<EOF
{
  "org_id": "$ORG_ID",
  "team_id": "smoke",
  "repo_id": "$SMOKE_REPO_ID",
  "repo_name": "$SMOKE_REPO_ID",
  "branch": "main",
  "commit_sha": "smoke-meta-001",
  "target_path": ".",
  "cli_version": "0.3.2",
  "scan_result": {
    "total_findings": 4,
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 1,
    "info": 0,
    "ai_estimated_count": 3,
    "scan_duration_ms": 123,
    "files_scanned": 4,
    "rules_loaded": 169,
    "findings": [
      {
        "rule_id": "AISHIELD-SMOKE-001",
        "rule_title": "Smoke metadata finding 1",
        "severity": "high",
        "file_path": "src/a.py",
        "line_number": 10,
        "snippet": "unsafe_call()",
        "ai_confidence": 0.81,
        "ai_tendency": "Generated from test fixture",
        "fix_suggestion": "Use safe call",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection"
      },
      {
        "rule_id": "AISHIELD-SMOKE-002",
        "rule_title": "Smoke metadata finding 2",
        "severity": "medium",
        "file_path": "src/b.py",
        "line_number": 20,
        "snippet": "dangerous_concat()",
        "ai_confidence": 0.73,
        "ai_tendency": "Generated from test fixture",
        "fix_suggestion": "Use parameterized API",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection"
      },
      {
        "rule_id": "AISHIELD-SMOKE-003",
        "rule_title": "Smoke metadata finding 3",
        "severity": "high",
        "file_path": "src/c.py",
        "line_number": 30,
        "snippet": "open_admin_port()",
        "ai_confidence": 0.66,
        "ai_tendency": "Generated from test fixture",
        "fix_suggestion": "Restrict access",
        "cwe_id": "CWE-20",
        "owasp_category": "A05:2021 - Security Misconfiguration"
      },
      {
        "rule_id": "AISHIELD-SMOKE-004",
        "rule_title": "Smoke metadata finding 4",
        "severity": "low",
        "file_path": "src/d.py",
        "line_number": 40,
        "snippet": "debug_log()",
        "ai_confidence": 0.51,
        "ai_tendency": "Generated from test fixture",
        "fix_suggestion": "Remove debug log"
      }
    ]
  }
}
EOF

  local status
  if ! status="$(curl -sS -o "$TMP_DIR/ingest-smoke-response.json" -w "%{http_code}" \
    -H "x-api-key: $API_KEY" \
    -H "Content-Type: application/json" \
    -X POST \
    --data @"$payload" \
    "$BASE_URL/api/v1/scans/ingest")"; then
    echo "fail: ingest-smoke-scan -> request failed"
    return 1
  fi

  if [[ "$status" != "200" ]]; then
    echo "fail: ingest-smoke-scan -> HTTP $status"
    cat "$TMP_DIR/ingest-smoke-response.json"
    echo
    return 1
  fi

  echo "pass: ingest-smoke-scan -> HTTP 200 ($SMOKE_REPO_ID)"
}

assert_strict_cors() {
  local allowed_origin="${AISHIELD_SMOKE_ALLOWED_ORIGIN:-http://localhost:3000}"
  local blocked_origin="${AISHIELD_SMOKE_DISALLOWED_ORIGIN:-https://not-allowed.example}"
  local allowed_headers="$TMP_DIR/cors-allowed.headers"
  local blocked_headers="$TMP_DIR/cors-blocked.headers"

  curl -sS -D "$allowed_headers" -o /dev/null \
    -H "Origin: $allowed_origin" \
    "$BASE_URL/api/health"

  local allow_header
  allow_header="$(awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}' "$allowed_headers" | tr -d '\r' | tail -n1)"
  if [[ "$allow_header" != "$allowed_origin" ]]; then
    echo "fail: cors -> expected allow origin '$allowed_origin', got '${allow_header:-<none>}'"
    return 1
  fi

  curl -sS -D "$blocked_headers" -o /dev/null \
    -H "Origin: $blocked_origin" \
    "$BASE_URL/api/health"

  local blocked_header
  blocked_header="$(awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}' "$blocked_headers" | tr -d '\r' | tail -n1)"
  if [[ -n "$blocked_header" ]]; then
    echo "fail: cors -> blocked origin unexpectedly allowed: $blocked_header"
    return 1
  fi

  echo "pass: cors -> strict allowlist behavior verified"
}

assert_rate_limit() {
  local max_requests="${AISHIELD_SMOKE_RATE_LIMIT_MAX:-6}"
  local probe_key="smoke-rate-limit-probe-$(date +%s)"

  for ((i = 1; i <= max_requests; i++)); do
    local status
    status="$(curl -sS -o /dev/null -w "%{http_code}" \
      -H "x-api-key: $probe_key" \
      "$BASE_URL/api/health")"
    if [[ "$status" != "200" ]]; then
      echo "fail: rate-limit -> expected HTTP 200 on request $i/$max_requests, got $status"
      return 1
    fi
  done

  local throttled
  throttled="$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "x-api-key: $probe_key" \
    "$BASE_URL/api/health")"
  if [[ "$throttled" != "429" ]]; then
    echo "fail: rate-limit -> expected HTTP 429 after $max_requests requests, got $throttled"
    return 1
  fi

  echo "pass: rate-limit -> middleware limit enforced"
}

echo "== AIShield Analytics API Smoke Test =="
echo "base_url: $BASE_URL"
echo "org_id:   $ORG_ID"
echo "days:     $DAYS"
echo

if ! HEALTH_STATUS="$(curl -sS -o "$TMP_DIR/health.json" -w "%{http_code}" "$BASE_URL/api/health")"; then
  echo "fail: health -> request failed"
  echo "hint: start analytics API, then rerun this script"
  echo "      expected health endpoint: $BASE_URL/api/health"
  exit 1
fi
if [[ "$HEALTH_STATUS" != "200" ]]; then
  echo "fail: health -> HTTP $HEALTH_STATUS"
  cat "$TMP_DIR/health.json"
  echo
  exit 1
fi
echo "pass: health -> HTTP 200"

ingest_smoke_scan

request_json "summary" \
  "$BASE_URL/api/v1/analytics/summary?org_id=$ORG_ID&days=$DAYS"

request_json "trends" \
  "$BASE_URL/api/v1/analytics/trends?org_id=$ORG_ID&days=$DAYS"

request_json "top-rules" \
  "$BASE_URL/api/v1/analytics/top-rules?org_id=$ORG_ID&days=$DAYS&limit=10"

request_json "ai-metrics" \
  "$BASE_URL/api/v1/analytics/ai-metrics?org_id=$ORG_ID&days=$DAYS"

request_json "compliance-gaps" \
  "$BASE_URL/api/v1/analytics/compliance-gaps?org_id=$ORG_ID&days=$DAYS&limit=10"

request_file "compliance-report" \
  "$BASE_URL/api/v1/reports/compliance?org_id=$ORG_ID&format=csv"

if [[ "${AISHIELD_SMOKE_ASSERT_CORS:-0}" == "1" ]]; then
  assert_strict_cors
fi

if [[ "${AISHIELD_SMOKE_ASSERT_RATE_LIMIT:-0}" == "1" ]]; then
  assert_rate_limit
fi

echo
echo "all checks passed"
