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
  fi

  echo "pass: $name -> HTTP 200, non-empty body"
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

request_json "summary" \
  "$BASE_URL/api/v1/analytics/summary?org_id=$ORG_ID&days=$DAYS"

request_json "trends" \
  "$BASE_URL/api/v1/analytics/trends?org_id=$ORG_ID&days=$DAYS"

request_json "top-rules" \
  "$BASE_URL/api/v1/analytics/top-rules?org_id=$ORG_ID&days=$DAYS&limit=10"

request_json "ai-metrics" \
  "$BASE_URL/api/v1/analytics/ai-metrics?org_id=$ORG_ID&days=$DAYS"

request_file "compliance-report" \
  "$BASE_URL/api/v1/reports/compliance?org_id=$ORG_ID&format=csv"

echo
echo "all checks passed"
