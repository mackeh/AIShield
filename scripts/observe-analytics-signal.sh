#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${AISHIELD_ANALYTICS_URL:-http://localhost:8080}"
API_KEY="${AISHIELD_API_KEY:-}"
ORG_ID="${AISHIELD_ORG_ID:-test_org_1}"
DAYS="${AISHIELD_DAYS:-30}"
ITERATIONS="${AISHIELD_BURNIN_ITERATIONS:-12}"
INTERVAL_SECONDS="${AISHIELD_BURNIN_INTERVAL_SECONDS:-10}"
OUTPUT_DIR="${AISHIELD_BURNIN_OUTPUT_DIR:-$ROOT_DIR/.aishield-staging}"
MAX_ERROR_RATE_PCT="${AISHIELD_BURNIN_MAX_ERROR_RATE_PCT:-1.0}"
MAX_P95_MS="${AISHIELD_BURNIN_MAX_P95_MS:-1500}"
MIN_COVERAGE_PCT="${AISHIELD_BURNIN_MIN_COVERAGE_PCT:-70.0}"
EXIT_ON_FAILURE="${AISHIELD_BURNIN_EXIT_ON_FAILURE:-1}"

if [[ -z "$API_KEY" ]]; then
  echo "error: AISHIELD_API_KEY is required"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

HAS_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAS_JQ=1
fi

RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")"
RAW_FILE="$OUTPUT_DIR/analytics-signal-$RUN_ID.csv"
REPORT_FILE="$OUTPUT_DIR/analytics-signal-$RUN_ID.md"
LATEST_REPORT="$OUTPUT_DIR/analytics-signal-latest.md"

printf "iteration,endpoint,http_code,latency_ms,total_findings,coverage_pct,timestamp\n" >"$RAW_FILE"

request_endpoint() {
  local iteration="$1"
  local endpoint_name="$2"
  local url="$3"
  local needs_auth="$4"
  local body_file="$OUTPUT_DIR/.burnin-${endpoint_name}-${iteration}.json"
  local curl_output
  local http_code="000"
  local latency_ms="0.0"
  local total_findings=""
  local coverage_pct=""

  if [[ "$needs_auth" == "1" ]]; then
    if curl_output="$(curl -sS -o "$body_file" -w "%{http_code} %{time_total}" \
      -H "x-api-key: $API_KEY" \
      "$url" 2>/dev/null)"; then
      http_code="${curl_output%% *}"
      latency_ms="$(awk -v t="${curl_output##* }" 'BEGIN { printf "%.3f", t * 1000 }')"
    fi
  else
    if curl_output="$(curl -sS -o "$body_file" -w "%{http_code} %{time_total}" \
      "$url" 2>/dev/null)"; then
      http_code="${curl_output%% *}"
      latency_ms="$(awk -v t="${curl_output##* }" 'BEGIN { printf "%.3f", t * 1000 }')"
    fi
  fi

  if [[ "$HAS_JQ" == "1" && "$http_code" == "200" ]]; then
    if [[ "$endpoint_name" == "summary" ]]; then
      total_findings="$(jq -r '.summary.total_findings // empty' "$body_file" 2>/dev/null || true)"
    elif [[ "$endpoint_name" == "compliance-gaps" ]]; then
      coverage_pct="$(jq -r '.summary.coverage_pct // empty' "$body_file" 2>/dev/null || true)"
    fi
  fi

  printf "%s,%s,%s,%s,%s,%s,%s\n" \
    "$iteration" \
    "$endpoint_name" \
    "$http_code" \
    "$latency_ms" \
    "$total_findings" \
    "$coverage_pct" \
    "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >>"$RAW_FILE"

  rm -f "$body_file"
}

percentile_from_file() {
  local sorted_file="$1"
  local percentile="$2"
  local count
  local rank

  count="$(wc -l <"$sorted_file" | tr -d ' ')"
  if [[ "$count" -eq 0 ]]; then
    echo "0.0"
    return
  fi

  rank="$(awk -v n="$count" -v p="$percentile" 'BEGIN { r = int((p / 100.0) * n + 0.999999); if (r < 1) r = 1; if (r > n) r = n; print r }')"
  sed -n "${rank}p" "$sorted_file"
}

endpoint_latency_stat() {
  local endpoint_name="$1"
  local percentile="$2"
  local tmp_file
  tmp_file="$(mktemp)"

  awk -F, -v endpoint="$endpoint_name" 'NR > 1 && $2 == endpoint && $3 == "200" { print $4 }' "$RAW_FILE" | sort -n >"$tmp_file"
  percentile_from_file "$tmp_file" "$percentile"
  rm -f "$tmp_file"
}

endpoint_count() {
  local endpoint_name="$1"
  awk -F, -v endpoint="$endpoint_name" 'NR > 1 && $2 == endpoint { c++ } END { print c + 0 }' "$RAW_FILE"
}

endpoint_failures() {
  local endpoint_name="$1"
  awk -F, -v endpoint="$endpoint_name" 'NR > 1 && $2 == endpoint && ($3 == "000" || ($3 + 0) >= 400) { c++ } END { print c + 0 }' "$RAW_FILE"
}

echo "== Observe Analytics Signal =="
echo "base_url:    $BASE_URL"
echo "org_id:      $ORG_ID"
echo "days:        $DAYS"
echo "iterations:  $ITERATIONS"
echo "interval(s): $INTERVAL_SECONDS"
echo "output_dir:  $OUTPUT_DIR"
echo

for ((i = 1; i <= ITERATIONS; i++)); do
  request_endpoint "$i" "health" "$BASE_URL/api/health" "0"
  request_endpoint "$i" "summary" "$BASE_URL/api/v1/analytics/summary?org_id=$ORG_ID&days=$DAYS" "1"
  request_endpoint "$i" "compliance-gaps" "$BASE_URL/api/v1/analytics/compliance-gaps?org_id=$ORG_ID&days=$DAYS&limit=5" "1"
  request_endpoint "$i" "ai-metrics" "$BASE_URL/api/v1/analytics/ai-metrics?org_id=$ORG_ID&days=$DAYS" "1"

  echo "sample $i/$ITERATIONS captured"
  if [[ "$i" -lt "$ITERATIONS" ]]; then
    sleep "$INTERVAL_SECONDS"
  fi
done

total_requests="$(awk -F, 'NR > 1 { c++ } END { print c + 0 }' "$RAW_FILE")"
failed_requests="$(awk -F, 'NR > 1 && ($3 == "000" || ($3 + 0) >= 400) { c++ } END { print c + 0 }' "$RAW_FILE")"
error_rate_pct="$(awk -v failed="$failed_requests" -v total="$total_requests" 'BEGIN { if (total == 0) { printf "0.00" } else { printf "%.2f", (failed / total) * 100.0 } }')"

summary_p50_ms="$(endpoint_latency_stat "summary" "50")"
summary_p95_ms="$(endpoint_latency_stat "summary" "95")"
gaps_p50_ms="$(endpoint_latency_stat "compliance-gaps" "50")"
gaps_p95_ms="$(endpoint_latency_stat "compliance-gaps" "95")"
metrics_p50_ms="$(endpoint_latency_stat "ai-metrics" "50")"
metrics_p95_ms="$(endpoint_latency_stat "ai-metrics" "95")"

coverage_min="$(awk -F, 'NR > 1 && $2 == "compliance-gaps" && $6 != "" { if (min == "" || ($6 + 0) < min) min = $6 + 0 } END { if (min == "") print "n/a"; else printf "%.2f", min }' "$RAW_FILE")"
coverage_avg="$(awk -F, 'NR > 1 && $2 == "compliance-gaps" && $6 != "" { sum += $6; c++ } END { if (c == 0) print "n/a"; else printf "%.2f", sum / c }' "$RAW_FILE")"
findings_avg="$(awk -F, 'NR > 1 && $2 == "summary" && $5 != "" { sum += $5; c++ } END { if (c == 0) print "n/a"; else printf "%.2f", sum / c }' "$RAW_FILE")"

summary_total="$(endpoint_count "summary")"
summary_failures="$(endpoint_failures "summary")"
gaps_total="$(endpoint_count "compliance-gaps")"
gaps_failures="$(endpoint_failures "compliance-gaps")"
metrics_total="$(endpoint_count "ai-metrics")"
metrics_failures="$(endpoint_failures "ai-metrics")"

status="PASS"
reasons=()

if awk -v current="$error_rate_pct" -v max="$MAX_ERROR_RATE_PCT" 'BEGIN { exit !(current > max) }'; then
  status="FAIL"
  reasons+=("Error rate ${error_rate_pct}% exceeded max ${MAX_ERROR_RATE_PCT}%")
fi

if awk -v current="$summary_p95_ms" -v max="$MAX_P95_MS" 'BEGIN { exit !(current > max) }'; then
  status="FAIL"
  reasons+=("Summary p95 ${summary_p95_ms}ms exceeded max ${MAX_P95_MS}ms")
fi

if awk -v current="$gaps_p95_ms" -v max="$MAX_P95_MS" 'BEGIN { exit !(current > max) }'; then
  status="FAIL"
  reasons+=("Compliance-gaps p95 ${gaps_p95_ms}ms exceeded max ${MAX_P95_MS}ms")
fi

if awk -v current="$metrics_p95_ms" -v max="$MAX_P95_MS" 'BEGIN { exit !(current > max) }'; then
  status="FAIL"
  reasons+=("AI-metrics p95 ${metrics_p95_ms}ms exceeded max ${MAX_P95_MS}ms")
fi

if [[ "$coverage_min" != "n/a" ]] && awk -v current="$coverage_min" -v min="$MIN_COVERAGE_PCT" 'BEGIN { exit !(current < min) }'; then
  status="FAIL"
  reasons+=("Coverage min ${coverage_min}% below minimum ${MIN_COVERAGE_PCT}%")
fi

{
  echo "# Analytics Signal Burn-in Report"
  echo
  echo "- Run ID: \`$RUN_ID\`"
  echo "- Timestamp (UTC): \`$(date -u +"%Y-%m-%dT%H:%M:%SZ")\`"
  echo "- Git commit: \`$(git rev-parse --short HEAD)\`"
  echo "- Base URL: \`$BASE_URL\`"
  echo "- Org ID: \`$ORG_ID\`"
  echo "- Sampling: \`${ITERATIONS} iterations x ${INTERVAL_SECONDS}s\`"
  echo "- Status: **$status**"
  echo
  echo "## Request Summary"
  echo
  echo "| Metric | Value |"
  echo "|---|---:|"
  echo "| Total requests | $total_requests |"
  echo "| Failed requests | $failed_requests |"
  echo "| Error rate | ${error_rate_pct}% |"
  echo
  echo "## Endpoint Latency and Failures"
  echo
  echo "| Endpoint | Requests | Failures | p50 (ms) | p95 (ms) |"
  echo "|---|---:|---:|---:|---:|"
  echo "| summary | $summary_total | $summary_failures | $summary_p50_ms | $summary_p95_ms |"
  echo "| compliance-gaps | $gaps_total | $gaps_failures | $gaps_p50_ms | $gaps_p95_ms |"
  echo "| ai-metrics | $metrics_total | $metrics_failures | $metrics_p50_ms | $metrics_p95_ms |"
  echo
  echo "## Signal Quality Snapshot"
  echo
  echo "| Metric | Value |"
  echo "|---|---:|"
  echo "| Average total findings (summary) | $findings_avg |"
  echo "| Coverage avg (compliance-gaps) | $coverage_avg% |"
  echo "| Coverage min (compliance-gaps) | $coverage_min% |"
  echo
  echo "## SLO Gates"
  echo
  echo "| Gate | Threshold | Observed | Result |"
  echo "|---|---:|---:|---|"
  echo "| Error rate | <= ${MAX_ERROR_RATE_PCT}% | ${error_rate_pct}% | $(awk -v current="$error_rate_pct" -v max="$MAX_ERROR_RATE_PCT" 'BEGIN { if (current <= max) print "PASS"; else print "FAIL" }') |"
  echo "| Summary p95 | <= ${MAX_P95_MS} ms | ${summary_p95_ms} ms | $(awk -v current="$summary_p95_ms" -v max="$MAX_P95_MS" 'BEGIN { if (current <= max) print "PASS"; else print "FAIL" }') |"
  echo "| Compliance-gaps p95 | <= ${MAX_P95_MS} ms | ${gaps_p95_ms} ms | $(awk -v current="$gaps_p95_ms" -v max="$MAX_P95_MS" 'BEGIN { if (current <= max) print "PASS"; else print "FAIL" }') |"
  echo "| AI-metrics p95 | <= ${MAX_P95_MS} ms | ${metrics_p95_ms} ms | $(awk -v current="$metrics_p95_ms" -v max="$MAX_P95_MS" 'BEGIN { if (current <= max) print "PASS"; else print "FAIL" }') |"
  if [[ "$coverage_min" == "n/a" ]]; then
    echo "| Coverage min | >= ${MIN_COVERAGE_PCT}% | n/a | SKIP |"
  else
    echo "| Coverage min | >= ${MIN_COVERAGE_PCT}% | ${coverage_min}% | $(awk -v current="$coverage_min" -v min="$MIN_COVERAGE_PCT" 'BEGIN { if (current >= min) print "PASS"; else print "FAIL" }') |"
  fi

  if [[ "${#reasons[@]}" -gt 0 ]]; then
    echo
    echo "## Failure Reasons"
    echo
    for reason in "${reasons[@]}"; do
      echo "- $reason"
    done
  fi

  if [[ "$HAS_JQ" != "1" ]]; then
    echo
    echo "> Note: \`jq\` not found. Some signal fields may be unavailable."
  fi
} >"$REPORT_FILE"

cp "$REPORT_FILE" "$LATEST_REPORT"

echo
echo "raw samples: $RAW_FILE"
echo "report:      $REPORT_FILE"
echo "latest:      $LATEST_REPORT"
echo "status:      $status"

if [[ "$status" == "FAIL" && "$EXIT_ON_FAILURE" == "1" ]]; then
  exit 1
fi
