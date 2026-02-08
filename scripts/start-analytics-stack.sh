#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

DB_URL="${DATABASE_URL:-postgres://aishield:aishield_dev_password@localhost:5432/aishield_analytics}"
API_KEY="${AISHIELD_API_KEY:-test_key_e2e_12345}"
PORT="${PORT:-8080}"

echo "== Starting AIShield Analytics Stack =="
echo "root:      $ROOT_DIR"
echo "db:        $DB_URL"
echo "port:      $PORT"
echo

echo "[1/3] Starting Docker services..."
docker compose -f docker-compose.analytics.yml up -d

echo "[2/3] Starting analytics API..."
if pgrep -f "target/debug/aishield-analytics" >/dev/null 2>&1; then
  echo "      API already running"
else
  export DATABASE_URL="$DB_URL"
  export AISHIELD_API_KEY="$API_KEY"
  export PORT
  export RUST_LOG="${RUST_LOG:-info,aishield_analytics=debug}"

  if [[ -x "$ROOT_DIR/target/debug/aishield-analytics" ]]; then
    nohup "$ROOT_DIR/target/debug/aishield-analytics" > /tmp/aishield-analytics.log 2>&1 &
  else
    nohup cargo run -p aishield-analytics > /tmp/aishield-analytics.log 2>&1 &
  fi
  echo "      API started (logs: /tmp/aishield-analytics.log)"
fi

echo "[3/3] Running smoke test..."
sleep 2
AISHIELD_ANALYTICS_URL="http://localhost:${PORT}" \
AISHIELD_API_KEY="$API_KEY" \
  "$ROOT_DIR/scripts/smoke-analytics-api.sh"

echo
echo "✅ Analytics stack is ready"
echo "   API health:  http://localhost:${PORT}/api/health"
echo "   DB UI:       http://localhost:5050"
echo "   Stop stack:  ./scripts/stop-analytics-stack.sh"
