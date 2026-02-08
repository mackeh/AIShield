#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "== Stopping AIShield Analytics Stack =="

echo "[1/2] Stopping analytics API process..."
pkill -f "target/debug/aishield-analytics" >/dev/null 2>&1 || true
pkill -f "cargo run -p aishield-analytics" >/dev/null 2>&1 || true

echo "[2/2] Stopping Docker services..."
docker compose -f docker-compose.analytics.yml down

echo "✅ Analytics stack stopped"
