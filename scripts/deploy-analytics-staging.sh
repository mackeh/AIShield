#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

TARGET_REF="${1:-origin/main}"
STATE_DIR="$ROOT_DIR/.aishield-staging"
STATE_FILE="$STATE_DIR/last-deploy.env"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: required env var '$name' is not set"
    exit 1
  fi
}

assert_clean_git_tree() {
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: git working tree is not clean"
    echo "hint: commit/stash changes before staging deploy"
    exit 1
  fi
}

validate_staging_env() {
  require_env "AISHIELD_API_KEY"
  require_env "AISHIELD_ALLOWED_ORIGINS"

  if [[ "${#AISHIELD_API_KEY}" -lt 24 ]]; then
    echo "error: AISHIELD_API_KEY must be at least 24 characters for staging"
    exit 1
  fi

  if [[ "$AISHIELD_ALLOWED_ORIGINS" == *"*"* ]]; then
    echo "error: AISHIELD_ALLOWED_ORIGINS must not contain '*' in staging"
    exit 1
  fi
}

rollback_to_previous() {
  local previous_commit="$1"
  echo "↩️  Rolling back to previous commit: $previous_commit"

  ./scripts/stop-analytics-stack.sh || true
  git checkout "$previous_commit"
  cargo build -p aishield-analytics
  ./scripts/start-analytics-stack.sh
}

deploy_started_at="$(date +%s)"

echo "== Deploy AIShield Analytics to Staging =="
echo "target ref: $TARGET_REF"
echo

assert_clean_git_tree
validate_staging_env

export AISHIELD_RATE_LIMIT_REQUESTS="${AISHIELD_RATE_LIMIT_REQUESTS:-120}"
export AISHIELD_RATE_LIMIT_SECONDS="${AISHIELD_RATE_LIMIT_SECONDS:-60}"
export AISHIELD_SMOKE_ASSERT_CORS="${AISHIELD_SMOKE_ASSERT_CORS:-1}"
export AISHIELD_SMOKE_ALLOWED_ORIGIN="${AISHIELD_SMOKE_ALLOWED_ORIGIN:-http://localhost:3000}"
export AISHIELD_SMOKE_DISALLOWED_ORIGIN="${AISHIELD_SMOKE_DISALLOWED_ORIGIN:-https://not-allowed.example}"
export AISHIELD_SMOKE_ASSERT_RATE_LIMIT="${AISHIELD_SMOKE_ASSERT_RATE_LIMIT:-1}"
export AISHIELD_SMOKE_RATE_LIMIT_MAX="${AISHIELD_SMOKE_RATE_LIMIT_MAX:-$AISHIELD_RATE_LIMIT_REQUESTS}"

PREVIOUS_COMMIT="$(git rev-parse HEAD)"
git fetch origin
TARGET_COMMIT="$(git rev-parse "$TARGET_REF")"

echo "previous commit: $PREVIOUS_COMMIT"
echo "target commit:   $TARGET_COMMIT"
echo

mkdir -p "$STATE_DIR"

if ! {
  ./scripts/stop-analytics-stack.sh
  git checkout "$TARGET_COMMIT"
  cargo build -p aishield-analytics
  ./scripts/start-analytics-stack.sh
}; then
  echo "❌ Staging deployment failed. Attempting rollback..."
  rollback_to_previous "$PREVIOUS_COMMIT"
  echo "rollback complete"
  exit 1
fi

deploy_duration_seconds="$(( $(date +%s) - deploy_started_at ))"

cat >"$STATE_FILE" <<EOF
PREVIOUS_COMMIT=$PREVIOUS_COMMIT
DEPLOYED_COMMIT=$TARGET_COMMIT
TARGET_REF=$TARGET_REF
DEPLOYED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DEPLOY_DURATION_SECONDS=$deploy_duration_seconds
LAST_ACTION=deploy
EOF

echo
echo "✅ Staging deployment succeeded"
echo "state file: $STATE_FILE"
echo "rollback:   ./scripts/rollback-analytics-staging.sh"
echo "duration:   ${deploy_duration_seconds}s"
