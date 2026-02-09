#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

STATE_FILE="${AISHIELD_STAGING_STATE_FILE:-$ROOT_DIR/.aishield-staging/last-deploy.env}"

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
    echo "hint: commit/stash changes before rollback"
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

if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: staging state file not found: $STATE_FILE"
  echo "hint: run ./scripts/deploy-analytics-staging.sh at least once first"
  exit 1
fi

# shellcheck disable=SC1090
source "$STATE_FILE"

TARGET_COMMIT="${1:-${PREVIOUS_COMMIT:-}}"
if [[ -z "$TARGET_COMMIT" ]]; then
  echo "error: no rollback target available"
  exit 1
fi

echo "== Rollback AIShield Analytics Staging =="
echo "target commit: $TARGET_COMMIT"
echo

assert_clean_git_tree
validate_staging_env

export AISHIELD_RATE_LIMIT_REQUESTS="${AISHIELD_RATE_LIMIT_REQUESTS:-120}"
export AISHIELD_RATE_LIMIT_SECONDS="${AISHIELD_RATE_LIMIT_SECONDS:-60}"
export AISHIELD_SMOKE_ASSERT_CORS="${AISHIELD_SMOKE_ASSERT_CORS:-1}"
export AISHIELD_SMOKE_ALLOWED_ORIGIN="${AISHIELD_SMOKE_ALLOWED_ORIGIN:-http://localhost:3000}"
export AISHIELD_SMOKE_DISALLOWED_ORIGIN="${AISHIELD_SMOKE_DISALLOWED_ORIGIN:-https://not-allowed.example}"
export AISHIELD_SMOKE_ASSERT_RATE_LIMIT="${AISHIELD_SMOKE_ASSERT_RATE_LIMIT:-1}"
export AISHIELD_SMOKE_RATE_LIMIT_MAX="${AISHIELD_SMOKE_RATE_LIMIT_MAX:-6}"

./scripts/stop-analytics-stack.sh
git checkout "$TARGET_COMMIT"
cargo build -p aishield-analytics
./scripts/start-analytics-stack.sh

cat >"$STATE_FILE" <<EOF
PREVIOUS_COMMIT=$TARGET_COMMIT
DEPLOYED_COMMIT=$TARGET_COMMIT
TARGET_REF=rollback
DEPLOYED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

echo
echo "✅ Rollback succeeded"
echo "active commit: $TARGET_COMMIT"
