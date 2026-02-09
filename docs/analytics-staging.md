# Analytics Staging Deploy

This runbook provides a safe path to deploy and rollback the analytics API stack in a staging environment.

## Prerequisites

- Staging host has this repository checked out
- Docker + Docker Compose available
- Rust toolchain installed (for rebuilding `aishield-analytics`)
- Clean git working tree on the staging host

Required environment variables:

```bash
export AISHIELD_API_KEY="your-long-staging-api-key"
export AISHIELD_ALLOWED_ORIGINS="https://staging-dashboard.example.com"
```

Optional hardening knobs (defaults shown):

```bash
export AISHIELD_RATE_LIMIT_REQUESTS=120
export AISHIELD_RATE_LIMIT_SECONDS=60
export AISHIELD_SMOKE_ASSERT_CORS=1
export AISHIELD_SMOKE_ASSERT_RATE_LIMIT=1
```

## Deploy

Deploy latest `origin/main`:

```bash
./scripts/deploy-analytics-staging.sh
```

Deploy a specific ref:

```bash
./scripts/deploy-analytics-staging.sh v0.3.2
```

What the script does:

1. Validates staging env (`AISHIELD_API_KEY`, strict CORS allowlist).
2. Verifies git working tree is clean.
3. Stops current analytics stack.
4. Checks out target ref/commit.
5. Rebuilds analytics API binary.
6. Starts stack and runs smoke + hardening assertions.
7. Writes deploy state to `.aishield-staging/last-deploy.env`.

## Rollback

Rollback to the previously deployed commit:

```bash
./scripts/rollback-analytics-staging.sh
```

Rollback to an explicit commit:

```bash
./scripts/rollback-analytics-staging.sh <commit-sha>
```

The rollback script stops the running stack, checks out target commit, rebuilds, and re-runs smoke/hardening checks before confirming success.

## Burn-in Observation

Capture live signal quality during staging burn-in:

```bash
AISHIELD_API_KEY="your-long-staging-api-key" \
AISHIELD_ANALYTICS_URL="http://localhost:8080" \
AISHIELD_ORG_ID="test_org_1" \
AISHIELD_BURNIN_ITERATIONS=12 \
AISHIELD_BURNIN_INTERVAL_SECONDS=10 \
./scripts/observe-analytics-signal.sh
```

Outputs:

- Raw samples: `.aishield-staging/analytics-signal-<run-id>.csv`
- Markdown report: `.aishield-staging/analytics-signal-<run-id>.md`
- Latest report alias: `.aishield-staging/analytics-signal-latest.md`

Default SLO gates enforced by the script:

- Error rate <= `1.0%`
- p95 latency <= `1500ms` for `summary`, `compliance-gaps`, `ai-metrics`
- Coverage minimum >= `70%` when coverage metrics are available

Tune with env vars:

- `AISHIELD_BURNIN_MAX_ERROR_RATE_PCT`
- `AISHIELD_BURNIN_MAX_P95_MS`
- `AISHIELD_BURNIN_MIN_COVERAGE_PCT`
- `AISHIELD_BURNIN_EXIT_ON_FAILURE=0` to keep non-blocking behavior

For stricter staging after metadata backfill is complete, set:

```bash
export AISHIELD_BURNIN_MIN_COVERAGE_PCT=85
```

## Notes

- Deploy script performs an automatic rollback if deployment validation fails.
- State file path is ignored by git: `.aishield-staging/`.
