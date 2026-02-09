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

## Notes

- Deploy script performs an automatic rollback if deployment validation fails.
- State file path is ignored by git: `.aishield-staging/`.
