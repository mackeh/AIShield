# AIShield GitHub Actions

AIShield includes a workflow at `.github/workflows/aishield.yml` that scans and uploads SARIF.

Release automation is defined at `.github/workflows/release.yml` and runs on version tags (`v*.*.*`).

## What It Does

1. Checks out repository code
2. Installs Rust toolchain
3. Runs AIShield in SARIF mode
4. Uploads `aishield.sarif` to GitHub Code Scanning

## Baseline Workflow

```yaml
name: AIShield Security Scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  actions: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo run -p aishield-cli -- scan . --format sarif --output aishield.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository
        continue-on-error: true
        with:
          sarif_file: aishield.sarif
```

## Common Auth/Permissions Failure

If upload annotations show:

- `Resource not accessible by integration`

check:

- repository has **Code scanning alerts** enabled
- workflow includes `permissions.security-events: write`
- pull request comes from trusted context (fork PRs can restrict tokens)
- SARIF upload is guarded with the same-repo `if:` condition

## Recommended CI Command Variants

```bash
# strict fail on high+ findings (for gating jobs)
cargo run -p aishield-cli -- scan . --staged --severity high --fail-on-findings

# full SARIF artifact with normalized dedup for code scanning
cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif
```

## Local Debugging

Use GitHub CLI:

```bash
gh run list --workflow aishield.yml --limit 5
gh run view <RUN_ID> --log
gh run watch <RUN_ID> --exit-status
```
