# AIShield GitHub Actions

AIShield includes a workflow at `.github/workflows/aishield.yml` that scans and uploads SARIF.

Release automation is defined at `.github/workflows/release.yml` and runs on version tags (`v*.*.*`).

Documentation deployment is defined at `.github/workflows/docs.yml` and publishes the VitePress site to GitHub Pages.

You can scaffold a baseline scan workflow in a new project with:

```bash
cargo run -p aishield-cli -- init --templates github-actions
```

## What It Does

1. Checks out repository code
2. Installs Rust toolchain
3. Runs AIShield in SARIF mode
4. Emits inline PR annotations on pull requests
5. Uploads `aishield.sarif` to GitHub Code Scanning

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

env:
  AISHIELD_ENABLE_SAST_BRIDGE: ${{ vars.AISHIELD_ENABLE_SAST_BRIDGE || 'true' }}
  AISHIELD_BRIDGE_ENGINES: ${{ vars.AISHIELD_BRIDGE_ENGINES || 'all' }}

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: dtolnay/rust-toolchain@stable
      - run: |
          if [ "${AISHIELD_ENABLE_SAST_BRIDGE}" = "true" ]; then
            echo "AISHIELD_BRIDGE_ARGS=--bridge ${AISHIELD_BRIDGE_ENGINES}" >> "$GITHUB_ENV"
          else
            echo "AISHIELD_BRIDGE_ARGS=" >> "$GITHUB_ENV"
          fi
      - if: env.AISHIELD_ENABLE_SAST_BRIDGE == 'true'
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - if: env.AISHIELD_ENABLE_SAST_BRIDGE == 'true'
        run: |
          python -m pip install --upgrade pip
          pip install semgrep bandit
      - if: env.AISHIELD_ENABLE_SAST_BRIDGE == 'true'
        uses: actions/setup-node@v4
        with:
          node-version: "20"
      - if: env.AISHIELD_ENABLE_SAST_BRIDGE == 'true'
        run: npm install -g eslint
      - run: cargo run -p aishield-cli -- scan . --format sarif --output aishield.sarif ${AISHIELD_BRIDGE_ARGS}
      - if: github.event_name == 'pull_request'
        run: cargo run -p aishield-cli -- scan . --format github --dedup normalized --changed-from "${{ github.event.pull_request.base.sha }}" ${AISHIELD_BRIDGE_ARGS}
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

## Bridge Controls

Bridge installation and bridge findings are enabled by default.

Optional repository variables:

- `AISHIELD_ENABLE_SAST_BRIDGE`: `true` (default) or `false`
- `AISHIELD_BRIDGE_ENGINES`: engine list passed to `--bridge` (default `all`)

## Recommended CI Command Variants

```bash
# strict fail on high+ findings (for gating jobs)
cargo run -p aishield-cli -- scan . --staged --severity high --fail-on-findings

# full SARIF artifact with normalized dedup for code scanning
cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif

# PR-only annotations scoped to changed files
cargo run -p aishield-cli -- scan . --format github --dedup normalized --changed-from "$BASE_SHA"

# compare against prior SARIF baseline (new findings only)
cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --baseline previous.sarif --output aishield-new.sarif

# include external bridges (if tools are installed in runner)
cargo run -p aishield-cli -- scan . --format sarif --bridge semgrep,bandit,eslint --output aishield.sarif
```

## Local Debugging

Use GitHub CLI:

```bash
gh run list --workflow aishield.yml --limit 5
gh run view <RUN_ID> --log
gh run watch <RUN_ID> --exit-status
```

For docs workflow runs:

```bash
gh run list --workflow docs.yml --limit 5
gh run watch <RUN_ID> --exit-status
```

For GitLab adoption patterns, see `docs/integrations.md` and `.gitlab-ci.yml.example`.

## Docs Site Deployment (GitHub Pages)

The docs workflow builds and publishes `docs/.vitepress/dist` using GitHub Pages Actions.

### Trigger Conditions

- push to `main` affecting:
  - `docs/**`
  - `package.json`
  - `package-lock.json`
  - `.github/workflows/docs.yml`
- manual run via `workflow_dispatch`

### Required Repository Setting

In **Settings → Pages**, set source to **GitHub Actions**.

### Workflow Summary

1. Checkout repository
2. Set up Node.js 20 with npm cache
3. Run `npm ci`
4. Run `npm run docs:build`
5. Upload Pages artifact
6. Deploy artifact to GitHub Pages environment
