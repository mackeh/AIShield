# Integrations

AIShield is built to plug into common developer workflows.

You can scaffold these integrations quickly:

```bash
cargo run -p aishield-cli -- init --templates all
```

## VS Code

AIShield ships workspace recommendations and task shortcuts:

- `.vscode/extensions.json`
- `.vscode/tasks.json`

AIShield also includes a VS Code extension bootstrap:

- `integrations/vscode-extension`

Recommended tasks:

- `AIShield: test`
- `AIShield: scan workspace`
- `AIShield: build docs`
- `AIShield: docs dev server`

You can run tasks from **Terminal -> Run Task**.

Extension quick start:

```bash
cd integrations/vscode-extension
npm install
npm run build
```

See `docs/vscode-extension.md` for commands and settings.

Current extension UX includes:

- diagnostics in Problems panel
- hover cards with AI/risk context
- quick-fix code actions via `aishield fix --write`
- AIShield Findings explorer view
- AI paste-detection heuristics with optional auto-scan
- optional security-lens line highlighting
- status bar scan summaries
- local telemetry summary + latency-based tuning hints

## GitHub Actions

Existing workflows:

- `.github/workflows/aishield.yml`: scan + PR annotations + SARIF upload
- `.github/workflows/release.yml`: tag-based release automation
- `.github/workflows/docs.yml`: VitePress build and GitHub Pages deployment

Typical scan command used in CI:

```bash
cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif
```

Enable bridge findings (Semgrep/Bandit/ESLint):

```bash
cargo run -p aishield-cli -- scan . --format sarif --bridge all --dedup normalized --output aishield.sarif
```

## GitLab CI

Use `.gitlab-ci.yml.example` as a starting point.

Or generate `.gitlab-ci.yml` directly with:

```bash
cargo run -p aishield-cli -- init --templates gitlab-ci
```

Quick-start snippet:

```yaml
stages: [scan]

scan:aishield:
  stage: scan
  image: rust:1.84
  script:
    - cargo build --workspace
    - cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif
  artifacts:
    paths: [aishield.sarif]
```

## Bitbucket Pipelines

Generate a baseline Bitbucket pipeline:

```bash
cargo run -p aishield-cli -- init --templates bitbucket-pipelines
```

This writes `bitbucket-pipelines.yml` with PR/main scan jobs and scan artifact publishing.

## CircleCI

Generate CircleCI config:

```bash
cargo run -p aishield-cli -- init --templates circleci
```

This writes `.circleci/config.yml` with a scan workflow and SARIF artifact storage.

## Jenkins

Generate a Jenkins declarative pipeline:

```bash
cargo run -p aishield-cli -- init --templates jenkins
```

This writes `Jenkinsfile` with build + scan stages and SARIF artifact archiving.

## Pre-commit Hooks

Install local hook:

```bash
cargo run -p aishield-cli -- hook install --severity high
```

This defaults to staged-file scanning for fast developer feedback.

## Webhooks (Alerting Bootstrap)

Send alert payloads to webhook endpoints (Slack-compatible relays, internal alert routers, etc.):

```bash
cargo run -p aishield-cli -- scan . \
  --notify-webhook https://hooks.example/security \
  --notify-min-severity high
```

Config and env support:

- `.aishield.yml`: `notify_webhook_url`, `notify_min_severity`
- environment override: `AISHIELD_NOTIFY_WEBHOOK`

## Local Dashboard + Analytics Pipeline

Start dashboard:

```bash
npm run dashboard:dev
```

Ingest scan artifacts into history:

```bash
npm run dashboard:ingest -- --input aishield.json --target github-actions/main
```

Use this when scans run in CI and you want local trend analytics from exported reports.

## Local Automation

Useful local commands:

```bash
cargo test
cargo run -p aishield-cli -- scan .
cargo run -p aishield-cli --features onnx -- scan . --ai-model onnx --onnx-model models/ai-classifier/model.onnx
npm run docs:build
```
