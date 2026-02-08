# Integrations

AIShield is built to plug into common developer workflows.

## VS Code

AIShield ships workspace recommendations and task shortcuts:

- `.vscode/extensions.json`
- `.vscode/tasks.json`

Recommended tasks:

- `AIShield: test`
- `AIShield: scan workspace`
- `AIShield: build docs`
- `AIShield: docs dev server`

You can run tasks from **Terminal -> Run Task**.

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

## Pre-commit Hooks

Install local hook:

```bash
cargo run -p aishield-cli -- hook install --severity high
```

This defaults to staged-file scanning for fast developer feedback.

## Local Automation

Useful local commands:

```bash
cargo test
cargo run -p aishield-cli -- scan .
npm run docs:build
```
