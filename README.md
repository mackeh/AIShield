# AIShield

AIShield is a Rust-based security scanner focused on vulnerabilities commonly introduced by AI-generated code.

It finds high-risk patterns that often look plausible in review but are unsafe in production: timing-unsafe auth checks, weak crypto defaults, injection-prone query building, insecure runtime flags, and related misconfigurations.

## Why AIShield

AI coding assistants increase delivery speed, but they also reproduce insecure examples from public training data. AIShield adds a dedicated guardrail layer for AI-assisted codebases by combining:

- AI-prone vulnerability rulepacks across Python, JavaScript, Go, Rust, and Java
- infrastructure rulepacks for Terraform/HCL, Kubernetes manifests, and Dockerfiles
- AI-likelihood scoring and context-aware risk scoring per finding
- CI-ready outputs (`json`, `sarif`, `github`) with dedup normalization
- practical remediation workflows (`fix`, targeted location fixes, interactive TUI)
- ecosystem integration for GitHub Actions, GitLab CI, Bitbucket Pipelines, CircleCI, Jenkins, VS Code, and pre-commit

## 60-Second Demo

```bash
# from repository root
cargo run -p aishield-cli -- scan tests/fixtures
```

Example summary from fixture scan:

```text
AIShield scan complete: 96 findings across 7 files (92 rules loaded)
Summary: critical=6 high=66 medium=19 low=5 info=0
AI-Generated (estimated): 27 of 96 findings
```

## Demo Pack

A reproducible demo suite is included under `demos/`.

```bash
bash demos/run.sh
```

Generated artifacts:

- `demos/output/scan-table.txt`
- `demos/output/scan.json`
- `demos/output/scan.sarif`
- `demos/output/scan-github.txt`
- `demos/output/fix-dry-run.txt`
- `demos/output/bench.txt`
- `demos/output/stats.txt`

See `demos/README.md` for walkthrough details.

## Quick Start

```bash
# scan current project
cargo run -p aishield-cli -- scan .

# machine output for CI
cargo run -p aishield-cli -- scan . --format json --dedup normalized --output aishield.json

# SARIF for GitHub Code Scanning
cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif

# compare against a baseline report and show only new findings
cargo run -p aishield-cli -- scan . --format sarif --baseline baseline.sarif --output aishield-new.sarif

# enable experimental cross-file auth-route heuristics
cargo run -p aishield-cli -- scan . --cross-file

# send webhook alert for high+ findings
cargo run -p aishield-cli -- scan . --notify-webhook https://hooks.example/security --notify-min-severity high

# GitHub PR annotations
cargo run -p aishield-cli -- scan . --format github --dedup normalized

# interactive remediation TUI
cargo run -p aishield-cli -- fix . --interactive

# benchmark scanner performance
cargo run -p aishield-cli -- bench . --iterations 5 --warmup 1
```

## Bootstrap Integrations

Use `init` to scaffold project wiring quickly:

```bash
# config only
cargo run -p aishield-cli -- init

# scaffold config + common CI/editor/hook templates
cargo run -p aishield-cli -- init --templates all
```

Supported templates:

- `config`
- `github-actions`
- `gitlab-ci`
- `bitbucket-pipelines`
- `circleci`
- `jenkins`
- `vscode`
- `pre-commit`

## Core Commands

- `scan`: run analysis with filters, dedup mode, bridge engines, and output formats
- `fix`: print/apply remediations (`--write`, `--dry-run`, `--interactive`)
- `bench`: benchmark scan throughput and p95 latency
- `stats`: summarize local scan history
- `init`: scaffold config and ecosystem templates
- `create-rule`: scaffold new YAML detection rules
- `hook install`: install local pre-commit scanning hook

Full command reference: `docs/cli.md`

## Documentation

AIShield includes a VitePress docs site with local search and structured navigation.

```bash
npm install
npm run docs:dev
npm run docs:build
```

Key docs:

- `docs/getting-started.md`
- `docs/cli.md`
- `docs/configuration.md`
- `docs/output-formats.md`
- `docs/integrations.md`
- `docs/ci-github-actions.md`
- `docs/rules-authoring.md`
- `docs/contributing.md`
- `docs/releasing.md`

## Contributor Onboarding

- `CONTRIBUTING.md` for setup, workflow, and PR expectations
- `.github/ISSUE_TEMPLATE/` and `.github/PULL_REQUEST_TEMPLATE.md`
- `.vscode/` for recommended extensions and common tasks
- `.gitlab-ci.yml.example` for GitLab CI adoption patterns

## Project Status

Current implementation includes:

- Rust workspace: `aishield-core` + `aishield-cli`
- 90+ rules across auth/crypto/injection/misconfiguration
- expanded Go/Rust/Java rulepacks toward phase-2 target depth
- infrastructure scanning bootstrap for Terraform, Kubernetes, and Dockerfile misconfig patterns
- experimental cross-file auth-route heuristics (`--cross-file`)
- optional SAST bridge for Semgrep/Bandit/ESLint
- hardened SARIF upload and PR annotation workflows across push/PR contexts
- VitePress documentation site + GitHub Pages deployment workflow

Roadmap and milestones: `project.md` and `docs/roadmap.md`

## Security

For vulnerability disclosure, follow `SECURITY.md`.
