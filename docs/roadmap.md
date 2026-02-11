# Roadmap Snapshot

This page mirrors `project.md` and highlights the current implementation direction.

## Phase 1: Foundation

- [x] Rust workspace (`aishield-core`, `aishield-cli`)
- [x] YAML rule engine + foundational detection coverage
- [x] Multi-format output (`table`, `json`, `sarif`, `github`)
- [x] CLI commands for scan/fix/init/hook/stats/bench
- [x] `init` scaffolding templates for GitHub Actions, GitLab CI, VS Code, and pre-commit
- [x] Documentation site (VitePress)

## Phase 2: Intelligence

- [x] Heuristic AI-likelihood scoring integrated
- [x] SAST bridge normalization and dedup path
- [x] Go/Rust/Java rulepacks expanded toward 20-per-language target
- [x] Interactive fix TUI upgrades (search/filter, badges, preview pane)
- [x] ONNX classifier integration bootstrap (feature-flagged with heuristic fallback)
- [x] ONNX runtime runner bridge integration (model execution path + fallback behavior)
- [x] Trained model distribution and calibration tuning
- [x] Full PR annotation + SARIF workflow hardening across repo contexts

## Phase 3: Platform and Ecosystem Core

- [x] VS Code extension bootstrap (scan commands + diagnostics)
- [x] Advanced VS Code UX beta (hover cards, quick fixes, findings panel, security lens)
- [x] AI paste-detection bootstrap in VS Code extension
- [x] Advanced VS Code UX GA polish and telemetry-informed tuning
- [x] Web dashboard and analytics pipeline bootstrap
- [x] Alerting bootstrap via scan webhooks
- [x] Experimental cross-file auth-route heuristics (`--cross-file`)
- [x] Additional language bootstrap (C#, Ruby, PHP)
- [x] Additional language ecosystems (Kotlin, Swift)
- [x] Expand language rulepack depth toward 20-per-language targets for new ecosystems
- [x] Infra/IaC scanning bootstrap (Terraform, Kubernetes YAML, Dockerfiles)

## Phase 4: Ecosystem Expansion

- [x] C#/Ruby/PHP rulepacks expanded to 20 rules each (auth, crypto, injection, misconfig)
- [x] IaC rules expanded to 15 each (Terraform, Kubernetes, Dockerfile)
- [x] Production-grade GitLab CI template (cache, MR diff scan, SAST report, bridge gating)
- [x] Production-grade Bitbucket Pipelines template (PR diff scan, fail gate, bridge pipeline)
- [x] Expanded test fixtures for all new rules
- [x] Analytics CI threshold gating
- [x] Enterprise multi-repo aggregation (CLI flags for org/team/repo)
- [x] Custom rule marketplace/sharing (`rules install` command)
- [x] Team-level analytics dashboards (supported via schema/API/CLI tagging)

## Phase 5: Usability & Adoption

- [ ] 5.1 — Package Manager Distribution (crates.io, Homebrew tap, npx wrapper, pre-built binaries)
- [ ] 5.2 — Interactive Config Wizard (`aishield init` with dialoguer)
- [ ] 5.3 — Severity Tuning Profiles (`--profile strict|pragmatic|ai-focus`)
- [ ] 5.4 — Watch Mode (`aishield watch` with file-system notifications)
- [ ] 5.5 — PR Comment Bot (GitHub App / Action for inline review comments)
- [ ] 5.6 — Online Playground (WASM-compiled scanner in browser)
- [ ] 5.7 — Dashboard Enhancements (Team/Org views, scan comparison, PDF/CSV export)

## Phase 6: Advanced Security & Woo Factor

- [x] 6.1 — Prompt Injection Detection (15 LLM rules across Python, JS, Go, Java)
- [ ] 6.2 — Supply Chain / Dependency Awareness (OSV API, lockfile parsing)
- [x] 6.3 — Secrets Detection Expansion (15 cross-language rules for AWS, GCP, Azure, GitHub, Slack, Stripe, etc.)
- [ ] 6.4 — Lightweight Taint Analysis (tree-sitter intra-function tracking)
- [ ] 6.5 — SBOM Generation (SPDX 2.3 / CycloneDX 1.5)
- [ ] 6.6 — Signed Scan Reports (Ed25519 cryptographic signatures)
- [ ] 6.7 — AI Vulnerability Score Badge (`--badge` with shields.io)
- [ ] 6.8 — Vibe Check Mode (`--vibe` personality-driven output)
- [ ] 6.9 — VS Code AI Radar Heatmap (gutter overlay for AI confidence)
- [ ] 6.10 — LLM-Powered Auto-Fix Loop (one-click AI-assisted remediation)
- [ ] 6.11 — Browser Extension (WASM scanner for GitHub/GitLab/StackOverflow)

## Long-Term Vision

- AST-based analysis (tree-sitter full cross-file)
- Language Server Protocol (LSP) for multi-editor support
- AIShield Cloud (SaaS with multi-tenant API, SSO, hosted dashboards)

## Milestone Notes

Rule catalog: 268 rules across 14 language categories + cross-language secrets.

CI/CD templates: GitHub Actions, GitLab CI, Bitbucket Pipelines, CircleCI, Jenkins all production-ready with `aishield init --templates all`.

Dependency map for Phase 5-6: see `aishield-build-process.md`.
