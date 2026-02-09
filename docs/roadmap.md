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
- [ ] Enterprise multi-repo aggregation
- [ ] Custom rule marketplace/sharing
- [ ] Team-level analytics dashboards

## Milestone Notes

Rule catalog: 237 rules across 13 languages (all application languages at 20 rules, IaC at 15 each).

CI/CD templates: GitHub Actions, GitLab CI, Bitbucket Pipelines, CircleCI, Jenkins all production-ready with `aishield init --templates all`.

Near-term focus:
- enterprise multi-repo features
- custom rule sharing and marketplace
- team-level analytics and RBAC
