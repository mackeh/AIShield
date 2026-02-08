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
- [ ] ONNX AI-vs-human classifier integration
- [ ] Full PR annotation + SARIF workflow hardening across all repo contexts

## Phase 3+: Platform and Ecosystem

- [ ] VS Code extension
- [ ] Web dashboard and analytics pipeline
- [x] Alerting bootstrap via scan webhooks
- [x] Experimental cross-file auth-route heuristics (`--cross-file`)
- [ ] Additional language ecosystems (C#, Ruby, PHP, Kotlin, Swift)
- [x] Infra/IaC scanning bootstrap (Terraform, Kubernetes YAML, Dockerfiles)

## Milestone Notes

Near-term focus is reliability and signal quality:

- reduce duplicate/noisy findings in CI
- improve remediation coverage and fix confidence
- harden release and security workflows
