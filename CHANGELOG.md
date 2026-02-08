# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog and follows semantic versioning.

## [Unreleased]

### Added

- `github` scan output format for GitHub Actions inline PR annotations
- CI workflow step to emit AIShield PR annotations alongside SARIF upload
- `scan --changed-from <ref>` to scope scans/annotations to changed files
- Optional SAST bridge (`--bridge`) for Semgrep/Bandit/ESLint with parallel execution
- Bridge findings normalized into unified AIShield result schema with dedup
- CI workflow optionally installs bridge tools (enabled by default, toggle via repo vars)
- SARIF/GitHub annotation rendering now clamps line/column to valid 1-based values
- Added initial Go/Rust/Java language scanning support with starter rulepacks and fixtures
- Added `bench` command for repeatable scan-time benchmarking with table/JSON output
- Added `fix --interactive` groundwork for prompt-driven autofix selection (`yes/no/all/quit`)
- Added `fix <path:line[:col]>` targeting to focus remediation on a specific finding location
- Expanded safe autofix replacements for additional JavaScript/Java crypto and debug patterns
- Expanded safe autofix coverage to priority Python/JavaScript/Go/Java rules (toward top-20 remediation target)
- Upgraded `fix --interactive` to a keyboard-driven TUI MVP using ratatui
- Added TUI search/filter mode, severity badges, and preview diff pane for interactive fixes
- Upgraded risk scoring with context/exploitability heuristics (sensitive path boosts, sink signals, fixture/test dampening)
- Expanded Go/Rust/Java rulepacks to 20 rules each with corresponding fixture coverage
- Strengthened tests to enforce phase-2 rule depth and per-language fixture detection coverage
- Expanded Go/Rust/Java vulnerable fixtures to exercise new auth/crypto/injection/misconfig rules
- Added heuristic AI-likelihood classifier in core (path/snippet signals) and wired risk scoring to dynamic AI confidence
- Added web dashboard + analytics pipeline bootstrap (`dashboard/`) with trend KPIs and top-rule/target views
- Added report ingestion utility for AIShield JSON/SARIF artifacts (`dashboard/scripts/ingest-report.js`)
- Added dashboard sample-history generator and Node tests for analytics/history parsing logic
- Expanded Kotlin/Swift rulepacks with additional auth/crypto/injection/misconfig detections and fixture coverage
- Strengthened regression assertions for Kotlin/Swift fixture findings and minimum repository rule depth

## [0.1.1] - 2026-02-07

### Added

- Release automation workflow on tag push (`.github/workflows/release.yml`)
- Published security policy (`SECURITY.md`)

## [0.1.0] - 2026-02-07

### Added

- Initial Rust workspace with `aishield-core` and `aishield-cli`
- Foundation scanner and rule engine for Python and JavaScript
- Foundational rulepack expanded to 32 rules with fixture coverage
- Output renderers for table, JSON, and SARIF
- GitHub Actions security scan workflow with SARIF upload
- Config loading and report file output support
- Staged-only scanning and path exclusion controls
- Suppression markers and improved scan analytics
- Local scan history tracking and `stats` command
- Autofix support (`fix --write`, `fix --dry-run`)
- Rule scaffolding command (`create-rule`)
- Machine-output dedup normalization for JSON/SARIF to reduce CI noise
- Expanded documentation for CLI, configuration, outputs, and CI

[Unreleased]: https://github.com/mackeh/AIShield/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/mackeh/AIShield/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mackeh/AIShield/releases/tag/v0.1.0
