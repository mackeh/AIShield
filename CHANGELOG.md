# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog and follows semantic versioning.

## [Unreleased]

### Added

- No unreleased entries yet.

## [0.3.1] - 2026-02-08

### Fixed

- Analytics stack startup now waits for API health before executing smoke checks, improving CI reliability in cold-start environments
- Docs workflow stabilized to avoid hard failure when GitHub Pages is not configured for deployment
- Resolved VitePress dead links across contributor guides and database setup documentation

### Changed

- Added a dedicated docs testing guide page (`docs/guides/testing-guide.md`) and refreshed guide cross-links

## [0.3.0] - 2026-02-08

### Added

- Analytics platform milestone: PostgreSQL/TimescaleDB ingestion pipeline, Axum API service, and dashboard API mode with trend/report endpoints
- One-command analytics stack lifecycle scripts (`scripts/start-analytics-stack.sh`, `scripts/stop-analytics-stack.sh`) with smoke-test bootstrap
- Dedicated analytics smoke CI workflow for PR/push validation (`.github/workflows/analytics-smoke.yml`)
- CLI analytics payload enrichment with inferred compliance metadata (`cwe_id`, `owasp_category`) plus regression tests
- API hardening upgrades: configurable CORS allowlist and request rate limiting

### Changed

- Updated project/testing/quickstart docs to reflect current Week 5 reliability-hardening status and stack workflow
- Removed obsolete Docker Compose `version` key from analytics stack config

## [0.2.0] - 2026-02-08

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
- Reached Kotlin/Swift phase-2 depth milestone (20 rules each) with updated rule-depth gates
- Added ONNX model manifest support (`--onnx-manifest`) and calibration profiles (`--ai-calibration`)
- Tuned classifier blending to use configurable calibration settings from profile/manifest
- Polished VS Code extension for GA: status bar UX, debounced auto-scan controls, diagnostics cap, and local telemetry summaries

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

[Unreleased]: https://github.com/mackeh/AIShield/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/mackeh/AIShield/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mackeh/AIShield/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mackeh/AIShield/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/mackeh/AIShield/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mackeh/AIShield/releases/tag/v0.1.0
