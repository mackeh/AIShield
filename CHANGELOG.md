# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog and follows semantic versioning.

## [Unreleased]

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
