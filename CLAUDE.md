# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AIShield is a Rust-based security scanner that detects vulnerabilities introduced by AI coding assistants. It uses regex/string-based pattern matching (not AST) against YAML-defined rules, with AI-likelihood scoring to estimate whether findings originated from AI autocomplete.

## Build & Test Commands

```bash
# Build
cargo build                          # Debug build
cargo build --release                # Release build
cargo build --release --features onnx  # With ONNX AI classifier

# Test
cargo test                           # All Rust tests
cargo test -p aishield-core          # Core crate only
cargo test -p aishield-cli           # CLI crate only
cargo test -p aishield-analytics     # Analytics crate only
npm run dashboard:test               # Dashboard Node.js tests

# Lint/Format
cargo fmt --all                      # Format all Rust code
cargo fmt --all -- --check           # Check formatting without modifying

# Run the scanner
cargo run -p aishield-cli -- scan /path/to/target
cargo run -p aishield-cli -- scan tests/fixtures   # Scan test fixtures
cargo run -p aishield-cli -- scan . --format json   # JSON output
cargo run -p aishield-cli -- scan . --format sarif --output aishield.sarif
cargo run -p aishield-cli -- fix . --interactive     # TUI fix mode

# Docs site (VitePress, Node.js 20+)
npm install
npm run docs:dev       # Dev server at localhost:5173
npm run docs:build     # Production build

# Dashboard
npm run dashboard:dev  # Dev server

# Analytics stack (requires Docker)
./scripts/start-analytics-stack.sh
./scripts/stop-analytics-stack.sh
```

## Workspace Architecture

Rust workspace with three crates plus Node.js tooling:

### `crates/aishield-core` — Scanning Engine
- `scanner.rs` — File discovery, language detection, directory walking (skips `.git`, `target`, `node_modules`, `.next`, `dist`)
- `rules.rs` — YAML rule parsing, `Rule` struct with `pattern_any`/`pattern_all`/`pattern_not` matching
- `detector.rs` — `Analyzer` that runs rules against source files, produces `Finding`s with `ScanResult`/`ScanSummary`
- `scoring.rs` — Risk score computation: weighted blend of severity (30%), AI likelihood (30%), context risk (20%), exploitability (20%)
- `classifier/` — AI-likelihood scoring with heuristic mode and optional ONNX model (`onnx` feature flag)

Key types exported from `lib.rs`: `Analyzer`, `Finding`, `ScanResult`, `ScanSummary`, `Severity`, `Rule`, `RuleSet`, `AiClassifierOptions`

### `crates/aishield-cli` — Command-Line Interface
- Manual arg parsing (no clap derive macros, uses `env::args()` directly)
- Subcommands: `scan`, `fix`, `bench`, `init`, `create-rule`, `rules`, `stats`, `hook`, `config`, `analytics`
- `analytics_client.rs` — HTTP client for analytics API
- `config.rs` — TOML-based configuration management
- `git_utils.rs` — Git integration for `--changed-from` diffing
- TUI built with `ratatui`/`crossterm` for interactive fix mode

### `crates/aishield-analytics` — Analytics API Server
- Axum-based HTTP service backed by PostgreSQL + TimescaleDB
- `handlers.rs` — API route handlers
- `db.rs` — SQLx database queries
- `models.rs` — Data models for scans/findings
- `auth.rs` — JWT authentication
- Database migrations in `/migrations/` (applied via docker-entrypoint-initdb.d)

### `dashboard/` — Node.js Web Dashboard
- `server.js` — Express server
- `lib/history.js` — Scan history processing
- `lib/ingest.js` — Report ingestion
- Tests: `lib/*.test.js` (run with `node --test`)

### `rules/` — YAML Detection Rules
237 rules across 14 language directories: `python`, `javascript`, `go`, `rust`, `java`, `csharp`, `ruby`, `php`, `kotlin`, `swift`, `terraform`, `kubernetes`, `dockerfile`, `github-actions`

Each rule directory is organized by category (e.g., `rules/python/crypto/`, `rules/python/auth/`, `rules/python/injection/`).

Rule YAML fields: `id`, `title`, `severity`, `confidence_that_ai_generated`, `languages`, `pattern_any`/`pattern_all`/`pattern_not`, `negative_patterns`, `fix.suggestion`, `category`, `cwe_id`, `owasp_category`, `tags`, `ai_tendency`

### Other Directories
- `tests/fixtures/` — Vulnerable code samples per language for integration testing
- `docs/` — VitePress documentation site
- `integrations/vscode-extension/` — VS Code extension
- `models/` — ONNX model and Python training scripts
- `scripts/` — Analytics stack management, deployment, and testing scripts

## Key Architectural Decisions

- **Regex pattern matching over AST**: Deliberate choice for performance and ease of rule authoring. Most AI-introduced vulnerabilities are syntactic patterns. See `ARCHITECTURAL_DECISIONS.md`.
- **PostgreSQL + TimescaleDB over ClickHouse**: More accessible for self-hosting; relational model suits org/team metadata.
- **SAST bridge is manual**: Users must install Semgrep/Bandit/ESLint themselves and enable with `--bridge all`. No auto-installation.

## Development Conventions

- Run `cargo fmt --all` before committing Rust changes
- When adding a rule: create YAML in `rules/<language>/<category>/`, add a corresponding fixture in `tests/fixtures/`, verify with `cargo run -p aishield-cli -- scan tests/fixtures`
- Rule IDs must be stable and unique (format: `AISHIELD-<LANG>-<CATEGORY>-<NNN>`)
- Feature branches off `main`; do not commit directly to main
- CI validates with: `cargo fmt`, `cargo test`, scan with SARIF output, and analytics smoke tests

## CI Workflows (`.github/workflows/`)

- `aishield-scan.yml` — Builds and runs scan on PRs/pushes, uploads SARIF
- `analytics-smoke.yml` — Spins up Docker analytics stack, runs smoke tests with threshold gates
- `docs.yml` — Builds VitePress docs, optional GitHub Pages deploy
- `release.yml` — Creates GitHub releases from tags (`v*.*.*`)

## Output Formats

The CLI supports: plain text (default), `json`, `sarif`, `github` (PR annotations). Dedup modes: `normalized`, `strict`.
