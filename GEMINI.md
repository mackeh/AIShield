# AIShield Context for Gemini Agents

## Project Overview

**AIShield** is a high-performance security scanner written in Rust, specifically designed to detect vulnerabilities introduced by AI coding assistants (Copilot, ChatGPT, etc.). It identifies insecure patterns that are syntactically correct but semantically dangerous (e.g., timing attacks, weak crypto defaults, hallucinated packages).

*   **Status:** Production-ready (Version 0.4.0+).
*   **Core Philosophy:** Speed (sub-2s scans), AI-specific detection (confidence scoring), and local-first architecture.
*   **Primary Languages:** Rust (Core/CLI/Analytics), Node.js (Dashboard/Docs), Python (Model training).

## Architecture & Structure

The project is a Rust workspace with supporting Node.js applications.

### Directory Structure

*   `crates/`
    *   `aishield-core`: The scanning engine, rule parser, and analysis logic.
    *   `aishield-cli`: The command-line interface entry point.
    *   `aishield-analytics`: Axum-based API service for centralized metrics (requires Postgres/TimescaleDB).
*   `dashboard/`: A Node.js web application for visualizing scan history and metrics locally.
*   `docs/`: VitePress-based documentation site.
*   `rules/`: YAML-based detection rules organized by language (e.g., `rules/python/crypto`).
*   `models/`: Contains the ONNX model and Python scripts for the AI classifier.
*   `tests/fixtures/`: Vulnerable code samples used for integration testing.

### Key Architectural Decisions

*   **Detection Engine:** Uses **Regex and string-based pattern matching** rather than ASTs. This is a deliberate choice for performance and ease of rule authoring, as most AI hallucinations are syntactic.
*   **Analytics:** Uses **PostgreSQL + TimescaleDB** (via Docker) for the enterprise/team analytics stack, replacing the originally planned ClickHouse.
*   **SAST Bridge:** Integration with external tools (Semgrep, Bandit, ESLint) is **manual**; the user must install the tools and enable them via flags.

## Build & Run Instructions

### Rust (Core & CLI)

**Prerequisite:** Rust 1.75+

*   **Build Release:** `cargo build --release`
*   **Run CLI:** `cargo run -p aishield-cli -- <command> <args>`
    *   *Example Scan:* `cargo run -p aishield-cli -- scan .`
    *   *Example Fix:* `cargo run -p aishield-cli -- fix . --interactive`
*   **Test:** `cargo test`
*   **Format:** `cargo fmt --all`

### Dashboard (Node.js)

**Prerequisite:** Node.js 20+

*   **Install Dependencies:** `npm install` (in root)
*   **Run Dev Server:** `npm run dashboard:dev` (runs on port 4318)
*   **Test:** `npm run dashboard:test`

### Documentation

*   **Run Dev Server:** `npm run docs:dev` (runs on port 5173)

### Full Stack (Analytics)

*   **Start Stack:** `./scripts/start-analytics-stack.sh` (Requires Docker)
*   **Stop Stack:** `./scripts/stop-analytics-stack.sh`

## Development Conventions

*   **Code Style:** Strict adherence to `cargo fmt` for Rust.
*   **Testing:**
    *   Unit tests in Rust modules.
    *   Integration tests via `tests/fixtures`.
    *   When adding a rule, **always** add a corresponding fixture to prove detection.
*   **Rule Authoring:** Rules are defined in YAML. Key fields: `id`, `title`, `severity`, `languages`, `pattern`, `fix.suggestion`. See `docs/rules-authoring.md`.
*   **Workflows:** Create feature branches. Do not commit directly to main.

## Common Tasks for Agents

1.  **Adding a Rule:**
    *   Create a YAML file in `rules/<language>/<category>/`.
    *   Create a vulnerable code file in `tests/fixtures/`.
    *   Verify with `cargo run -p aishield-cli -- scan tests/fixtures`.

2.  **Fixing a Bug:**
    *   Identify the crate (`core` vs `cli`).
    *   Write a failing test case.
    *   Implement fix and verify with `cargo test`.

3.  **Updating Docs:**
    *   Edit Markdown files in `docs/`.
    *   Verify changes with `npm run docs:dev`.

## Troubleshooting

*   **Scan finds nothing?** Check `.aishield-ignore` or default ignores.
*   **Build fails?** Ensure strict dependency versions in `Cargo.toml`.
*   **Bridge tools missing?** Remind user to install them (Semgrep, Bandit, etc.) manually.
