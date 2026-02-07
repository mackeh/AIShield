# AIShield

AIShield is a security scanner focused on vulnerabilities commonly introduced by AI-generated code.

It is designed to catch high-risk patterns that look plausible in review but are unsafe in production, such as timing-unsafe auth checks, weak crypto usage, unsafe HTML rendering, and injection-prone query building.

## Why this project exists

AI coding assistants increase development speed, but they also repeat insecure patterns from public examples and outdated snippets. AIShield adds a dedicated security layer for AI-assisted development by combining:

- Rule-based detection for AI-prone vulnerabilities
- AI-confidence metadata per rule
- Context-aware risk scoring
- CLI + CI + pre-commit integration

## Current implementation status

This repository currently contains a solid foundation for Phase 1:

- Rust workspace with `aishield-core` and `aishield-cli`
- Rule-driven scanner for Python and JavaScript source files
- 32 foundational rules across crypto, injection, auth, and misconfiguration
- Severity + composite risk scoring per finding
- Output formats: `table`, `json`, `sarif`, `github` (PR annotations)
- Optional SAST bridge for Semgrep, Bandit, and ESLint (parallel orchestration)
- Config support via `.aishield.yml`
- Report file output via `--output`
- Scan history tracking plus `aishield stats --last Nd` analytics
- Local pre-commit hook installer
- GitHub Actions workflow uploading SARIF to GitHub Security
- Expanded vulnerable fixture suite and regression tests for rule coverage

## Project structure

```text
crates/
  aishield-core/   # scanner engine, rule parsing, scoring
  aishield-cli/    # CLI commands and output renderers
rules/             # YAML rules grouped by language/category
docs/              # authoring and project docs
tests/fixtures/    # vulnerable sample files
.github/workflows/ # CI scans + SARIF upload
```

## Documentation

- `docs/cli.md`: command reference and options
- `docs/configuration.md`: `.aishield.yml` keys, defaults, and precedence
- `docs/output-formats.md`: table/json/sarif schemas and dedup behavior
- `docs/ci-github-actions.md`: GitHub Actions integration and troubleshooting
- `docs/releasing.md`: release and version-tag workflow
- `docs/rules-authoring.md`: custom rule authoring guide
- `CHANGELOG.md`: curated release history
- `SECURITY.md`: vulnerability reporting policy and support window

## Quick start

```bash
# scan current project
cargo run -p aishield-cli -- scan .

# scan while excluding generated/vendor paths
cargo run -p aishield-cli -- scan . --exclude vendor/,dist/,node_modules/

# scan only staged files (fast pre-commit mode)
cargo run -p aishield-cli -- scan . --staged

# machine-readable output
cargo run -p aishield-cli -- scan . --format json

# GitHub Security compatible output
cargo run -p aishield-cli -- scan . --format sarif --output aishield.sarif

# GitHub Actions annotation output
cargo run -p aishield-cli -- scan . --format github

# run built-in rules + external SAST engines (if installed)
cargo run -p aishield-cli -- scan . --bridge semgrep,bandit,eslint

# disable machine-output dedup if needed
cargo run -p aishield-cli -- scan . --format sarif --dedup none

# initialize local config
cargo run -p aishield-cli -- init

# install a pre-commit gate
cargo run -p aishield-cli -- hook install --severity high

# view local scan analytics (last 30 days by default)
cargo run -p aishield-cli -- stats --last 30d
```

## CLI commands

### `scan`

```bash
aishield scan <path> \
  [--rules-dir DIR] \
  [--format table|json|sarif|github] \
  [--dedup none|normalized] \
  [--bridge semgrep,bandit,eslint|all] \
  [--rules auth,crypto] \
  [--exclude vendor/,dist/] \
  [--ai-only] \
  [--min-ai-confidence N] \
  [--severity LEVEL] \
  [--fail-on-findings] \
  [--staged|--changed-from REF] \
  [--output FILE] \
  [--history-file FILE] \
  [--no-history] \
  [--config FILE] \
  [--no-config]
```

### `fix`

```bash
aishield fix <path> [--rules-dir DIR] [--write] [--dry-run] [--config FILE] [--no-config]
```

`--write` applies available safe autofixes in-place for supported rules.  
`--dry-run` reports what would change without writing files.

### `init`

```bash
aishield init [--output PATH]
```

### `create-rule`

```bash
aishield create-rule \
  --id AISHIELD-PY-AUTH-999 \
  --title "Timing Unsafe Session Compare" \
  --language python \
  --category auth \
  --severity high \
  --pattern-any "session_token == " \
  --pattern-not "compare_digest(" \
  --tags auth,timing-attack \
  --suggestion "Use hmac.compare_digest for secret comparisons."
```

This scaffolds a new YAML rule under `rules/<language>/<category>/`.

### `hook install`

```bash
aishield hook install [--severity LEVEL] [--path TARGET] [--all-files]
```

By default the installed hook scans only staged files. Use `--all-files` to force full-path scans in pre-commit.

### `stats`

```bash
aishield stats [--last Nd] [--history-file FILE] [--format table|json] [--config FILE] [--no-config]
```

## Configuration

Example `.aishield.yml`:

```yaml
version: 1
rules_dir: rules
format: table
dedup_mode: normalized
bridge_engines: []
rules: [auth]
exclude_paths: [vendor/, node_modules/, dist/]
ai_only: false
min_ai_confidence: 0.70
severity_threshold: medium
fail_on_findings: false
history_file: .aishield-history.log
record_history: true
```

CLI flags override config values.

`dedup_mode` controls machine-output normalization (`json`/`sarif`) to reduce duplicate findings in CI.  
Default behavior is `normalized` for machine formats and `none` for table output.

`bridge_engines` enables optional external SAST orchestration (`semgrep`, `bandit`, `eslint`) when available.

## Rule engine overview

Rules are YAML files with metadata and pattern logic.

Pattern fields supported:

- `pattern.any`: at least one must match on a line
- `pattern.all`: all must match on the same line
- `pattern.not`: none must match on that line
- `pattern.contains`: compatibility alias for `pattern.any`

See `docs/rules-authoring.md` for full details and examples.

Suppression markers (for intentional exceptions):

- `aishield:ignore` on a line comment suppresses the next line finding (or same line inline).
- `aishield:ignore <RULE_ID>` suppresses only that rule.
- `aishield:ignore-file` suppresses all findings in the file.
- `aishield:ignore-file <RULE_ID>` suppresses only a specific rule across the file.

## CI integration

A workflow is included at `.github/workflows/aishield.yml` to:

1. Run AIShield in SARIF mode
2. Emit inline PR annotations (on pull requests)
3. Upload `aishield.sarif` to GitHub Security (`code scanning alerts`)

PR annotations are scoped to files changed since the PR base commit using `--changed-from`.
Bridge tool installation (Semgrep/Bandit/ESLint) is enabled by default in CI and can be toggled with repository variable `AISHIELD_ENABLE_SAST_BRIDGE=false`.

See `docs/ci-github-actions.md` for permissions details and runbook-style troubleshooting.

Release creation is automated by `.github/workflows/release.yml` on `v*.*.*` tag pushes.

## Roadmap focus

Near-term priorities:

- More high-signal rule coverage across auth/crypto/injection/misconfig
- More precise matching semantics and fewer false positives
- Better remediation output and fix workflows
- Additional language support and deeper static analysis

## Goal

AIShield aims to become the practical security guardrail for AI-assisted coding workflows: fast enough for pre-commit, clear enough for developers, and structured enough for CI and governance.
