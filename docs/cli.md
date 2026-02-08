# AIShield CLI Reference

This document is the command reference for `aishield-cli`.

## Command Summary

```bash
aishield scan <path> [options]
aishield fix <path> [options]
aishield bench <path> [options]
aishield init [options]
aishield create-rule [options]
aishield hook install [options]
aishield stats [options]
```

## `scan`

Run security analysis against a file or directory.

```bash
aishield scan <path> \
  [--rules-dir DIR] \
  [--format table|json|sarif|github] \
  [--dedup none|normalized] \
  [--bridge semgrep,bandit,eslint|all] \
  [--rules c1,c2] \
  [--exclude p1,p2] \
  [--ai-only] \
  [--cross-file] \
  [--ai-model heuristic|onnx] \
  [--onnx-model FILE] \
  [--min-ai-confidence N] \
  [--severity LEVEL] \
  [--fail-on-findings] \
  [--staged|--changed-from REF] \
  [--output FILE] \
  [--baseline FILE] \
  [--notify-webhook URL] \
  [--notify-min-severity LEVEL] \
  [--history-file FILE] \
  [--no-history] \
  [--config FILE] \
  [--no-config]
```

Options:

- `--rules-dir DIR`: rules directory (default `rules`)
- `--format`: output format (`table`, `json`, `sarif`, `github`)
- `--dedup`: machine-output dedup mode (`none`, `normalized`)
- `--bridge`: optional external SAST engines (`semgrep`, `bandit`, `eslint`, or `all`)
- `--rules`: comma-separated category filters (`auth,crypto,injection,...`)
- `--exclude`: comma-separated path fragments to skip
- `--ai-only`: only run rules at/above AI-confidence threshold
- `--cross-file`: enable experimental cross-file auth-route heuristics
- `--ai-model`: AI-likelihood scoring mode (`heuristic` default, `onnx` optional)
- `--onnx-model FILE`: path to ONNX model (auto-enables `onnx` mode when set)
- `--min-ai-confidence N`: threshold for `--ai-only` in `0.0..1.0`
- `--severity LEVEL`: minimum severity gate (`critical|high|medium|low|info`)
- `--fail-on-findings`: return exit code `2` when findings exist
- `--staged`: scan only staged files under target path
- `--changed-from REF`: scan only files changed from a git ref (for example PR base SHA)
- `--output FILE`: write report to file instead of stdout
- `--baseline FILE`: suppress findings already present in an existing AIShield JSON/SARIF report
- `--notify-webhook URL`: send scan alert payload to webhook endpoint
- `--notify-min-severity LEVEL`: minimum severity that triggers webhook notification (default `high`)
- `--history-file FILE`: override history log file
- `--no-history`: disable history append for this run
- `--config FILE`: config file path (default `.aishield.yml`)
- `--no-config`: ignore config file

Examples:

```bash
# full scan in table mode
cargo run -p aishield-cli -- scan .

# staged-only scan for pre-commit speed
cargo run -p aishield-cli -- scan . --staged --severity high --fail-on-findings

# changed-files scan for CI pull requests
cargo run -p aishield-cli -- scan . --format github --changed-from origin/main

# json for CI systems
cargo run -p aishield-cli -- scan . --format json --output aishield.json

# SARIF for GitHub code scanning
cargo run -p aishield-cli -- scan . --format sarif --output aishield.sarif

# baseline compare: show only newly introduced findings
cargo run -p aishield-cli -- scan . --format sarif --baseline previous.sarif --output aishield-new.sarif

# enable experimental cross-file route auth checks
cargo run -p aishield-cli -- scan . --cross-file

# use ONNX classifier path (falls back to heuristic if unavailable)
cargo run -p aishield-cli -- scan . --ai-model onnx --onnx-model models/aishield.onnx

# send alerts to webhook for high+ findings
cargo run -p aishield-cli -- scan . --notify-webhook https://hooks.example/security --notify-min-severity high

# inline GitHub Actions annotations
cargo run -p aishield-cli -- scan . --format github

# bridge mode (requires local tool installation)
cargo run -p aishield-cli -- scan . --bridge all
```

## `fix`

Print or apply safe autofixes for supported rules.

```bash
aishield fix <path[:line[:col]]> [--rules-dir DIR] [--write|--interactive] [--dry-run] [--config FILE] [--no-config]
```

Options:

- `--write`: apply changes in place
- `--dry-run`: show planned edits without writing
- `--interactive`: open interactive TUI selection/apply flow
- supports safe replacements for a growing high-frequency rule set across Python/JavaScript/Go/Java

Interactive TUI controls:

- `↑/↓` or `k/j`: move selection
- `space`: toggle highlighted candidate
- `a`: select all candidates
- `c`: clear all selections
- `enter`: apply selected (or highlighted item if none selected)
- `q`/`esc`: cancel

TUI enhancements:

- `/`: enter search/filter mode
- type query terms to filter candidate list (match by rule, file, title, severity)
- `backspace`: remove search characters
- `enter`/`esc` in search mode: exit search mode
- severity badges are shown per row for quick prioritization
- right-side preview diff pane shows candidate before/after line changes

Examples:

```bash
# interactive review across all findings in a file/dir
cargo run -p aishield-cli -- fix src --interactive

# target one finding location from scan output
cargo run -p aishield-cli -- fix src/auth/login.py:34 --interactive
```

## `bench`

Run repeated scans and print timing metrics.

```bash
aishield bench <path> \
  [--rules-dir DIR] \
  [--iterations N] \
  [--warmup N] \
  [--format table|json] \
  [--bridge semgrep,bandit,eslint|all] \
  [--rules c1,c2] \
  [--exclude p1,p2] \
  [--ai-only] \
  [--cross-file] \
  [--ai-model heuristic|onnx] \
  [--onnx-model FILE] \
  [--min-ai-confidence N] \
  [--config FILE] \
  [--no-config]
```

Options:

- `--iterations N`: number of measured runs (default `5`)
- `--warmup N`: number of unmeasured warmup runs (default `1`)
- `--format`: benchmark output (`table` or `json`)

Example:

```bash
# benchmark core scan performance
cargo run -p aishield-cli -- bench . --iterations 10 --warmup 2

# include external bridge engines in benchmark
cargo run -p aishield-cli -- bench . --bridge all --format json
```

## `init`

Generate starter files for configuration and ecosystem integrations.

```bash
aishield init \
  [--output PATH] \
  [--templates config,github-actions,gitlab-ci,bitbucket-pipelines,circleci,jenkins,vscode,pre-commit|all] \
  [--force]
```

Options:

- `--output PATH`: override config file path (used when `config` template is selected)
- `--templates`: choose which templates to scaffold (default `config`)
- `--force`: overwrite existing target files

Examples:

```bash
# create only .aishield.yml
cargo run -p aishield-cli -- init

# scaffold config + GitHub Actions + pre-commit
cargo run -p aishield-cli -- init --templates config,github-actions,pre-commit

# scaffold all templates and overwrite existing files
cargo run -p aishield-cli -- init --templates all --force
```

## `create-rule`

Scaffold a new YAML rule in `rules/<language>/<category>/`.

```bash
aishield create-rule \
  --id AISHIELD-PY-AUTH-999 \
  --title "Timing Unsafe Session Compare" \
  --language python \
  --category auth \
  [--severity LEVEL] \
  [--pattern-any P] \
  [--pattern-all P] \
  [--pattern-not P] \
  [--tags t1,t2] \
  [--suggestion TEXT] \
  [--out-dir DIR] \
  [--force]
```

## `hook install`

Install local pre-commit hook:

```bash
aishield hook install [--severity LEVEL] [--path TARGET] [--all-files]
```

Defaults to staged-only scanning. Use `--all-files` for full target scans.

## `stats`

Aggregate recent local scan history:

```bash
aishield stats [--last Nd] [--history-file FILE] [--format table|json] [--config FILE] [--no-config]
```

Example:

```bash
cargo run -p aishield-cli -- stats --last 30d --format table
```
