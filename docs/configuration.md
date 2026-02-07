# AIShield Configuration

AIShield reads configuration from `.aishield.yml` by default.

Use `--config FILE` to load a different file, or `--no-config` to disable config loading.

## Example

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

## Keys

- `version`: config schema version (currently `1`)
- `rules_dir`: root directory for YAML rules
- `format`: default output format (`table|json|sarif|github`)
- `dedup_mode`: output dedup mode (`none|normalized`)
- `bridge_engines`: optional external engine list (`[semgrep]`, `[bandit]`, `[eslint]`, `[semgrep, bandit, eslint]`)
- `rules`: category filters list, same behavior as `--rules`
- `exclude_paths`: list of path fragments to skip
- `ai_only`: if `true`, include only AI-likelihood-filtered rules
- `min_ai_confidence`: threshold for AI likelihood (`0.0..1.0`)
- `severity_threshold`: minimum severity shown
- `fail_on_findings`: if `true`, scan exits with code `2` when findings exist
- `history_file`: path for stats/history log
- `record_history`: if `false`, disables history append

## Precedence

Runtime precedence is:

1. CLI flags
2. Config file values
3. Built-in defaults

Examples:

- If config sets `format: sarif` and command includes `--format json`, JSON is used.
- If config sets `dedup_mode: none` and command includes `--dedup normalized`, normalized mode is used.

## Dedup Defaults

If `dedup_mode` is not set:

- `table` output defaults to `none`
- `json`, `sarif`, and `github` output default to `normalized`

This reduces noisy duplicate findings in CI while keeping table output closer to raw scan data.
