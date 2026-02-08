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
cross_file: false
ai_model: heuristic
onnx_model_path: ""
min_ai_confidence: 0.70
severity_threshold: medium
fail_on_findings: false
history_file: .aishield-history.log
record_history: true
notify_webhook_url: ""
notify_min_severity: high
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
- `cross_file`: if `true`, enables experimental cross-file auth-route heuristics
- `ai_model`: AI-likelihood scorer mode (`heuristic|onnx`)
- `onnx_model_path`: local ONNX model path used when `ai_model: onnx`
- `min_ai_confidence`: threshold for AI likelihood (`0.0..1.0`)
- `severity_threshold`: minimum severity shown
- `fail_on_findings`: if `true`, scan exits with code `2` when findings exist
- `history_file`: path for stats/history log
- `record_history`: if `false`, disables history append
- `notify_webhook_url`: optional webhook endpoint for scan alerts
- `notify_min_severity`: minimum severity that triggers webhook notifications (`critical|high|medium|low|info`)

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

## ONNX Notes

- Build with ONNX feature for full runtime path:
  - `cargo run -p aishield-cli --features onnx -- scan . --ai-model onnx --onnx-model models/ai-classifier/model.onnx`
- If ONNX runtime prerequisites are unavailable, AIShield falls back to heuristic scoring.
