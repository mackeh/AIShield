# AIShield Output Formats

AIShield supports three scan output formats:

- `table`: human-friendly terminal view
- `json`: machine-friendly artifact for CI pipelines
- `sarif`: GitHub Code Scanning compatible format

## Table

Default format.

```bash
cargo run -p aishield-cli -- scan .
```

Includes:

- severity
- rule id
- location
- AI confidence
- risk score
- snippet
- summary counts

## JSON

```bash
cargo run -p aishield-cli -- scan . --format json --output aishield.json
```

Top-level shape:

```json
{
  "summary": {
    "total": 0,
    "scanned_files": 0,
    "matched_rules": 0,
    "dedup_mode": "normalized",
    "original_total": 0,
    "deduped_total": 0,
    "ai_estimated": 0,
    "top_pattern": "AISHIELD-...",
    "by_severity": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "info": 0
    }
  },
  "findings": []
}
```

Each finding includes id/title/severity/location/snippet/AI-confidence/risk/category/tags and optional remediation metadata.

## SARIF

```bash
cargo run -p aishield-cli -- scan . --format sarif --output aishield.sarif
```

AIShield writes SARIF `2.1.0` with:

- tool rules mapped from AIShield rule IDs
- per-result `ruleId`, level, location, and message
- result properties (`aiConfidence`, `riskScore`, `category`, `tags`)
- run-level dedup metadata in `runs[0].properties`

## Dedup Behavior

Use scan flag:

```bash
--dedup none|normalized
```

Behavior:

- `none`: no output dedup pass
- `normalized`: collapse equivalent findings using normalized keying (file + line + category + normalized snippet), keep highest-risk representative

Defaults:

- `table`: `none`
- `json`/`sarif`: `normalized`

`summary.original_total` and `summary.deduped_total` (JSON) and run properties (SARIF) expose what changed.
