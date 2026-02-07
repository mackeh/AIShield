# AIShield

Initial foundation for AIShield: a Rust workspace with a rule-driven security scanner focused on AI-prone vulnerability patterns.

## Current capabilities

- `aishield scan <path>`: scans Python and JavaScript/TypeScript files using YAML rules.
- Composite risk score per finding using severity, AI likelihood, context risk, and exploitability.
- `--format table|json|sarif` output formats.
- `aishield init`: writes a starter `.aishield.yml` config.
- `aishield fix <path>`: lists remediation suggestions from matched findings.

## Quick start

```bash
cargo run -p aishield-cli -- scan .
cargo run -p aishield-cli -- scan . --format json
cargo run -p aishield-cli -- scan . --format sarif > aishield.sarif
cargo run -p aishield-cli -- init
```
