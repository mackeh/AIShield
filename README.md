# AIShield

Initial foundation for AIShield: a Rust workspace with a rule-driven security scanner focused on AI-prone vulnerability patterns.

## Current capabilities

- `aishield scan <path>`: scans Python and JavaScript/TypeScript files using YAML rules.
- Composite risk score per finding using severity, AI likelihood, context risk, and exploitability.
- `--format table|json|sarif` output formats.
- `--output <file>` for writing reports directly to disk.
- Config loading from `.aishield.yml` (override with `--config`, disable with `--no-config`).
- `aishield init`: writes a starter `.aishield.yml` config.
- `aishield fix <path>`: lists remediation suggestions from matched findings.
- `aishield hook install`: installs a local git pre-commit hook that blocks on findings.

## Quick start

```bash
cargo run -p aishield-cli -- scan .
cargo run -p aishield-cli -- scan . --format json
cargo run -p aishield-cli -- scan . --format sarif --output aishield.sarif
cargo run -p aishield-cli -- init
cargo run -p aishield-cli -- hook install --severity high
```
