# Testing Guide

This page links the most useful validation paths for AIShield contributors.

## Core Validation

```bash
cargo fmt
cargo check --workspace
cargo test --workspace
```

## Scanner Validation

```bash
cargo run -p aishield-cli -- scan tests/fixtures
cargo run -p aishield-cli -- scan . --staged --severity high --fail-on-findings
```

## Dashboard and Analytics Validation

- [Dashboard Guide](../dashboard.md)
- [Database Setup](../DATABASE_SETUP.md)
- Week 5 checklist: `WEEK5_TESTING.md` (repository root)
