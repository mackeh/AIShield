# Getting Started

AIShield is a Rust-first security scanner for AI-assisted codebases. It combines curated rulepacks, AI-likelihood heuristics, risk scoring, and CI-friendly output formats.

## Prerequisites

- Rust toolchain (`stable` recommended)
- Git
- Optional bridge tools for richer findings:
  - Python + `bandit`
  - Semgrep
  - Node.js + `eslint`

## Quick Scan

```bash
cargo run -p aishield-cli -- scan .
```

## CI-Friendly Scan

```bash
cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif
```

## PR Annotation Mode

```bash
cargo run -p aishield-cli -- scan . --format github --changed-from origin/main
```

## Interactive Fix Mode

```bash
cargo run -p aishield-cli -- fix . --interactive
```

Inside the TUI:

- `/` enters search/filter mode
- `space` toggles selected fix
- `enter` applies selected fix(es)
- right pane previews line-level before/after diffs

## Local Docs Development

```bash
npm install
npm run docs:dev
```

Build docs for production:

```bash
npm run docs:build
```
