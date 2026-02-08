# Contributing to AIShield

Thanks for contributing to AIShield.

This project focuses on detecting security issues frequently introduced by AI-generated code. Contributions that improve signal quality, reduce false positives, and improve developer workflow are especially valuable.

## What To Contribute

- detection rules under `rules/<language>/<category>/`
- scanner and output behavior in `crates/aishield-core/` and `crates/aishield-cli/`
- fixture-based tests in `tests/fixtures/`
- docs and integration examples in `docs/`
- CI and release hardening in `.github/workflows/`

## Local Setup

Prerequisites:

- Rust stable toolchain
- Node.js 20+ (for docs site)
- Git

Setup:

```bash
git clone https://github.com/mackeh/AIShield.git
cd AIShield
cargo build
npm install
```

## Development Workflow

1. Create a branch from `main`.
2. Make focused changes with tests/docs.
3. Run local validation:

```bash
cargo fmt --all
cargo test
cargo run -p aishield-cli -- scan .
npm run docs:build
```

4. Open a PR with a clear summary and risk notes.

## Rule Contribution Checklist

When adding or updating rules:

- include `id`, `title`, `severity`, `languages`, and `pattern`
- keep rule IDs stable and unique
- add/update vulnerable fixtures to prove detection behavior
- add/update tests for regressions
- include remediation guidance (`fix.suggestion`) where possible

See `docs/rules-authoring.md` for full rule format guidance.

## Integration Testing

Use these commands before submitting CI/integration changes:

```bash
# SARIF artifact path used by CI
cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif

# GitHub annotation output
cargo run -p aishield-cli -- scan . --format github --dedup normalized
```

## Docs and Ecosystem Integrations

- Docs site: `npm run docs:dev`
- GitHub Actions docs: `docs/ci-github-actions.md`
- GitLab CI template: `.gitlab-ci.yml.example`
- VS Code recommendations/tasks: `.vscode/`

## Pull Request Expectations

- keep PRs scoped and reviewable
- include tests for behavior changes
- document flags/config changes in docs
- call out breaking changes explicitly
- do not include unrelated refactors in the same PR

## Reporting Security Issues

Do not open public issues for undisclosed vulnerabilities.

Follow `SECURITY.md` for private vulnerability reporting.
