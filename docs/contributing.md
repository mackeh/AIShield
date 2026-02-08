# Contributing

If you want to contribute quickly, follow this path:

1. Read `CONTRIBUTING.md`
2. Pick an issue labeled `bug` or `enhancement`
3. Open a small focused PR with tests/docs

## First Contribution Checklist

- clone the repo and run `cargo test`
- run scanner once: `cargo run -p aishield-cli -- scan .`
- build docs once: `npm run docs:build`
- verify changed behavior with fixture/tests

## Contribution Areas

- rule quality and category coverage
- false-positive/false-negative reduction
- CLI and TUI usability
- CI and SARIF/GitHub annotation quality
- docs, templates, and integration examples

## Contributor Templates

GitHub templates provided in this repository:

- `.github/ISSUE_TEMPLATE/bug_report.md`
- `.github/ISSUE_TEMPLATE/feature_request.md`
- `.github/PULL_REQUEST_TEMPLATE.md`

Use these templates to make triage and review faster.

## Security Reporting

For vulnerabilities in AIShield itself, do not open a public issue. Follow `SECURITY.md`.
