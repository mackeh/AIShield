# AIShield Documentation

This directory now serves as the source for the VitePress documentation site.

## Run the docs site locally

```bash
npm install
npm run docs:dev
```

## Build for production

```bash
npm run docs:build
```

## Doc map

- `index.md`: docs landing page
- `getting-started.md`: quick start and local docs development
- `architecture.md`: project and runtime architecture
- `dashboard.md`: local dashboard and analytics pipeline bootstrap
- `roadmap.md`: roadmap snapshot and current progress
- `integrations.md`: VS Code, GitHub Actions, GitLab CI, and hook integrations
- `contributing.md`: contributor onboarding and templates
- `cli.md`: CLI reference
- `ai-classifier.md`: heuristic + ONNX classifier modes
- `configuration.md`: `.aishield.yml` keys and precedence
- `output-formats.md`: table/json/sarif/github outputs + dedup behavior
- `vscode-extension.md`: VS Code extension bootstrap and usage
- `ci-github-actions.md`: CI integration and troubleshooting
- `analytics-staging.md`: staging deploy + rollback runbook for analytics stack
- `releasing.md`: release/tag workflow
- `rules-authoring.md`: custom rule authoring guide
