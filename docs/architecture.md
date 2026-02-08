# Architecture

AIShield is organized as a Rust workspace with a separation between scanning logic and presentation/UX.

## Components

## `aishield-core`

Core scanner and data model:

- rule loading and validation (`rules/` YAML)
- file discovery and language inference
- finding extraction + severity/risk scoring
- AI-likelihood heuristics/classifier hooks
- output shaping and dedup normalization
- optional SAST bridge normalization

## `aishield-cli`

Operator-facing interface:

- commands: `scan`, `fix`, `bench`, `stats`, `init`, `create-rule`, `hook install`
- output modes: `table`, `json`, `sarif`, `github`
- CI controls: `--changed-from`, `--staged`, `--fail-on-findings`
- remediation UX: targeted and interactive autofix flows

## Rules and Fixtures

- `rules/`: language + category rulepacks
- `tests/fixtures/`: intentionally vulnerable snippets used in regression tests

## CI and Release Surfaces

- `.github/workflows/aishield.yml`: scanning + annotations + SARIF upload
- `.github/workflows/release.yml`: tag-driven release workflow
- `CHANGELOG.md`: curated release narrative
- `SECURITY.md`: vulnerability reporting and support expectations

## Documentation Stack

The docs site uses VitePress with local search and structured navigation:

- source docs in `docs/`
- site config in `docs/.vitepress/config.ts`
- theme overrides in `docs/.vitepress/theme/`
