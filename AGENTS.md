# Repository Guidelines

## Project Structure & Module Organization
AIShield is a Rust workspace with supporting Node tooling.

- `crates/aishield-core/`: scanner engine, rule loading, scoring, classifier hooks.
- `crates/aishield-cli/`: user-facing CLI (`scan`, `fix`, `init`, `analytics`, etc.).
- `crates/aishield-analytics/`: analytics API service and DB access.
- `rules/<language>/<category>/`: YAML detection rules (for example `rules/javascript/auth/*.yaml`).
- `tests/fixtures/`: intentionally vulnerable samples used for regression checks.
- `dashboard/`: local analytics dashboard server and web UI.
- `docs/`: VitePress documentation source.
- `scripts/`: smoke tests and analytics stack lifecycle scripts.

## Build, Test, and Development Commands
- `cargo build --workspace`: compile all Rust crates.
- `cargo check --workspace`: fast type-check pass.
- `cargo test --workspace`: run Rust tests.
- `cargo run -p aishield-cli -- scan tests/fixtures`: validate scanner behavior against fixtures.
- `cargo fmt --all`: apply Rust formatting.
- `npm ci`: install Node dependencies for docs/dashboard workflows.
- `npm run docs:dev` / `npm run docs:build`: run or build docs site.
- `npm run dashboard:dev`: start dashboard server (`http://127.0.0.1:4318` by default).
- `npm run dashboard:test`: run dashboard Node tests (`node --test`).
- `./scripts/start-analytics-stack.sh` and `./scripts/stop-analytics-stack.sh`: start/stop local Postgres + analytics API + smoke flow.

## Coding Style & Naming Conventions
- Rust: follow `rustfmt` defaults (4-space indentation, idiomatic `snake_case`/`CamelCase`).
- JavaScript (dashboard): ES modules, single quotes, semicolons, small pure helpers in `dashboard/lib/`.
- Rules: keep filenames descriptive and lowercase kebab-case; keep IDs stable and unique in `AISHIELD-LANG-CATEGORY-NNN` format.

## Testing Guidelines
- Run `cargo fmt --all`, `cargo check --workspace`, and `cargo test --workspace` before opening a PR.
- For rule changes, add/update fixtures in `tests/fixtures/` and confirm detections with CLI scan output.
- For dashboard/API changes, run `npm run dashboard:test` and `./scripts/smoke-analytics-api.sh`.
- CI smoke gates analytics thresholds (including minimum coverage percentage when available).

## Commit & Pull Request Guidelines
- Prefer Conventional Commit style seen in history: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`, `release:`.
- Keep commits scoped; avoid unrelated refactors.
- PRs should include: clear description, motivation, test commands run, docs/changelog updates, and screenshots for UI changes.
- Follow `.github/PULL_REQUEST_TEMPLATE.md` and call out breaking changes explicitly.

## Security & Configuration Tips
- Do not commit real secrets, API keys, or private vulnerability details; use `SECURITY.md` for responsible disclosure.
- Keep local overrides in environment variables (`AISHIELD_API_KEY`, `DATABASE_URL`, `AISHIELD_ANALYTICS_URL`) rather than hardcoding them.
