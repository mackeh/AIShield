# AIShield Dashboard

Local web dashboard + analytics pipeline bootstrap for AIShield scan history.

## What it provides

- timeline analytics from `.aishield-history.log`
- KPI and trend views for findings, severity, and AI-estimated ratio
- top rules and top targets to highlight recurring hotspots
- ingestion utility for AIShield JSON/SARIF reports from CI artifacts

## Run locally

```bash
npm run dashboard:dev
```

Default URL: `http://127.0.0.1:4318`

Optional environment variables:

- `AISHIELD_HISTORY_FILE=/path/to/.aishield-history.log`
- `AISHIELD_DASHBOARD_PORT=5000`

## Generate sample data

```bash
npm run dashboard:sample-history
npm run dashboard:dev
```

## Ingest scan reports into history

```bash
# produce JSON report
cargo run -p aishield-cli -- scan . --format json --output aishield.json

# append summary to history
npm run dashboard:ingest -- --input aishield.json --target repo
```

Supported formats:

- AIShield JSON (`--format json`)
- SARIF (`--format sarif`)
- auto-detect (`--format auto`, default)

## API

- `GET /api/health`
- `GET /api/analytics?days=30&limit=10`
