# Dashboard and Analytics

AIShield includes a local web dashboard bootstrap for team-level trend visibility.

The dashboard reads scan history and gives fast answers to:

- are findings trending up or down?
- which rules are recurring most often?
- which repos/targets carry the most risk?
- is AI-estimated vulnerable code ratio improving?

## Start the dashboard

```bash
npm install
npm run dashboard:dev
```

Open: `http://127.0.0.1:4318`

Optional overrides:

```bash
AISHIELD_DASHBOARD_PORT=5000 npm run dashboard:dev
AISHIELD_HISTORY_FILE=/tmp/aishield-history.log npm run dashboard:dev
```

## Feed analytics history

AIShield CLI already appends scan summaries to history by default when you run `scan`.

For artifact-based CI flows, ingest JSON or SARIF reports explicitly:

```bash
# generate report
cargo run -p aishield-cli -- scan . --format json --output aishield.json

# append report summary to history
npm run dashboard:ingest -- --input aishield.json --target github-actions/main
```

Also supported:

```bash
npm run dashboard:ingest -- --input aishield.sarif --format sarif --target nightly-scan
```

## CI integration example (GitHub Actions)

```yaml
- name: Run AIShield scan
  run: cargo run -p aishield-cli -- scan . --format json --output aishield.json

- name: Ingest analytics record
  run: npm run dashboard:ingest -- --input aishield.json --target github-actions/${{ github.ref_name }}
```

## Sample data for demos

```bash
npm run dashboard:sample-history
npm run dashboard:dev
```

This replaces `.aishield-history.log` with generated demo records.
