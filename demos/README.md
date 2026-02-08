# AIShield Demos

This directory contains reproducible demos for AIShield.

## Quick Demo

From repository root:

```bash
bash demos/run.sh
```

This regenerates demo artifacts under `demos/output/`.

## Included Demo Artifacts

- `demos/output/scan-table.txt`: human-readable scan against vulnerable fixtures
- `demos/output/scan.json`: machine output with normalized dedup metadata
- `demos/output/scan.sarif`: SARIF output for GitHub Code Scanning
- `demos/output/scan-github.txt`: GitHub annotation commands (`::error`, `::warning`, `::notice`)
- `demos/output/fix-dry-run.txt`: remediation dry run against fixture file
- `demos/output/bench.txt`: benchmark output (`--iterations 3 --warmup 1`)
- `demos/output/stats.txt`: local scan history analytics (`--last 30d`)

## One-Minute Walkthrough

1. Run `bash demos/run.sh`.
2. Open `demos/output/scan-table.txt` and review top risk findings.
3. Open `demos/output/scan.json` for CI-friendly schema + dedup summary.
4. Open `demos/output/fix-dry-run.txt` to see suggested safe replacements.
5. Open `demos/output/scan-github.txt` to inspect PR annotation payloads.

## Notes

- Fixture scans intentionally produce findings.
- Counts can change as rules and scoring evolve.
