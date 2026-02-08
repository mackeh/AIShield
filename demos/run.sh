#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/demos/output"

mkdir -p "$OUT_DIR"

cd "$ROOT_DIR"

echo "[demo] generating table scan output"
cargo run -q -p aishield-cli -- scan tests/fixtures > "$OUT_DIR/scan-table.txt"

echo "[demo] generating JSON scan output"
cargo run -q -p aishield-cli -- scan tests/fixtures --format json --dedup normalized --output "$OUT_DIR/scan.json"

echo "[demo] generating SARIF scan output"
cargo run -q -p aishield-cli -- scan tests/fixtures --format sarif --dedup normalized --output "$OUT_DIR/scan.sarif"

echo "[demo] generating GitHub annotation output"
cargo run -q -p aishield-cli -- scan tests/fixtures --format github --dedup normalized > "$OUT_DIR/scan-github.txt"

echo "[demo] generating fix dry-run output"
cargo run -q -p aishield-cli -- fix tests/fixtures/vulnerable.py --dry-run > "$OUT_DIR/fix-dry-run.txt"

echo "[demo] generating benchmark output"
cargo run -q -p aishield-cli -- bench tests/fixtures --iterations 3 --warmup 1 --format table > "$OUT_DIR/bench.txt"

echo "[demo] generating stats output"
cargo run -q -p aishield-cli -- stats --last 30d --format table > "$OUT_DIR/stats.txt"

echo "[demo] done. outputs written to $OUT_DIR"
