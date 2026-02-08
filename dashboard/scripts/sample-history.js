#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

import { appendHistoryRecord, createHistoryRecord } from '../lib/ingest.js';

function parseArgs(argv) {
  const options = {
    historyFile: '.aishield-history.log',
    days: 30,
    scansPerDay: 2,
    target: '.',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--history-file':
        options.historyFile = argv[i + 1];
        i += 1;
        break;
      case '--days':
        options.days = Number(argv[i + 1]);
        i += 1;
        break;
      case '--scans-per-day':
        options.scansPerDay = Number(argv[i + 1]);
        i += 1;
        break;
      case '--target':
        options.target = argv[i + 1];
        i += 1;
        break;
      case '--help':
      case '-h':
        console.log(`Usage: node dashboard/scripts/sample-history.js [options]

Options:
  --history-file <file>   Path to write sample history (default .aishield-history.log)
  --days <n>              Number of days to generate (default 30)
  --scans-per-day <n>     Scans per day (default 2)
  --target <name>         Target field in history rows (default .)
`);
        process.exit(0);
      default:
        throw new Error(`Unknown option: ${arg}`);
    }
  }

  return options;
}

function clampInt(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateRecord(timestamp, target, dayIndex) {
  const trendFactor = Math.max(0.65, 1.25 - dayIndex * 0.012);
  const critical = rand(0, 2);
  const high = Math.max(1, Math.round(rand(3, 10) * trendFactor));
  const medium = Math.max(1, Math.round(rand(2, 8) * trendFactor));
  const low = rand(0, 4);
  const info = rand(0, 2);
  const total = critical + high + medium + low + info;

  const aiEstimated = Math.min(total, Math.max(0, Math.round(total * (0.15 + Math.random() * 0.25))));
  const rulePool = [
    'AISHIELD-PY-CRYPTO-001',
    'AISHIELD-JS-INJ-001',
    'AISHIELD-GO-AUTH-001',
    'AISHIELD-RS-MISC-005',
    'AISHIELD-JAVA-INJ-003',
  ];

  return createHistoryRecord({
    target,
    timestamp,
    summary: {
      total,
      critical,
      high,
      medium,
      low,
      info,
      ai_estimated: aiEstimated,
      top_rule: rulePool[rand(0, rulePool.length - 1)],
    },
  });
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const days = clampInt(options.days, 30, 1, 3650);
  const scansPerDay = clampInt(options.scansPerDay, 2, 1, 50);

  const historyPath = path.resolve(options.historyFile);
  fs.mkdirSync(path.dirname(historyPath), { recursive: true });

  if (fs.existsSync(historyPath)) {
    fs.unlinkSync(historyPath);
  }

  const now = Math.floor(Date.now() / 1000);

  let generated = 0;
  for (let dayOffset = days - 1; dayOffset >= 0; dayOffset -= 1) {
    const dayStart = now - dayOffset * 86400 - 86399;
    for (let i = 0; i < scansPerDay; i += 1) {
      const timestamp = dayStart + (i + 1) * Math.floor(86400 / (scansPerDay + 1));
      const record = generateRecord(timestamp, options.target, dayOffset);
      appendHistoryRecord(historyPath, record);
      generated += 1;
    }
  }

  console.log(`[aishield-dashboard] generated ${generated} sample records at ${historyPath}`);
}

try {
  main();
} catch (error) {
  console.error(`[aishield-dashboard] ${String(error && error.message ? error.message : error)}`);
  process.exitCode = 1;
}
