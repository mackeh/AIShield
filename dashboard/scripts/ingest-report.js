#!/usr/bin/env node

import path from 'node:path';

import {
  appendHistoryRecord,
  createHistoryRecord,
  parseJsonFile,
  summarizeReportPayload,
} from '../lib/ingest.js';

function printHelp() {
  console.log(`AIShield dashboard report ingester

Usage:
  node dashboard/scripts/ingest-report.js --input <report.json|report.sarif> [options]

Options:
  --input <file>          Input AIShield JSON/SARIF report (required)
  --format <auto|json|sarif>
                          Parse mode (default: auto)
  --target <name>         Target identifier written to history (default: basename(input))
  --history-file <file>   History log path (default: .aishield-history.log)
  --timestamp <epoch>     Override event timestamp in seconds
  --dry-run               Print normalized record and do not write history
  --help                  Show this message
`);
}

function parseArgs(argv) {
  const options = {
    format: 'auto',
    historyFile: '.aishield-history.log',
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--input':
        options.input = argv[i + 1];
        i += 1;
        break;
      case '--format':
        options.format = String(argv[i + 1] || 'auto').toLowerCase();
        i += 1;
        break;
      case '--target':
        options.target = argv[i + 1];
        i += 1;
        break;
      case '--history-file':
        options.historyFile = argv[i + 1];
        i += 1;
        break;
      case '--timestamp':
        options.timestamp = Number(argv[i + 1]);
        i += 1;
        break;
      case '--dry-run':
        options.dryRun = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        throw new Error(`Unknown option: ${arg}`);
    }
  }

  return options;
}

function defaultTargetFromInput(inputPath) {
  const base = path.basename(inputPath);
  return base.replace(/\.(json|sarif)$/i, '') || base;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    printHelp();
    return;
  }
  if (!options.input) {
    throw new Error('--input is required');
  }

  const payload = parseJsonFile(options.input);
  const summary = summarizeReportPayload(payload, options.format);
  const record = createHistoryRecord({
    target: options.target || defaultTargetFromInput(options.input),
    timestamp: options.timestamp,
    summary,
  });

  if (options.dryRun) {
    console.log(JSON.stringify(record, null, 2));
    return;
  }

  appendHistoryRecord(options.historyFile, record);

  console.log('[aishield-dashboard] ingested report into history');
  console.log(`  input:   ${path.resolve(options.input)}`);
  console.log(`  format:  ${options.format}`);
  console.log(`  target:  ${record.target}`);
  console.log(`  total:   ${record.total}`);
  console.log(`  history: ${path.resolve(options.historyFile)}`);
}

try {
  main();
} catch (error) {
  console.error(`[aishield-dashboard] ${String(error && error.message ? error.message : error)}`);
  process.exitCode = 1;
}
