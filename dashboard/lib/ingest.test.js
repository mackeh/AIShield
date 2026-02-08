import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  appendHistoryRecord,
  createHistoryRecord,
  formatHistoryRecord,
  summarizeAishieldJson,
  summarizeAishieldSarif,
  summarizeReportPayload,
} from './ingest.js';
import { parseHistoryLine } from './history.js';

test('summarizeAishieldJson reads summary fields', () => {
  const payload = {
    summary: {
      total: 7,
      ai_estimated: 2,
      top_pattern: 'AISHIELD-PY-CRYPTO-001',
      by_severity: {
        critical: 1,
        high: 2,
        medium: 3,
        low: 1,
        info: 0,
      },
    },
    findings: [],
  };

  const summary = summarizeAishieldJson(payload);
  assert.equal(summary.total, 7);
  assert.equal(summary.critical, 1);
  assert.equal(summary.high, 2);
  assert.equal(summary.ai_estimated, 2);
  assert.equal(summary.top_rule, 'AISHIELD-PY-CRYPTO-001');
});

test('summarizeAishieldSarif maps SARIF levels', () => {
  const payload = {
    runs: [{
      results: [
        { ruleId: 'A', level: 'error', properties: { aiConfidence: 90 } },
        { ruleId: 'A', level: 'warning', properties: { aiConfidence: 30 } },
        { ruleId: 'B', level: 'note', properties: { aiConfidence: 80 } },
      ],
    }],
  };

  const summary = summarizeAishieldSarif(payload);
  assert.equal(summary.total, 3);
  assert.equal(summary.high, 1);
  assert.equal(summary.medium, 1);
  assert.equal(summary.low, 1);
  assert.equal(summary.ai_estimated, 2);
  assert.equal(summary.top_rule, 'A');
});

test('summarizeReportPayload auto-detects report shape', () => {
  const jsonSummary = summarizeReportPayload({ summary: { total: 2, by_severity: {} }, findings: [] }, 'auto');
  assert.equal(jsonSummary.total, 2);

  const sarifSummary = summarizeReportPayload({ runs: [{ results: [] }] }, 'auto');
  assert.equal(sarifSummary.total, 0);
});

test('create/format/append history record produces parseable line', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aishield-ingest-test-'));
  const file = path.join(dir, '.aishield-history.log');

  const record = createHistoryRecord({
    target: 'repo|svc',
    timestamp: 1700000000,
    summary: {
      total: 9,
      critical: 1,
      high: 2,
      medium: 3,
      low: 2,
      info: 1,
      ai_estimated: 4,
      top_rule: 'AISHIELD-JS-INJ-001',
    },
  });

  const line = formatHistoryRecord(record);
  assert.ok(line.includes('repo%7Csvc'));

  appendHistoryRecord(file, record);

  const parsed = parseHistoryLine(fs.readFileSync(file, 'utf8').trim());
  assert.ok(parsed);
  assert.equal(parsed.target, 'repo|svc');
  assert.equal(parsed.total, 9);
  assert.equal(parsed.high, 2);
});
