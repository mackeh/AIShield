import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  escapeHistoryField,
  filterByDays,
  parseHistoryContent,
  parseHistoryLine,
  percentChange,
  summarize,
  timeSeries,
  topRules,
  topTargets,
  unescapeHistoryField,
} from './history.js';

test('parseHistoryLine parses valid line and escapes/unescapes pipes', () => {
  const line = '1700000000|repo%7Capi%252Fv1|10|1|3|4|1|1|2|AISHIELD-PY-CRYPTO-001';
  const parsed = parseHistoryLine(line);
  assert.ok(parsed);
  assert.equal(parsed.target, 'repo|api%2Fv1');
  assert.equal(parsed.total, 10);
  assert.equal(parsed.critical, 1);
});

test('escape and unescape are reversible', () => {
  const input = 'foo|bar%baz';
  const escaped = escapeHistoryField(input);
  assert.equal(escaped, 'foo%7Cbar%25baz');
  assert.equal(unescapeHistoryField(escaped), input);
});

test('parseHistoryContent + summarize + rankings', () => {
  const content = [
    '1700000000|repo-a|8|1|2|3|1|1|2|AISHIELD-PY-CRYPTO-001',
    '1700003600|repo-b|5|0|3|1|1|0|1|AISHIELD-JS-INJ-001',
    '1700086400|repo-a|4|0|2|1|1|0|1|AISHIELD-PY-CRYPTO-001',
  ].join('\n');

  const rows = parseHistoryContent(content);
  assert.equal(rows.length, 3);

  const summary = summarize(rows);
  assert.equal(summary.scans, 3);
  assert.equal(summary.findings, 17);
  assert.equal(summary.high_or_above, 8);
  assert.equal(summary.ai_estimated, 4);
  assert.equal(summary.avg_findings_per_scan, 5.67);

  const series = timeSeries(rows);
  assert.equal(series.length, 2);
  assert.equal(series[0].findings, 13);

  const rules = topRules(rows, 2);
  assert.equal(rules[0].rule, 'AISHIELD-PY-CRYPTO-001');
  assert.equal(rules[0].count, 2);

  const targets = topTargets(rows, 2);
  assert.equal(targets[0].target, 'repo-a');
  assert.equal(targets[0].findings, 12);
  assert.equal(targets[0].scans, 2);
});

test('filterByDays keeps only records newer than cutoff', () => {
  const now = 1700172800;
  const rows = [
    { timestamp: now - 10, total: 1 },
    { timestamp: now - 86400 * 2, total: 1 },
  ];
  const recent = filterByDays(rows, 1, now);
  assert.equal(recent.length, 1);
});

test('percentChange returns null when previous is zero and current is non-zero', () => {
  assert.equal(percentChange(10, 0), null);
  assert.equal(percentChange(0, 0), 0);
  assert.equal(percentChange(12, 10), 20);
});

test('load history from file content parsing helper', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aishield-history-test-'));
  const historyFile = path.join(dir, '.aishield-history.log');
  fs.writeFileSync(historyFile, '1700000000|repo|3|0|1|1|1|0|1|AISHIELD-JS-INJ-001\n', 'utf8');

  const parsed = parseHistoryContent(fs.readFileSync(historyFile, 'utf8'));
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].target, 'repo');
});
