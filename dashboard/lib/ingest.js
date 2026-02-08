import fs from 'node:fs';
import path from 'node:path';

import { escapeHistoryField } from './history.js';

function toNumber(value, fallback = 0) {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return fallback;
  }
  return num;
}

function mode(values) {
  const counts = new Map();
  for (const value of values) {
    if (!value) {
      continue;
    }
    counts.set(value, (counts.get(value) || 0) + 1);
  }

  const rows = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
  return rows.length ? rows[0][0] : '-';
}

export function summarizeAishieldJson(payload) {
  const summary = payload && typeof payload === 'object' ? payload.summary || {} : {};
  const findings = Array.isArray(payload?.findings) ? payload.findings : [];
  const sev = summary.by_severity || {};

  return {
    total: toNumber(summary.total, findings.length),
    critical: toNumber(sev.critical, 0),
    high: toNumber(sev.high, 0),
    medium: toNumber(sev.medium, 0),
    low: toNumber(sev.low, 0),
    info: toNumber(sev.info, 0),
    ai_estimated: toNumber(summary.ai_estimated, findings.filter((f) => toNumber(f.ai_confidence, 0) >= 70).length),
    top_rule: String(summary.top_pattern || mode(findings.map((f) => f.id)) || '-'),
  };
}

function sarifLevelToSeverity(level) {
  const normalized = String(level || '').toLowerCase();
  if (normalized === 'error') {
    return 'high';
  }
  if (normalized === 'warning') {
    return 'medium';
  }
  if (normalized === 'note') {
    return 'low';
  }
  return 'info';
}

export function summarizeAishieldSarif(payload) {
  const runs = Array.isArray(payload?.runs) ? payload.runs : [];
  const results = runs.flatMap((run) => (Array.isArray(run?.results) ? run.results : []));

  const severity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const result of results) {
    const bucket = sarifLevelToSeverity(result?.level);
    severity[bucket] += 1;
  }

  return {
    total: results.length,
    critical: severity.critical,
    high: severity.high,
    medium: severity.medium,
    low: severity.low,
    info: severity.info,
    ai_estimated: results.filter((result) => toNumber(result?.properties?.aiConfidence, 0) >= 70).length,
    top_rule: String(mode(results.map((result) => result.ruleId)) || '-'),
  };
}

export function summarizeReportPayload(payload, format = 'auto') {
  const normalizedFormat = String(format || 'auto').toLowerCase();
  if (normalizedFormat === 'json') {
    return summarizeAishieldJson(payload);
  }
  if (normalizedFormat === 'sarif') {
    return summarizeAishieldSarif(payload);
  }

  if (payload && typeof payload === 'object' && payload.summary && Array.isArray(payload.findings)) {
    return summarizeAishieldJson(payload);
  }
  if (payload && typeof payload === 'object' && Array.isArray(payload.runs)) {
    return summarizeAishieldSarif(payload);
  }

  throw new Error('Unsupported report payload; expected AIShield JSON or SARIF object');
}

export function parseJsonFile(inputPath) {
  const resolved = path.resolve(inputPath);
  const raw = fs.readFileSync(resolved, 'utf8');
  return JSON.parse(raw);
}

export function createHistoryRecord({ target, timestamp, summary }) {
  return {
    timestamp: toNumber(timestamp, Math.floor(Date.now() / 1000)),
    target: String(target || '.'),
    total: toNumber(summary.total, 0),
    critical: toNumber(summary.critical, 0),
    high: toNumber(summary.high, 0),
    medium: toNumber(summary.medium, 0),
    low: toNumber(summary.low, 0),
    info: toNumber(summary.info, 0),
    ai_estimated: toNumber(summary.ai_estimated, 0),
    top_rule: String(summary.top_rule || '-'),
  };
}

export function formatHistoryRecord(record) {
  return [
    record.timestamp,
    escapeHistoryField(record.target),
    record.total,
    record.critical,
    record.high,
    record.medium,
    record.low,
    record.info,
    record.ai_estimated,
    escapeHistoryField(record.top_rule),
  ].join('|');
}

export function appendHistoryRecord(historyFile, record) {
  const resolved = path.resolve(historyFile);
  const parent = path.dirname(resolved);
  fs.mkdirSync(parent, { recursive: true });
  const line = `${formatHistoryRecord(record)}\n`;
  fs.appendFileSync(resolved, line, 'utf8');
}
