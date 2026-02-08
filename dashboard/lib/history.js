import fs from 'node:fs';
import path from 'node:path';

export function escapeHistoryField(input) {
  return String(input || '').replaceAll('%', '%25').replaceAll('|', '%7C');
}

export function unescapeHistoryField(value) {
  return String(value || '')
    .replace(/%7C/gi, '|')
    .replace(/%25/gi, '%');
}

export function parseHistoryLine(line) {
  const parts = String(line || '').trim().split('|');
  if (parts.length !== 10) {
    return null;
  }

  const record = {
    timestamp: Number(parts[0]),
    target: unescapeHistoryField(parts[1]),
    total: Number(parts[2]),
    critical: Number(parts[3]),
    high: Number(parts[4]),
    medium: Number(parts[5]),
    low: Number(parts[6]),
    info: Number(parts[7]),
    ai_estimated: Number(parts[8]),
    top_rule: unescapeHistoryField(parts[9]),
  };

  if (!Number.isFinite(record.timestamp)) {
    return null;
  }

  for (const key of ['total', 'critical', 'high', 'medium', 'low', 'info', 'ai_estimated']) {
    if (!Number.isFinite(record[key])) {
      return null;
    }
  }

  return record;
}

export function parseHistoryContent(content) {
  return String(content || '')
    .split(/\r?\n/)
    .map(parseHistoryLine)
    .filter(Boolean)
    .sort((a, b) => a.timestamp - b.timestamp);
}

export function loadHistory(historyPath) {
  const resolved = path.resolve(historyPath);
  if (!fs.existsSync(resolved)) {
    return [];
  }

  const content = fs.readFileSync(resolved, 'utf8');
  return parseHistoryContent(content);
}

export function filterByDays(records, days, nowEpoch = Math.floor(Date.now() / 1000)) {
  if (!days || !Number.isFinite(days) || days <= 0) {
    return [...records];
  }

  const cutoff = nowEpoch - Math.floor(days * 86400);
  return records.filter((record) => record.timestamp >= cutoff);
}

export function filterByRange(records, minTimestampInclusive, maxTimestampExclusive) {
  return records.filter((record) => (
    record.timestamp >= minTimestampInclusive && record.timestamp < maxTimestampExclusive
  ));
}

export function summarize(records) {
  const summary = {
    scans: records.length,
    findings: 0,
    severity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
    high_or_above: 0,
    ai_estimated: 0,
    ai_ratio: 0,
    avg_findings_per_scan: 0,
  };

  for (const record of records) {
    summary.findings += record.total;
    summary.severity.critical += record.critical;
    summary.severity.high += record.high;
    summary.severity.medium += record.medium;
    summary.severity.low += record.low;
    summary.severity.info += record.info;
    summary.ai_estimated += record.ai_estimated;
  }

  summary.high_or_above = summary.severity.critical + summary.severity.high;
  summary.ai_ratio = summary.findings > 0
    ? Number((summary.ai_estimated / summary.findings).toFixed(4))
    : 0;
  summary.avg_findings_per_scan = summary.scans > 0
    ? Number((summary.findings / summary.scans).toFixed(2))
    : 0;

  return summary;
}

export function timeSeries(records) {
  const buckets = new Map();

  for (const record of records) {
    const day = new Date(record.timestamp * 1000).toISOString().slice(0, 10);
    let bucket = buckets.get(day);
    if (!bucket) {
      bucket = {
        day,
        scans: 0,
        findings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        ai_estimated: 0,
        high_or_above: 0,
        ai_ratio: 0,
      };
      buckets.set(day, bucket);
    }

    bucket.scans += 1;
    bucket.findings += record.total;
    bucket.critical += record.critical;
    bucket.high += record.high;
    bucket.medium += record.medium;
    bucket.low += record.low;
    bucket.info += record.info;
    bucket.ai_estimated += record.ai_estimated;
  }

  const series = Array.from(buckets.values()).sort((a, b) => a.day.localeCompare(b.day));
  for (const point of series) {
    point.high_or_above = point.critical + point.high;
    point.ai_ratio = point.findings > 0
      ? Number((point.ai_estimated / point.findings).toFixed(4))
      : 0;
  }
  return series;
}

export function topRules(records, limit = 10) {
  const counts = new Map();
  for (const record of records) {
    if (!record.top_rule || record.top_rule === '-') {
      continue;
    }
    counts.set(record.top_rule, (counts.get(record.top_rule) || 0) + 1);
  }

  return Array.from(counts.entries())
    .map(([rule, count]) => ({ rule, count }))
    .sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule))
    .slice(0, Math.max(1, limit));
}

export function topTargets(records, limit = 10) {
  const counts = new Map();

  for (const record of records) {
    const target = record.target || '.';
    let agg = counts.get(target);
    if (!agg) {
      agg = { target, findings: 0, scans: 0, critical: 0, high: 0 };
      counts.set(target, agg);
    }

    agg.findings += record.total;
    agg.scans += 1;
    agg.critical += record.critical;
    agg.high += record.high;
  }

  return Array.from(counts.values())
    .sort((a, b) => b.findings - a.findings || a.target.localeCompare(b.target))
    .slice(0, Math.max(1, limit));
}

export function percentChange(currentValue, previousValue) {
  if (!Number.isFinite(previousValue) || previousValue <= 0) {
    if (!Number.isFinite(currentValue) || currentValue <= 0) {
      return 0;
    }
    return null;
  }

  return Number((((currentValue - previousValue) / previousValue) * 100).toFixed(1));
}
