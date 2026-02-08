#!/usr/bin/env node

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  filterByDays,
  filterByRange,
  loadHistory,
  percentChange,
  summarize,
  timeSeries,
  topRules,
  topTargets,
} from './lib/history.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.AISHIELD_DASHBOARD_PORT || process.env.PORT || 4318);
const HISTORY_PATH = process.env.AISHIELD_HISTORY_FILE || '.aishield-history.log';
const STATIC_ROOT = path.join(__dirname, 'public');

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendText(res, status, text, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': Buffer.byteLength(text),
  });
  res.end(text);
}

function parseDays(query) {
  const raw = Number(query.days || 30);
  if (!Number.isFinite(raw) || raw <= 0) {
    return 30;
  }
  return Math.min(3650, Math.max(1, Math.round(raw)));
}

function parseLimit(query, fallback) {
  const raw = Number(query.limit || fallback);
  if (!Number.isFinite(raw) || raw <= 0) {
    return fallback;
  }
  return Math.min(100, Math.max(1, Math.round(raw)));
}

function buildPayload(days, ruleLimit, targetLimit) {
  const allRecords = loadHistory(HISTORY_PATH);
  const nowEpoch = Math.floor(Date.now() / 1000);
  const currentRecords = filterByDays(allRecords, days, nowEpoch);

  const seconds = Math.floor(days * 86400);
  const currentStart = nowEpoch - seconds;
  const previousStart = currentStart - seconds;
  const previousRecords = filterByRange(allRecords, previousStart, currentStart);

  const summary = summarize(currentRecords);
  const previous = summarize(previousRecords);

  return {
    generated_at: new Date().toISOString(),
    days,
    history_file: path.resolve(HISTORY_PATH),
    summary,
    comparison: {
      scans_delta_pct: percentChange(summary.scans, previous.scans),
      findings_delta_pct: percentChange(summary.findings, previous.findings),
      critical_delta_pct: percentChange(summary.severity.critical, previous.severity.critical),
      high_or_above_delta_pct: percentChange(summary.high_or_above, previous.high_or_above),
      ai_ratio_delta_pct: percentChange(summary.ai_ratio * 100, previous.ai_ratio * 100),
      previous_window_scans: previous.scans,
      previous_window_findings: previous.findings,
    },
    metadata: {
      total_scans_available: allRecords.length,
      window_scans: currentRecords.length,
      days_with_activity: timeSeries(currentRecords).length,
      history_exists: fs.existsSync(path.resolve(HISTORY_PATH)),
    },
    series: timeSeries(currentRecords),
    top_rules: topRules(currentRecords, ruleLimit),
    top_targets: topTargets(currentRecords, targetLimit),
  };
}

function safePublicPath(requestPath) {
  const requested = decodeURIComponent(requestPath || '/');
  const withDefault = requested === '/' ? '/index.html' : requested;
  const normalized = path.normalize(withDefault).replace(/^\.+[\\/]+/, '');
  const candidate = path.join(STATIC_ROOT, normalized);
  if (!candidate.startsWith(STATIC_ROOT)) {
    return null;
  }
  return candidate;
}

function staticContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.css':
      return 'text/css; charset=utf-8';
    case '.js':
      return 'text/javascript; charset=utf-8';
    case '.json':
      return 'application/json; charset=utf-8';
    case '.svg':
      return 'image/svg+xml';
    default:
      return 'application/octet-stream';
  }
}

const server = http.createServer((req, res) => {
  const requestUrl = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);

  if (requestUrl.pathname === '/api/health') {
    return sendJson(res, 200, { ok: true, service: 'aishield-dashboard' });
  }

  if (requestUrl.pathname === '/api/analytics') {
    try {
      const days = parseDays(Object.fromEntries(requestUrl.searchParams.entries()));
      const limit = parseLimit(Object.fromEntries(requestUrl.searchParams.entries()), 10);
      return sendJson(res, 200, buildPayload(days, limit, limit));
    } catch (error) {
      return sendJson(res, 500, {
        error: 'analytics_error',
        message: String(error && error.message ? error.message : error),
      });
    }
  }

  const filePath = safePublicPath(requestUrl.pathname || '/');
  if (!filePath) {
    return sendText(res, 403, 'Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (requestUrl.pathname !== '/' && requestUrl.pathname !== '/index.html') {
        return sendText(res, 404, 'Not Found');
      }
      const fallback = path.join(STATIC_ROOT, 'index.html');
      fs.readFile(fallback, (fallbackErr, fallbackData) => {
        if (fallbackErr) {
          return sendText(res, 500, 'Dashboard unavailable');
        }
        return sendText(res, 200, fallbackData.toString('utf8'), 'text/html; charset=utf-8');
      });
      return;
    }

    res.writeHead(200, {
      'Content-Type': staticContentType(filePath),
      'Content-Length': data.length,
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`AIShield dashboard listening on http://127.0.0.1:${PORT}`);
  console.log(`History source: ${path.resolve(HISTORY_PATH)}`);
});
