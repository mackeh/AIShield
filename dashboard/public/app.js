const SVG_NS = 'http://www.w3.org/2000/svg';

const kpiRoot = document.getElementById('kpis');
const kpiTemplate = document.getElementById('kpi-template');
const trend = document.getElementById('trend-chart');
const rulesList = document.getElementById('top-rules');
const targetsList = document.getElementById('top-targets');
const snapshotList = document.getElementById('snapshot');
const deltasRoot = document.getElementById('deltas');
const severityBody = document.querySelector('#severity-table tbody');
const historyFile = document.getElementById('history-file');
const ingestCmd = document.getElementById('ingest-cmd');
const daysSelect = document.getElementById('days');
const refreshBtn = document.getElementById('refresh');

const fmt = new Intl.NumberFormat();

daysSelect.addEventListener('change', () => load());
refreshBtn.addEventListener('click', () => load());

load().catch(console.error);

async function load() {
  const days = Number(daysSelect.value || 30);
  const response = await fetch(`/api/analytics?days=${days}&limit=10`, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`dashboard api failed: ${response.status}`);
  }

  const payload = await response.json();
  renderKPIs(payload.summary);
  renderTrend(payload.series || []);
  renderTopRules(payload.top_rules || []);
  renderTopTargets(payload.top_targets || []);
  renderTable(payload.series || []);
  renderSnapshot(payload);
  renderDeltas(payload.comparison || {});

  historyFile.textContent = payload.history_file || '';
  ingestCmd.textContent = 'cargo run -p aishield-cli -- scan . --format json --output aishield.json\n'
    + 'node dashboard/scripts/ingest-report.js --input aishield.json --target repo';
}

function clearNode(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function renderKPIs(summary) {
  const items = [
    ['Scans', summary.scans],
    ['Findings', summary.findings],
    ['High+', summary.high_or_above],
    ['Critical', summary.severity.critical],
    ['Average / scan', summary.avg_findings_per_scan],
    ['AI-estimated', summary.ai_estimated],
    ['AI ratio', `${(summary.ai_ratio * 100).toFixed(1)}%`],
  ];

  clearNode(kpiRoot);
  for (const [label, value] of items) {
    const node = kpiTemplate.content.cloneNode(true);
    node.querySelector('h3').textContent = label;
    node.querySelector('p').textContent = typeof value === 'number' ? fmt.format(value) : value;
    kpiRoot.appendChild(node);
  }
}

function svgEl(name, attrs = {}) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs)) {
    el.setAttribute(key, String(value));
  }
  return el;
}

function renderTrend(series) {
  const w = 960;
  const h = 260;
  const pad = { x: 36, y: 24 };
  clearNode(trend);

  if (!series.length) {
    const text = svgEl('text', { x: 20, y: 40, fill: '#8fa9bc' });
    text.textContent = 'No scan history in selected window.';
    trend.appendChild(text);
    return;
  }

  const maxY = Math.max(...series.map((p) => Math.max(p.findings, p.high_or_above)), 1);
  const xStep = (w - pad.x * 2) / Math.max(1, series.length - 1);
  const toX = (idx) => pad.x + idx * xStep;
  const toY = (val) => h - pad.y - (val / maxY) * (h - pad.y * 2);

  const findingsLine = series.map((point, idx) => `${toX(idx)},${toY(point.findings)}`).join(' ');
  const highLine = series.map((point, idx) => `${toX(idx)},${toY(point.high_or_above)}`).join(' ');
  const baseLeft = `${pad.x},${h - pad.y}`;
  const baseRight = `${toX(series.length - 1)},${h - pad.y}`;

  trend.appendChild(svgEl('polyline', {
    points: `${baseLeft} ${baseRight}`,
    stroke: '#21435b',
    'stroke-width': 1,
    fill: 'none',
  }));

  trend.appendChild(svgEl('polygon', {
    points: `${baseLeft} ${findingsLine} ${baseRight}`,
    fill: 'rgba(25,180,164,0.18)',
  }));

  trend.appendChild(svgEl('polyline', {
    points: findingsLine,
    fill: 'none',
    stroke: '#19b4a4',
    'stroke-width': 2.4,
  }));

  trend.appendChild(svgEl('polyline', {
    points: highLine,
    fill: 'none',
    stroke: '#ff6b5f',
    'stroke-width': 2,
    'stroke-dasharray': '3 2',
  }));

  series.forEach((point, idx) => {
    const circle = svgEl('circle', {
      cx: toX(idx),
      cy: toY(point.findings),
      r: 2.8,
      fill: '#19b4a4',
    });
    const title = svgEl('title');
    title.textContent = `${point.day}: ${point.findings} findings`;
    circle.appendChild(title);
    trend.appendChild(circle);
  });
}

function makeChip(text) {
  const em = document.createElement('em');
  em.className = 'chip';
  em.textContent = text;
  return em;
}

function addNoneRow(root) {
  const item = document.createElement('li');
  const left = document.createElement('span');
  left.textContent = 'None';
  const right = document.createElement('strong');
  right.textContent = '0';
  item.append(left, right);
  root.appendChild(item);
}

function renderTopRules(rows) {
  clearNode(rulesList);
  if (!rows.length) {
    addNoneRow(rulesList);
    return;
  }

  for (const row of rows) {
    const item = document.createElement('li');
    const left = document.createElement('span');
    left.textContent = row.rule;
    left.appendChild(makeChip('rule'));

    const value = document.createElement('strong');
    value.textContent = fmt.format(row.count);
    item.append(left, value);
    rulesList.appendChild(item);
  }
}

function renderTopTargets(rows) {
  clearNode(targetsList);
  if (!rows.length) {
    addNoneRow(targetsList);
    return;
  }

  for (const row of rows) {
    const item = document.createElement('li');
    const left = document.createElement('span');
    left.textContent = row.target;
    left.appendChild(makeChip(`${fmt.format(row.scans)} scan(s)`));

    const value = document.createElement('strong');
    value.textContent = fmt.format(row.findings);
    item.append(left, value);
    targetsList.appendChild(item);
  }
}

function renderSnapshot(payload) {
  const summary = payload.summary || {};
  const metadata = payload.metadata || {};

  const rows = [
    ['Window scans', summary.scans],
    ['Days with activity', metadata.days_with_activity || 0],
    ['Scans in history', metadata.total_scans_available || 0],
    ['Generated', payload.generated_at ? new Date(payload.generated_at).toLocaleString() : '-'],
  ];

  clearNode(snapshotList);
  for (const [label, value] of rows) {
    const item = document.createElement('li');
    const left = document.createElement('span');
    left.textContent = label;

    const right = document.createElement('strong');
    right.textContent = typeof value === 'number' ? fmt.format(value) : String(value);
    item.append(left, right);
    snapshotList.appendChild(item);
  }
}

function renderDelta(label, value) {
  const pill = document.createElement('span');
  pill.className = 'delta';

  if (value === null) {
    pill.classList.add('neutral');
    pill.textContent = `${label}: n/a`;
    return pill;
  }

  const sign = value > 0 ? '+' : '';
  if (value > 0) {
    pill.classList.add('up');
  } else if (value < 0) {
    pill.classList.add('down');
  } else {
    pill.classList.add('neutral');
  }

  pill.textContent = `${label}: ${sign}${value.toFixed(1)}%`;
  return pill;
}

function renderDeltas(comparison) {
  clearNode(deltasRoot);
  deltasRoot.append(
    renderDelta('Findings', comparison.findings_delta_pct ?? 0),
    renderDelta('Critical', comparison.critical_delta_pct ?? 0),
    renderDelta('High+', comparison.high_or_above_delta_pct ?? 0),
    renderDelta('AI ratio', comparison.ai_ratio_delta_pct ?? 0),
  );
}

function severityBadge(kind, value) {
  const span = document.createElement('span');
  span.className = `sev sev-${kind}`;
  span.textContent = fmt.format(value);
  return span;
}

function addCell(row, content) {
  const td = document.createElement('td');
  if (typeof content === 'string' || typeof content === 'number') {
    td.textContent = String(content);
  } else {
    td.appendChild(content);
  }
  row.appendChild(td);
}

function renderTable(series) {
  clearNode(severityBody);

  for (const rowData of series) {
    const row = document.createElement('tr');
    addCell(row, rowData.day);
    addCell(row, fmt.format(rowData.scans));
    addCell(row, fmt.format(rowData.findings));
    addCell(row, severityBadge('highplus', rowData.high_or_above));
    addCell(row, severityBadge('critical', rowData.critical));
    addCell(row, severityBadge('high', rowData.high));
    addCell(row, severityBadge('medium', rowData.medium));
    addCell(row, severityBadge('low', rowData.low));
    addCell(row, `${fmt.format(rowData.ai_estimated)} (${(rowData.ai_ratio * 100).toFixed(0)}%)`);
    severityBody.appendChild(row);
  }
}
