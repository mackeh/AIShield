import { AnalyticsAPIClient } from './api-client.js';
import { createSettingsPanel, showSettings } from './settings.js';

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
const settingsBtn = document.getElementById('settings-btn');
const orgFilter = document.getElementById('org-filter');
const teamFilter = document.getElementById('team-filter');
const repoFilter = document.getElementById('repo-filter');
const filterGroup = document.getElementById('filter-group');

const fmt = new Intl.NumberFormat();

// Initialize API client
const apiClient = AnalyticsAPIClient.fromLocalStorage();

// Initialize settings panel
createSettingsPanel();

// Show filters only in API mode
if (apiClient.isConfigured()) {
  filterGroup.style.display = 'flex';
  loadFilterOptions();
}

// Event listeners
daysSelect.addEventListener('change', () => load());
refreshBtn.addEventListener('click', () => load());
settingsBtn.addEventListener('click', () => showSettings());
orgFilter.addEventListener('change', () => {
  teamFilter.value = '';
  repoFilter.value = '';
  load();
});
teamFilter.addEventListener('change', () => load());
repoFilter.addEventListener('change', () => load());

load().catch(console.error);

async function load() {
  const days = Number(daysSelect.value || 30);
  
  // Try API client first if configured
  if (apiClient.isConfigured()) {
    try {
      console.log('Loading data from Analytics API...');
      updateModeBadge('api');
      
      // Build filter object from UI
      const filters = {
        days,
        limit: 10,
      };
      
      if (orgFilter.value) filters.org_id = orgFilter.value;
      if (teamFilter.value) filters.team_id = teamFilter.value;
      if (repoFilter.value) filters.repo_id = repoFilter.value;
      
      const summary = await apiClient.fetchSummary(filters);
      
      // Transform API response to match existing dashboard format
      const payload = {
        summary: summary.summary,
        series: summary.time_series,
        top_rules: summary.top_rules,
        top_targets: summary.top_repos, // API returns top_repos
        comparison: summary.trend || {},
        generated_at: new Date().toISOString(),
        metadata: {
          days_with_activity: summary.time_series?.length || 0,
          total_scans_available: summary.summary?.scans || 0,
        },
        history_file: `API Mode (${summary.org_id || 'all orgs'})`,
      };
      
      // Update history file display with filters
      if (filters.org_id || filters.team_id || filters.repo_id) {
        const filterParts = [];
        if (filters.org_id) filterParts.push(`org:${filters.org_id}`);
        if (filters.team_id) filterParts.push(`team:${filters.team_id}`);
        if (filters.repo_id) filterParts.push(`repo:${filters.repo_id}`);
        payload.history_file = `API Mode (${filterParts.join(', ')})`;
      }
      
      renderDashboard(payload);
      return;
    } catch (error) {
      console.warn('API fetch failed, falling back to file-based mode:', error.message);
      // Fall through to file-based mode
    }
  }
  
  // Fallback: Use existing file-based endpoint
  console.log('Loading data from file-based endpoint...');
  updateModeBadge('file');
  const response = await fetch(`/api/analytics?days=${days}&limit=10`, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`dashboard api failed: ${response.status}`);
  }

  const payload = await response.json();
  renderDashboard(payload);
}

function renderDashboard(payload) {
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
  
  // Render enterprise visualizations if in API mode
  if (apiClient.isConfigured()) {
    showEnterpriseViz();
    renderOrgHeatmap();
    renderTeamComparison();
  }
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

function updateModeBadge(mode) {
  const badge = document.getElementById('mode-badge');
  if (!badge) return;

  badge.className = 'mode-badge';
  
  if (mode === 'api') {
    badge.classList.add('api-mode');
    badge.textContent = '🌐 API Mode';
    badge.title = 'Loading data from Analytics API';
  } else if (mode === 'file') {
    badge.classList.add('file-mode');
    badge.textContent = '📁 File Mode';
    badge.title = 'Loading data from local history file';
  } else if (mode === 'error') {
    badge.classList.add('error-mode');
    badge.textContent = '⚠️ Error';
    badge.title = 'Error loading data';
  }
}

// Load filter options from API
async function loadFilterOptions() {
  if (!apiClient.isConfigured()) return;
  
  try {
    // Fetch available scans to extract unique orgs/teams/repos
    const scansData = await apiClient.fetchScans({ limit: 1000 });
    const scans = scansData.scans || [];
    
    // Extract unique values
    const orgs = [...new Set(scans.map(s => s.org_id).filter(Boolean))];
    const teams = [...new Set(scans.map(s => s.team_id).filter(Boolean))];
    const repos = [...new Set(scans.map(s => s.repo_name).filter(Boolean))];
    
    // Populate org filter
    orgs.sort().forEach(org => {
      const option = document.createElement('option');
      option.value = org;
      option.textContent = org;
      orgFilter.appendChild(option);
    });
    
    // Populate team filter
    teams.sort().forEach(team => {
      const option = document.createElement('option');
      option.value = team;
      option.textContent = team;
      teamFilter.appendChild(option);
    });
    
    // Populate repo filter
    repos.sort().forEach(repo => {
      const option = document.createElement('option');
      option.value = repo;
      option.textContent = repo;
      repoFilter.appendChild(option);
    });
    
    console.log(`Loaded filters: ${orgs.length} orgs, ${teams.length} teams, ${repos.length} repos`);
  } catch (error) {
    console.warn('Failed to load filter options:', error);
  }
}

// Show enterprise visualizations in API mode
function showEnterpriseViz() {
  if (apiClient.isConfigured()) {
    document.getElementById('org-heatmap-panel').style.display = 'block';
    document.getElementById('team-comparison-panel').style.display = 'block';
  }
}

// Render organization heatmap
async function renderOrgHeatmap() {
  const container = document.getElementById('org-heatmap');
  if (!apiClient.isConfigured()) return;
  
  try {
    // Fetch scans grouped by team
    const scansData = await apiClient.fetchScans({ limit: 1000 });
    const scans = scansData.scans || [];
    
    // Group by team_id and calculate metrics
    const teamMetrics = {};
    scans.forEach(scan => {
      const team = scan.team_id || 'Unassigned';
      if (!teamMetrics[team]) {
        teamMetrics[team] = {
          name: team,
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          scans: 0
        };
      }
      
      teamMetrics[team].total += scan.total_findings;
      teamMetrics[team].critical += scan.critical;
      teamMetrics[team].high += scan.high;
      teamMetrics[team].medium += scan.medium;
      teamMetrics[team].low += scan.low;
      teamMetrics[team].scans += 1;
    });
    
    // Sort by total findings
    const teams = Object.values(teamMetrics).sort((a, b) => b.total - a.total);
    
    if (teams.length === 0) {
      container.innerHTML = '<div class="viz-empty"><div class="icon">📊</div><p>No team data available</p><p>Run scans with --team-id to populate this view</p></div>';
      return;
    }
    
    // Find max for scaling
    const maxFindings = Math.max(...teams.map(t => t.total), 1);
    
    // Render heatmap rows
    container.innerHTML = '';
    teams.forEach(team => {
      const row = document.createElement('div');
      row.className = 'heatmap-row';
      
      const label = document.createElement('div');
      label.className = 'heatmap-label';
      label.textContent = team.name;
      label.title = `${team.scans} scans`;
      
      const bar = document.createElement('div');
      bar.className = 'heatmap-bar';
      
      // Determine heat level based on severity
      if (team.critical > 0) {
        bar.classList.add('heat-critical');
      } else if (team.high > 5) {
        bar.classList.add('heat-high');
      } else if (team.total > 0) {
        bar.classList.add('heat-medium');
      } else {
        bar.classList.add('heat-none');
      }
      
      // Scale width based on total findings
      const widthPercent = (team.total / maxFindings) * 100;
      bar.style.width = `${widthPercent}%`;
      bar.style.minWidth = '80px';
      
      bar.textContent = `${team.total} findings`;
      bar.title = `Critical: ${team.critical}, High: ${team.high}, Medium: ${team.medium}, Low: ${team.low}`;
      
      row.appendChild(label);
      row.appendChild(bar);
      container.appendChild(row);
    });
  } catch (error) {
    console.error('Failed to render org heatmap:', error);
    container.innerHTML = '<div class="viz-empty"><div class="icon">⚠️</div><p>Failed to load heatmap data</p></div>';
  }
}

// Render team comparison chart
async function renderTeamComparison() {
  const container = document.getElementById('team-comparison');
  if (!apiClient.isConfigured()) return;
  
  try {
    // Fetch scans grouped by team
    const scansData = await apiClient.fetchScans({ limit: 1000 });
    const scans = scansData.scans || [];
    
    // Group by team_id
    const teamData = {};
    scans.forEach(scan => {
      const team = scan.team_id || 'Unassigned';
      if (!teamData[team]) {
        teamData[team] = {
          name: team,
          totalFindings: 0,
          critical: 0,
          high: 0,
          scans: 0,
          avgFindings: 0,
          aiEstimated: 0
        };
      }
      
      teamData[team].totalFindings += scan.total_findings;
      teamData[team].critical += scan.critical;
      teamData[team].high += scan.high;
      teamData[team].scans += 1;
      teamData[team].aiEstimated += scan.ai_estimated_count || 0;
    });
    
    // Calculate averages
    Object.values(teamData).forEach(team => {
      team.avgFindings = team.scans > 0 ? (team.totalFindings / team.scans).toFixed(1) : 0;
    });
    
    // Sort and take top 8 teams
    const teams = Object.values(teamData)
      .sort((a, b) => b.totalFindings - a.totalFindings)
      .slice(0, 8);
    
    if (teams.length === 0) {
      container.innerHTML = '<div class="viz-empty"><div class="icon">📊</div><p>No team data available</p></div>';
      return;
    }
    
    // Render comparison cards
    const grid = document.createElement('div');
    grid.className = 'comparison-grid';
    
    teams.forEach(team => {
      const card = document.createElement('div');
      card.className = 'team-card';
      
      const criticalClass = team.critical > 0 ? 'critical' : team.high > 5 ? 'high' : 'good';
      
      card.innerHTML = `
        <h3>${team.name}</h3>
        <div class="team-metric">
          <span class="team-metric-label">Total Findings</span>
          <span class="team-metric-value">${fmt.format(team.totalFindings)}</span>
        </div>
        <div class="team-metric">
          <span class="team-metric-label">Critical</span>
          <span class="team-metric-value ${team.critical > 0 ? 'critical' : ''}">${team.critical}</span>
        </div>
        <div class="team-metric">
          <span class="team-metric-label">High</span>
          <span class="team-metric-value ${team.high > 5 ? 'high' : ''}">${team.high}</span>
        </div>
        <div class="team-metric">
          <span class="team-metric-label">Avg/Scan</span>
          <span class="team-metric-value">${team.avgFindings}</span>
        </div>
        <div class="team-metric">
          <span class="team-metric-label">AI-Estimated</span>
          <span class="team-metric-value">${team.aiEstimated}</span>
        </div>
        <div class="team-metric">
          <span class="team-metric-label">Scans</span>
          <span class="team-metric-value good">${team.scans}</span>
        </div>
      `;
      
      grid.appendChild(card);
    });
    
    container.innerHTML = '';
    container.appendChild(grid);
  } catch (error) {
    console.error('Failed to render team comparison:', error);
    container.innerHTML = '<div class="viz-empty"><div class="icon">⚠️</div><p>Failed to load comparison data</p></div>';
  }
}

// ============================================================
// AI METRICS RENDERING
// ============================================================

async function renderAIMetrics() {
  if (!apiClient.isConfigured()) {
    document.getElementById('ai-metrics-panel').style.display = 'none';
    return;
  }

  try {
    const filters = {
      days: Number(daysSelect.value || 30),
      org_id: orgFilter.value || undefined,
      team_id: teamFilter.value || undefined,
    };

    console.log('[AI Metrics] Fetching data...');
    const data = await apiClient.fetchAIMetrics(filters);
    
    document.getElementById('ai-metrics-panel').style.display = 'block';
    
    renderToolBreakdown(data.by_tool);
    renderTopAIPatterns(data.by_pattern);
    renderConfidenceDistribution(data.confidence_distribution);
    
    console.log('[AI Metrics] Rendered successfully');
  } catch (error) {
    console.error('[AI Metrics] Error:', error);
    document.getElementById('ai-metrics-panel').style.display = 'none';
  }
}

function renderToolBreakdown(tools) {
  const container = document.getElementById('ai-tool-breakdown');
  if (!tools || tools.length === 0) {
    container.innerHTML = '<p style="color: var(--text-muted);">No AI-detected findings</p>';
    return;
  }

  const html = tools.map(tool => `
    <div class="ai-tool-item">
      <div>
        <div class="ai-tool-name">${tool.tool}</div>
        <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;">
          ${tool.findings} findings
        </div>
      </div>
      <div class="ai-tool-stats">
        <span title="Percentage of AI findings">${tool.percentage.toFixed(1)}%</span>
        <span title="Average confidence">⭐ ${tool.avg_confidence.toFixed(1)}%</span>
      </div>
    </div>
  `).join('');

  container.innerHTML = html;
}

function renderTopAIPatterns(patterns) {
  const container = document.getElementById('ai-top-patterns');
  if (!patterns || patterns.length === 0) {
    container.innerHTML = '<p style="color: var(--text-muted);">No AI patterns detected</p>';
    return;
  }

  const html = patterns.slice(0, 5).map(pattern => `
    <div class="ai-pattern-item">
      <div class="ai-pattern-id">${pattern.pattern_id}</div>
      <div class="ai-pattern-desc">${pattern.description.substring(0, 60)}${pattern.description.length > 60 ? '...' : ''}</div>
      <div class="ai-pattern-meta">
        <span>Count: ${pattern.count}</span>
        <span>Tool: ${pattern.tool || 'N/A'}</span>
        <span>⭐ ${pattern.avg_confidence.toFixed(1)}%</span>
      </div>
    </div>
  `).join('');

  container.innerHTML = html;
}

function renderConfidenceDistribution(dist) {
  const container = document.getElementById('ai-confidence-dist');
  const total = dist.high + dist.medium + dist.low;
  
  if (total === 0) {
    container.innerHTML = '<p style="color: var(--text-muted);">No confidence data available</p>';
    return;
  }

  const highPct = (dist.high / total * 100).toFixed(1);
  const mediumPct = (dist.medium / total * 100).toFixed(1);
  const lowPct = (dist.low / total * 100).toFixed(1);

  container.innerHTML = `
    <div class="confidence-bar">
      <div class="confidence-label">
        <span>High (80-100%)</span>
        <span><strong>${dist.high}</strong> (${highPct}%)</span>
      </div>
      <div class="confidence-bar-inner confidence-high" style="width: ${highPct}%">
        <span>${highPct}%</span>
      </div>
    </div>
    
    <div class="confidence-bar">
      <div class="confidence-label">
        <span>Medium (60-80%)</span>
        <span><strong>${dist.medium}</strong> (${mediumPct}%)</span>
      </div>
      <div class="confidence-bar-inner confidence-medium" style="width: ${mediumPct}%">
        <span>${mediumPct}%</span>
      </div>
    </div>
    
    <div class="confidence-bar">
      <div class="confidence-label">
        <span>Low (<60%)</span>
        <span><strong>${dist.low}</strong> (${lowPct}%)</span>
      </div>
      <div class="confidence-bar-inner confidence-low" style="width: ${lowPct}%">
        <span>${lowPct}%</span>
      </div>
    </div>
  `;
}

// ============================================================
// COMPLIANCE REPORTING
// ============================================================

const exportBtn = document.getElementById('export-btn');
const reportModal = document.getElementById('report-modal');
const closeReportBtn = document.getElementById('close-report-modal');
const cancelReportBtn = document.getElementById('cancel-report-btn');
const generateReportBtn = document.getElementById('generate-report-btn');

function initReporting() {
  if (apiClient.isConfigured()) {
    exportBtn.style.display = 'inline-block';
  }

  // Open modal
  exportBtn.addEventListener('click', () => {
    reportModal.style.display = 'flex';
    // Set default dates
    const today = new Date();
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(today.getDate() - 30);
    
    document.getElementById('report-end').value = today.toISOString().split('T')[0];
    document.getElementById('report-start').value = thirtyDaysAgo.toISOString().split('T')[0];
  });

  // Close modal functions
  const close = () => reportModal.style.display = 'none';
  closeReportBtn.addEventListener('click', close);
  cancelReportBtn.addEventListener('click', close);
  window.addEventListener('click', (e) => {
    if (e.target === reportModal) close();
  });

  // Generate action
  generateReportBtn.addEventListener('click', async () => {
    const originalText = generateReportBtn.innerText;
    generateReportBtn.innerText = 'Generating...';
    generateReportBtn.disabled = true;

    try {
      const format = document.getElementById('report-format').value;
      const template = document.getElementById('report-template').value;
      const start = document.getElementById('report-start').value;
      const end = document.getElementById('report-end').value;
      
      const blob = await apiClient.generateReport({
        org_id: orgFilter.value || 'all', // Backend handles 'all' or specific org
        format: format === 'pdf-text' ? 'pdf' : format,
        template,
        start_date: start,
        end_date: end
      });
      
      // Trigger download
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `compliance-report-${orgFilter.value || 'all'}-${Date.now()}.${format === 'csv' ? 'csv' : 'txt'}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      close();
    } catch (error) {
      console.error('Report error:', error);
      alert('Failed to generate report: ' + error.message);
    } finally {
      generateReportBtn.innerText = originalText;
      generateReportBtn.disabled = false;
    }
  });
}

// Initialize reporting when app loads
document.addEventListener('DOMContentLoaded', () => {
    // ... existing init code ...
    initReporting();
});
