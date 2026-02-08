import * as vscode from "vscode";

export const TELEMETRY_KEY = "aishield.telemetry.v1";
export const MAX_SCAN_DURATION_SAMPLES = 60;

export type TelemetryState = {
  scansStarted: number;
  scansCompleted: number;
  scansFailed: number;
  fixesApplied: number;
  aiPasteSignals: number;
  findingsPublished: number;
  diagnosticsDropped: number;
  eventsSampled: number;
  scanDurationsMs: number[];
  lastUpdated: string;
  performanceHintShownCount: number;
};

export function loadTelemetryState(context: vscode.ExtensionContext): TelemetryState {
  return (
    context.globalState.get<TelemetryState>(TELEMETRY_KEY) ?? createEmptyTelemetryState()
  );
}

export function createEmptyTelemetryState(): TelemetryState {
  return {
    scansStarted: 0,
    scansCompleted: 0,
    scansFailed: 0,
    fixesApplied: 0,
    aiPasteSignals: 0,
    findingsPublished: 0,
    diagnosticsDropped: 0,
    eventsSampled: 0,
    scanDurationsMs: [],
    lastUpdated: new Date().toISOString(),
    performanceHintShownCount: 0,
  };
}

export function percentileNumbers(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil(p * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
}

export function telemetrySummaryText(t: TelemetryState): string {
    const p50 = percentileNumbers(t.scanDurationsMs, 0.5) / 1000;
    const p95 = percentileNumbers(t.scanDurationsMs, 0.95) / 1000;
    
    return `
AIShield Local Telemetry Summary
--------------------------------
Last Updated: ${t.lastUpdated}

Scans:
  Started:   ${t.scansStarted}
  Completed: ${t.scansCompleted}
  Failed:    ${t.scansFailed}

Performance (sec):
  p50 (Median): ${p50.toFixed(2)}s
  p95 (Slow):   ${p95.toFixed(2)}s
  Samples:      ${t.scanDurationsMs.length}

Features:
  AI Paste Signals: ${t.aiPasteSignals}
  Fixes Applied:    ${t.fixesApplied}

Diagnostics:
  Published: ${t.findingsPublished}
  Dropped:   ${t.diagnosticsDropped}
`;
}

export function clampNumber(val: number | undefined, min: number, max: number): number {
    return Math.min(Math.max(val ?? min, min), max);
}
