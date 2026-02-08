import * as cp from "node:child_process";
import * as path from "node:path";
import * as vscode from "vscode";

type AiShieldFinding = {
  id: string;
  title: string;
  severity: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  risk_score?: number;
  ai_confidence?: number;
  fix_suggestion?: string;
};

type AiShieldScanResult = {
  summary?: { total?: number };
  findings?: AiShieldFinding[];
};

type CliInvocation = {
  command: string;
  args: string[];
};

type ScanContext = {
  targetPath: string;
  workspaceRoot: string;
};

type FindingEntry = {
  finding: AiShieldFinding;
  uri: vscode.Uri;
  range: vscode.Range;
  key: string;
};

type TelemetryState = {
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

type ScanReason = "workspace" | "current-file" | "refresh" | "save" | "ai-paste" | "fix-follow-up";

const TELEMETRY_KEY = "aishield.telemetry.v1";
const MAX_SCAN_DURATION_SAMPLES = 60;

class FindingsProvider implements vscode.TreeDataProvider<FindingEntry> {
  private readonly emitter = new vscode.EventEmitter<FindingEntry | undefined | null | void>();
  private items: FindingEntry[] = [];

  readonly onDidChangeTreeData = this.emitter.event;

  setItems(next: FindingEntry[]): void {
    this.items = [...next].sort((a, b) => {
      const sevCmp = severityRank(b.finding.severity) - severityRank(a.finding.severity);
      if (sevCmp !== 0) {
        return sevCmp;
      }
      if (a.uri.fsPath !== b.uri.fsPath) {
        return a.uri.fsPath.localeCompare(b.uri.fsPath);
      }
      return (a.finding.line || 0) - (b.finding.line || 0);
    });
    this.emitter.fire();
  }

  clear(): void {
    this.items = [];
    this.emitter.fire();
  }

  getTreeItem(item: FindingEntry): vscode.TreeItem {
    const line = item.finding.line || 1;
    const label = `${severityLabel(item.finding.severity)} ${path.basename(item.uri.fsPath)}:${line} ${item.finding.title}`;
    const tree = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
    tree.tooltip = new vscode.MarkdownString(
      `**${item.finding.id}**\n\n${escapeMarkdown(item.finding.snippet)}\n\nRisk: ${(item.finding.risk_score ?? 0).toFixed(1)} | AI: ${(item.finding.ai_confidence ?? 0).toFixed(1)}`,
    );
    tree.description = item.finding.id;
    tree.command = {
      command: "aishield.openFinding",
      title: "Open Finding",
      arguments: [item],
    };
    tree.iconPath = iconForSeverity(item.finding.severity);
    return tree;
  }

  getChildren(): FindingEntry[] {
    return this.items;
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("aishield");
  const output = vscode.window.createOutputChannel("AIShield");
  const findings = new FindingsProvider();
  const lastScanByFile = new Map<string, FindingEntry[]>();
  const aiPasteSeen = new Set<string>();
  const activeScan = { value: null as Promise<void> | null };
  let lastScanContext: ScanContext | null = null;
  let autoScanTimer: NodeJS.Timeout | null = null;
  const telemetry = loadTelemetryState(context);

  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 30);
  statusBar.name = "AIShield";
  statusBar.command = "aishield.scanWorkspace";
  statusBar.text = "$(shield) AIShield: Ready";
  statusBar.tooltip = "AIShield security diagnostics";

  const updateStatusBarVisibility = (): void => {
    const enabled = vscode.workspace.getConfiguration("aishield").get<boolean>("statusBarEnabled", true);
    if (enabled) {
      statusBar.show();
    } else {
      statusBar.hide();
    }
  };

  const updateStatusBar = (summary: string, spinner = false): void => {
    const icon = spinner ? "$(sync~spin)" : "$(shield)";
    statusBar.text = `${icon} AIShield: ${summary}`;
  };

  const recordTelemetry = (reason: string, updater: (state: TelemetryState) => void): void => {
    const config = vscode.workspace.getConfiguration("aishield");
    const enabled = config.get<boolean>("telemetryEnabled", false);
    if (!enabled) {
      return;
    }
    const sampleRate = clampNumber(config.get<number>("telemetrySampleRate", 1), 0, 1);
    if (Math.random() > sampleRate) {
      return;
    }

    updater(telemetry);
    telemetry.eventsSampled += 1;
    telemetry.lastUpdated = new Date().toISOString();
    void context.globalState.update(TELEMETRY_KEY, telemetry);
    output.appendLine(`[AIShield][telemetry] ${reason}`);
  };

  const maybeShowPerformanceHint = (): void => {
    const config = vscode.workspace.getConfiguration("aishield");
    if (!config.get<boolean>("performanceHints", true)) {
      return;
    }
    if (!config.get<boolean>("telemetryEnabled", false)) {
      return;
    }
    if (telemetry.scanDurationsMs.length < 8 || telemetry.performanceHintShownCount >= 3) {
      return;
    }

    const p95 = percentileNumbers(telemetry.scanDurationsMs, 0.95);
    if (p95 < 4000) {
      return;
    }

    telemetry.performanceHintShownCount += 1;
    telemetry.lastUpdated = new Date().toISOString();
    void context.globalState.update(TELEMETRY_KEY, telemetry);

    void vscode.window
      .showWarningMessage(
        `AIShield scans are trending slow (p95 ${(p95 / 1000).toFixed(2)}s). Consider raising severity, reducing auto scans, or increasing debounce.`,
        "Open AIShield Settings",
        "Disable Hints",
      )
      .then((action) => {
        if (action === "Open AIShield Settings") {
          void vscode.commands.executeCommand("workbench.action.openSettings", "aishield.scanDebounceMs");
        } else if (action === "Disable Hints") {
          void config.update("performanceHints", false, vscode.ConfigurationTarget.Workspace);
        }
      });
  };

  const lensCritical = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    backgroundColor: "rgba(220,38,38,0.10)",
    borderColor: "rgba(220,38,38,0.35)",
    borderStyle: "solid",
    borderWidth: "0 0 0 2px",
  });
  const lensHigh = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    backgroundColor: "rgba(249,115,22,0.10)",
    borderColor: "rgba(249,115,22,0.35)",
    borderStyle: "solid",
    borderWidth: "0 0 0 2px",
  });
  const lensMedium = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    backgroundColor: "rgba(234,179,8,0.08)",
    borderColor: "rgba(234,179,8,0.30)",
    borderStyle: "solid",
    borderWidth: "0 0 0 2px",
  });

  context.subscriptions.push(
    diagnostics,
    output,
    statusBar,
    lensCritical,
    lensHigh,
    lensMedium,
    vscode.window.registerTreeDataProvider("aishield.findings", findings),
  );
  updateStatusBarVisibility();

  const refreshLens = (): void => {
    const enabled = vscode.workspace.getConfiguration("aishield").get<boolean>("securityLens", false);
    for (const editor of vscode.window.visibleTextEditors) {
      if (!enabled) {
        editor.setDecorations(lensCritical, []);
        editor.setDecorations(lensHigh, []);
        editor.setDecorations(lensMedium, []);
        continue;
      }

      const entries = lastScanByFile.get(editor.document.uri.fsPath) ?? [];
      const criticalRanges: vscode.Range[] = [];
      const highRanges: vscode.Range[] = [];
      const mediumRanges: vscode.Range[] = [];
      for (const entry of entries) {
        const sev = (entry.finding.severity || "").toLowerCase();
        if (sev === "critical") {
          criticalRanges.push(entry.range);
        } else if (sev === "high") {
          highRanges.push(entry.range);
        } else if (sev === "medium") {
          mediumRanges.push(entry.range);
        }
      }
      editor.setDecorations(lensCritical, criticalRanges);
      editor.setDecorations(lensHigh, highRanges);
      editor.setDecorations(lensMedium, mediumRanges);
    }
  };

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("aishield.securityLens")) {
        refreshLens();
      }
      if (event.affectsConfiguration("aishield.statusBarEnabled")) {
        updateStatusBarVisibility();
      }
    }),
    vscode.window.onDidChangeVisibleTextEditors(() => refreshLens()),
    vscode.window.onDidChangeActiveTextEditor(() => refreshLens()),
  );

  context.subscriptions.push(
    vscode.languages.registerHoverProvider({ scheme: "file" }, {
      provideHover(document, position) {
        const fileEntries = lastScanByFile.get(document.uri.fsPath) ?? [];
        const matches = fileEntries.filter((entry) => entry.range.contains(position));
        if (matches.length === 0) {
          return null;
        }

        const md = new vscode.MarkdownString(undefined, true);
        md.isTrusted = false;
        for (const [index, match] of matches.entries()) {
          if (index > 0) {
            md.appendMarkdown("\n---\n");
          }
          const f = match.finding;
          md.appendMarkdown(
            `**${escapeMarkdown(f.id)}** · ${severityLabel(f.severity)}\n\n` +
              `**${escapeMarkdown(f.title)}**\n\n` +
              `AI confidence: ${(f.ai_confidence ?? 0).toFixed(1)} · Risk: ${(f.risk_score ?? 0).toFixed(1)}\n\n` +
              `\`${escapeMarkdown(f.snippet)}\``,
          );
          if (f.fix_suggestion && f.fix_suggestion.trim().length > 0) {
            md.appendMarkdown(`\n\nFix suggestion: ${escapeMarkdown(f.fix_suggestion)}`);
          }
        }
        return new vscode.Hover(md);
      },
    }),
  );

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      {
        provideCodeActions(document, _range, context) {
          const out: vscode.CodeAction[] = [];
          const fileEntries = lastScanByFile.get(document.uri.fsPath) ?? [];
          if (fileEntries.length === 0) {
            return out;
          }

          for (const diagnostic of context.diagnostics) {
            const id = String(diagnostic.code ?? "");
            if (!id || diagnostic.source !== "AIShield") {
              continue;
            }
            const match = fileEntries.find(
              (entry) =>
                entry.finding.id === id &&
                entry.range.start.line === diagnostic.range.start.line,
            );
            if (!match) {
              continue;
            }

            const apply = new vscode.CodeAction(
              `AIShield: Apply fix (${match.finding.id})`,
              vscode.CodeActionKind.QuickFix,
            );
            apply.diagnostics = [diagnostic];
            apply.isPreferred = true;
            apply.command = {
              command: "aishield.applyFixForFinding",
              title: "Apply AIShield Fix",
              arguments: [match],
            };
            out.push(apply);
          }
          return out;
        },
      },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
  );

  const runScanWithLock = async (scanContext: ScanContext, reason: ScanReason): Promise<void> => {
    if (activeScan.value) {
      await activeScan.value;
    }
    updateStatusBar("Scanning…", true);
    recordTelemetry("scan.started", (state) => {
      state.scansStarted += 1;
    });
    activeScan.value = runScan(scanContext, reason, {
      diagnostics,
      output,
      findings,
      lastScanByFile,
      setLastContext: (next) => {
        lastScanContext = next;
      },
      refreshLens,
      updateStatusBar,
      recordTelemetry,
      telemetry,
      maybeShowPerformanceHint,
    });
    try {
      await activeScan.value;
    } finally {
      activeScan.value = null;
    }
  };

  const scheduleAutomaticScan = (scanContext: ScanContext, reason: ScanReason): void => {
    const config = vscode.workspace.getConfiguration("aishield");
    const debounceMs = clampNumber(config.get<number>("scanDebounceMs", 350), 0, 5000);
    if (autoScanTimer) {
      clearTimeout(autoScanTimer);
      autoScanTimer = null;
    }
    if (debounceMs === 0) {
      void runScanWithLock(scanContext, reason);
      return;
    }
    updateStatusBar(`Queued ${reason} scan`, true);
    autoScanTimer = setTimeout(() => {
      autoScanTimer = null;
      void runScanWithLock(scanContext, reason);
    }, debounceMs);
  };

  context.subscriptions.push(
    new vscode.Disposable(() => {
      if (autoScanTimer) {
        clearTimeout(autoScanTimer);
        autoScanTimer = null;
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aishield.scanWorkspace", async () => {
      const workspace = vscode.workspace.workspaceFolders?.[0];
      if (!workspace) {
        vscode.window.showWarningMessage("AIShield: open a workspace folder first.");
        return;
      }
      await runScanWithLock({
        targetPath: workspace.uri.fsPath,
        workspaceRoot: workspace.uri.fsPath,
      }, "workspace");
    }),
    vscode.commands.registerCommand("aishield.scanCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.uri.scheme !== "file") {
        vscode.window.showWarningMessage("AIShield: no active file to scan.");
        return;
      }
      const workspace = vscode.workspace.getWorkspaceFolder(editor.document.uri);
      await runScanWithLock({
        targetPath: editor.document.uri.fsPath,
        workspaceRoot: workspace?.uri.fsPath ?? path.dirname(editor.document.uri.fsPath),
      }, "current-file");
    }),
    vscode.commands.registerCommand("aishield.clearDiagnostics", () => {
      diagnostics.clear();
      findings.clear();
      lastScanByFile.clear();
      refreshLens();
      updateStatusBar("Diagnostics cleared");
      vscode.window.showInformationMessage("AIShield diagnostics cleared.");
    }),
    vscode.commands.registerCommand("aishield.refreshFindings", async () => {
      if (!lastScanContext) {
        vscode.window.showInformationMessage("AIShield: no previous scan context to refresh.");
        return;
      }
      await runScanWithLock(lastScanContext, "refresh");
    }),
    vscode.commands.registerCommand("aishield.openFinding", async (entry: FindingEntry) => {
      if (!entry) {
        return;
      }
      const doc = await vscode.workspace.openTextDocument(entry.uri);
      const editor = await vscode.window.showTextDocument(doc, { preview: false });
      editor.selection = new vscode.Selection(entry.range.start, entry.range.end);
      editor.revealRange(entry.range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
    }),
    vscode.commands.registerCommand("aishield.applyFixForFinding", async (entry: FindingEntry) => {
      if (!entry) {
        return;
      }
      const invocation = parseCliCommand(
        vscode.workspace.getConfiguration("aishield").get<string>(
          "cliCommand",
          "cargo run -p aishield-cli --",
        ),
      );
      const location = `${entry.uri.fsPath}:${entry.finding.line || 1}:${entry.finding.column || 1}`;
      const args = [...invocation.args, "fix", location, "--write"];
      output.appendLine(`[AIShield] Running: ${invocation.command} ${args.join(" ")}`);
      const workspace = vscode.workspace.getWorkspaceFolder(entry.uri);
      const result = await execCommand(
        invocation.command,
        args,
        workspace?.uri.fsPath ?? path.dirname(entry.uri.fsPath),
      );
      if (result.code !== 0) {
        output.appendLine(`[AIShield] fix stderr:\n${result.stderr}`);
        vscode.window.showErrorMessage(
          `AIShield fix failed for ${entry.finding.id}. See AIShield output channel.`,
        );
        return;
      }

      const doc = await vscode.workspace.openTextDocument(entry.uri);
      await doc.save();
      recordTelemetry("fix.applied", (state) => {
        state.fixesApplied += 1;
      });
      vscode.window.showInformationMessage(`AIShield fix applied for ${entry.finding.id}.`);
      await runScanWithLock({
        targetPath: entry.uri.fsPath,
        workspaceRoot: workspace?.uri.fsPath ?? path.dirname(entry.uri.fsPath),
      }, "fix-follow-up");
    }),
    vscode.commands.registerCommand("aishield.showTelemetrySummary", () => {
      const config = vscode.workspace.getConfiguration("aishield");
      if (!config.get<boolean>("telemetryEnabled", false)) {
        vscode.window.showInformationMessage(
          "AIShield telemetry is disabled. Enable `aishield.telemetryEnabled` to collect local metrics.",
        );
        return;
      }
      const summary = telemetrySummaryText(telemetry);
      output.appendLine("[AIShield] Telemetry summary");
      output.appendLine(summary);
      output.show(true);
      void vscode.window.showInformationMessage(
        `AIShield telemetry: ${telemetry.scansCompleted} completed scans, p95 ${(percentileNumbers(telemetry.scanDurationsMs, 0.95) / 1000).toFixed(2)}s`,
      );
    }),
    vscode.commands.registerCommand("aishield.resetTelemetry", async () => {
      const reset = createEmptyTelemetryState();
      Object.assign(telemetry, reset);
      await context.globalState.update(TELEMETRY_KEY, telemetry);
      updateStatusBar("Telemetry reset");
      vscode.window.showInformationMessage("AIShield telemetry summary reset.");
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(async (event) => {
      const config = vscode.workspace.getConfiguration("aishield");
      if (!config.get<boolean>("aiPasteDetection", true)) {
        return;
      }
      if (event.document.uri.scheme !== "file" || event.contentChanges.length === 0) {
        return;
      }

      const minLines = Math.max(3, config.get<number>("aiPasteMinLines", 8));
      const threshold = Math.max(1, config.get<number>("aiPasteHeuristicThreshold", 2));
      const scanOnAIPaste = config.get<boolean>("scanOnAIPaste", false);
      const workspace = vscode.workspace.getWorkspaceFolder(event.document.uri);
      const workspaceRoot = workspace?.uri.fsPath ?? path.dirname(event.document.uri.fsPath);

      for (const change of event.contentChanges) {
        const text = change.text ?? "";
        if (!text.trim()) {
          continue;
        }

        const lineCount = countLines(text);
        if (lineCount < minLines) {
          continue;
        }

        const score = aiPasteSignalScore(text);
        if (score < threshold) {
          continue;
        }

        const key = `${event.document.uri.fsPath}:${event.document.version}:${shortHash(text)}`;
        if (aiPasteSeen.has(key)) {
          continue;
        }
        aiPasteSeen.add(key);
        recordTelemetry("ai-paste.detected", (state) => {
          state.aiPasteSignals += 1;
        });

        const message = `AIShield: potential AI-assisted paste detected (${lineCount} lines, score ${score}).`;
        if (scanOnAIPaste) {
          void vscode.window.showInformationMessage(`${message} Running scan...`);
          scheduleAutomaticScan({
            targetPath: event.document.uri.fsPath,
            workspaceRoot,
          }, "ai-paste");
          continue;
        }

        const action = await vscode.window.showWarningMessage(message, "Scan File", "Ignore");
        if (action === "Scan File") {
          scheduleAutomaticScan({
            targetPath: event.document.uri.fsPath,
            workspaceRoot,
          }, "ai-paste");
        }
      }
    }),
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      const config = vscode.workspace.getConfiguration("aishield");
      if (!config.get<boolean>("scanOnSave", false) || document.uri.scheme !== "file") {
        return;
      }
      const workspace = vscode.workspace.getWorkspaceFolder(document.uri);
      scheduleAutomaticScan({
        targetPath: document.uri.fsPath,
        workspaceRoot: workspace?.uri.fsPath ?? path.dirname(document.uri.fsPath),
      }, "save");
    }),
  );
}

export function deactivate(): void {}

async function runScan(
  scanContext: ScanContext,
  reason: ScanReason,
  state: {
    diagnostics: vscode.DiagnosticCollection;
    output: vscode.OutputChannel;
    findings: FindingsProvider;
    lastScanByFile: Map<string, FindingEntry[]>;
    setLastContext: (context: ScanContext) => void;
    refreshLens: () => void;
    updateStatusBar: (summary: string, spinner?: boolean) => void;
    recordTelemetry: (reason: string, updater: (state: TelemetryState) => void) => void;
    telemetry: TelemetryState;
    maybeShowPerformanceHint: () => void;
  },
): Promise<void> {
  const config = vscode.workspace.getConfiguration("aishield");
  const baseInvocation = parseCliCommand(
    config.get<string>("cliCommand", "cargo run -p aishield-cli --"),
  );
  const minSeverity = config.get<string>("minSeverity", "low");
  const extraScanArgs = config.get<string[]>("extraScanArgs", []);
  const useOnnx = config.get<boolean>("useOnnx", false);
  const onnxModelPath = config.get<string>("onnxModelPath", "").trim();
  const onnxManifestPath = config.get<string>("onnxManifestPath", "").trim();
  const aiCalibration = config.get<string>("aiCalibration", "balanced");
  const maxDiagnostics = clampNumber(config.get<number>("maxDiagnostics", 600), 50, 5000);

  const args = [
    ...baseInvocation.args,
    "scan",
    scanContext.targetPath,
    "--format",
    "json",
    "--dedup",
    "normalized",
    "--severity",
    minSeverity,
    ...extraScanArgs,
  ];
  if (useOnnx) {
    args.push("--ai-model", "onnx");
    if (onnxManifestPath.length > 0) {
      args.push("--onnx-manifest", onnxManifestPath);
    } else if (onnxModelPath.length > 0) {
      args.push("--onnx-model", onnxModelPath);
    }
    if (["conservative", "balanced", "aggressive"].includes(aiCalibration)) {
      args.push("--ai-calibration", aiCalibration);
    }
  }

  state.output.appendLine(`[AIShield] Running (${reason}): ${baseInvocation.command} ${args.join(" ")}`);
  const started = Date.now();
  const result = await execCommand(baseInvocation.command, args, scanContext.workspaceRoot);
  const elapsedMs = Date.now() - started;

  if (result.code !== 0 && result.code !== 2) {
    state.output.appendLine(`[AIShield] stderr:\n${result.stderr}`);
    state.recordTelemetry("scan.failed", (telemetry) => {
      telemetry.scansFailed += 1;
    });
    state.updateStatusBar(`Scan failed (${reason})`);
    vscode.window.showErrorMessage(
      `AIShield scan failed (exit ${result.code ?? "unknown"}). See AIShield output channel.`,
    );
    return;
  }

  const parsed = tryParseScanJson(result.stdout);
  if (!parsed) {
    state.output.appendLine("[AIShield] Unable to parse JSON output.");
    state.output.appendLine(`[AIShield] stdout:\n${result.stdout}`);
    if (result.stderr.trim().length > 0) {
      state.output.appendLine(`[AIShield] stderr:\n${result.stderr}`);
    }
    state.recordTelemetry("scan.parse-failed", (telemetry) => {
      telemetry.scansFailed += 1;
    });
    state.updateStatusBar("Scan parse error");
    vscode.window.showErrorMessage("AIShield returned non-JSON output.");
    return;
  }

  const entries = publishDiagnostics(
    parsed.findings ?? [],
    scanContext.targetPath,
    scanContext.workspaceRoot,
    state.diagnostics,
    maxDiagnostics,
  );
  state.lastScanByFile.clear();
  for (const [file, fileEntries] of entries.byFile.entries()) {
    state.lastScanByFile.set(file, fileEntries);
  }
  state.findings.setItems(entries.all);
  state.setLastContext(scanContext);
  state.refreshLens();

  const total = parsed.summary?.total ?? entries.all.length;
  const severityBreakdown = summarizeSeverities(entries.all);
  state.updateStatusBar(`${total} finding(s) · ${(elapsedMs / 1000).toFixed(2)}s`);
  state.recordTelemetry("scan.completed", (telemetry) => {
    telemetry.scansCompleted += 1;
    telemetry.findingsPublished += entries.all.length;
    telemetry.diagnosticsDropped += entries.dropped;
    telemetry.scanDurationsMs.push(elapsedMs);
    if (telemetry.scanDurationsMs.length > MAX_SCAN_DURATION_SAMPLES) {
      telemetry.scanDurationsMs.splice(0, telemetry.scanDurationsMs.length - MAX_SCAN_DURATION_SAMPLES);
    }
  });
  state.maybeShowPerformanceHint();

  if (entries.dropped > 0) {
    state.output.appendLine(
      `[AIShield] Diagnostics truncated: dropped ${entries.dropped} finding(s) over maxDiagnostics=${maxDiagnostics}.`,
    );
  }

  vscode.window.showInformationMessage(
    `AIShield: ${total} finding(s) in ${(elapsedMs / 1000).toFixed(2)}s (${severityBreakdown}).`,
  );
}

function publishDiagnostics(
  findings: AiShieldFinding[],
  targetPath: string,
  workspaceRoot: string,
  collection: vscode.DiagnosticCollection,
  maxDiagnostics: number,
): { all: FindingEntry[]; byFile: Map<string, FindingEntry[]>; dropped: number } {
  const byFile = new Map<string, vscode.Diagnostic[]>();
  const findingByFile = new Map<string, FindingEntry[]>();
  const all: FindingEntry[] = [];
  const sortedFindings = [...findings].sort((a, b) => {
    const sevCmp = severityRank(b.severity) - severityRank(a.severity);
    if (sevCmp !== 0) {
      return sevCmp;
    }
    return (b.risk_score ?? 0) - (a.risk_score ?? 0);
  });
  const limitedFindings = sortedFindings.slice(0, maxDiagnostics);
  const dropped = Math.max(0, sortedFindings.length - limitedFindings.length);

  for (const finding of limitedFindings) {
    const filePath = resolveFindingPath(finding.file, targetPath, workspaceRoot);
    const uri = vscode.Uri.file(filePath);
    const line = Math.max(0, (finding.line || 1) - 1);
    const column = Math.max(0, (finding.column || 1) - 1);
    const range = new vscode.Range(line, column, line, column + 1);
    const severity = mapSeverity(finding.severity);

    const message = [
      `[${finding.id}] ${finding.title}`,
      `AI confidence: ${(finding.ai_confidence ?? 0).toFixed(1)} | Risk: ${(finding.risk_score ?? 0).toFixed(1)}`,
      finding.snippet,
      finding.fix_suggestion ? `Fix: ${finding.fix_suggestion}` : "",
    ]
      .filter((segment) => segment && segment.trim().length > 0)
      .join("\n");

    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.source = "AIShield";
    diagnostic.code = finding.id;

    const fileDiags = byFile.get(filePath) ?? [];
    fileDiags.push(diagnostic);
    byFile.set(filePath, fileDiags);

    const key = `${filePath}::${finding.id}::${line}:${column}`;
    const entry: FindingEntry = { finding, uri, range, key };
    all.push(entry);
    const fileEntries = findingByFile.get(filePath) ?? [];
    fileEntries.push(entry);
    findingByFile.set(filePath, fileEntries);
  }

  collection.clear();
  for (const [filePath, diagnostics] of byFile.entries()) {
    collection.set(vscode.Uri.file(filePath), diagnostics);
  }
  return { all, byFile: findingByFile, dropped };
}

function resolveFindingPath(findingFile: string, targetPath: string, workspaceRoot: string): string {
  if (!findingFile || findingFile.trim().length === 0) {
    return targetPath;
  }
  if (path.isAbsolute(findingFile)) {
    return findingFile;
  }

  if (targetPath && !targetPath.endsWith(path.sep) && path.extname(targetPath).length > 0) {
    const basename = path.basename(targetPath);
    if (findingFile === basename) {
      return path.join(path.dirname(targetPath), findingFile);
    }
  }

  return path.join(workspaceRoot, findingFile);
}

function mapSeverity(raw: string): vscode.DiagnosticSeverity {
  switch ((raw || "").toLowerCase()) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function parseCliCommand(raw: string): CliInvocation {
  const tokens = shellSplit(raw.trim());
  if (tokens.length === 0) {
    return { command: "cargo", args: ["run", "-p", "aishield-cli", "--"] };
  }
  return { command: tokens[0], args: tokens.slice(1) };
}

function shellSplit(input: string): string[] {
  const out: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current.length > 0) {
        out.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }

  if (current.length > 0) {
    out.push(current);
  }
  return out;
}

function execCommand(
  command: string,
  args: string[],
  cwd: string,
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve) => {
    const child = cp.spawn(command, args, { cwd });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });
    child.on("error", (error) => {
      resolve({ stdout, stderr: `${stderr}\n${error.message}`, code: -1 });
    });
    child.on("close", (code) => resolve({ stdout, stderr, code }));
  });
}

function countLines(text: string): number {
  return text.split(/\r?\n/).length;
}

function shortHash(value: string): string {
  let hash = 5381;
  for (let i = 0; i < value.length; i += 1) {
    hash = ((hash << 5) + hash) ^ value.charCodeAt(i);
  }
  return Math.abs(hash >>> 0).toString(36);
}

function aiPasteSignalScore(text: string): number {
  const lower = text.toLowerCase();
  let score = 0;

  if (text.includes("```")) {
    score += 2;
  }
  if (
    containsAny(lower, [
      "here's",
      "here is",
      "sure,",
      "certainly",
      "let me know",
      "generated by",
      "assistant",
      "chatgpt",
      "copilot",
      "claude",
    ])
  ) {
    score += 2;
  }
  if (containsAny(lower, ["todo:", "example usage", "quick fix", "boilerplate"])) {
    score += 1;
  }
  if (containsAny(lower, ["class ", "function ", "def ", "func ", "public class "])) {
    score += 1;
  }
  if (countLines(text) >= 20) {
    score += 1;
  }
  if (text.length >= 1000) {
    score += 1;
  }

  return score;
}

function containsAny(haystack: string, needles: string[]): boolean {
  return needles.some((needle) => haystack.includes(needle));
}

function tryParseScanJson(raw: string): AiShieldScanResult | null {
  try {
    return JSON.parse(raw) as AiShieldScanResult;
  } catch {
    return null;
  }
}

function summarizeSeverities(entries: FindingEntry[]): string {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const entry of entries) {
    const key = (entry.finding.severity || "info").toLowerCase();
    if (key in counts) {
      counts[key as keyof typeof counts] += 1;
    }
  }
  return `C:${counts.critical} H:${counts.high} M:${counts.medium} L:${counts.low} I:${counts.info}`;
}

function severityRank(raw: string): number {
  switch ((raw || "").toLowerCase()) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

function severityLabel(raw: string): string {
  switch ((raw || "").toLowerCase()) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "medium":
      return "MEDIUM";
    case "low":
      return "LOW";
    default:
      return "INFO";
  }
}

function iconForSeverity(raw: string): vscode.ThemeIcon {
  switch ((raw || "").toLowerCase()) {
    case "critical":
    case "high":
      return new vscode.ThemeIcon("error");
    case "medium":
      return new vscode.ThemeIcon("warning");
    default:
      return new vscode.ThemeIcon("info");
  }
}

function escapeMarkdown(value: string): string {
  return value.replace(/[\\`*_{}[\]()#+\-.!]/g, "\\$&");
}

function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  return Math.min(max, Math.max(min, value));
}

function percentileNumbers(samples: number[], percentile: number): number {
  if (samples.length === 0) {
    return 0;
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const p = clampNumber(percentile, 0, 1);
  const index = (sorted.length - 1) * p;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) {
    return sorted[lower];
  }
  const frac = index - lower;
  return sorted[lower] + (sorted[upper] - sorted[lower]) * frac;
}

function createEmptyTelemetryState(): TelemetryState {
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

function loadTelemetryState(context: vscode.ExtensionContext): TelemetryState {
  const raw = context.globalState.get<Partial<TelemetryState>>(TELEMETRY_KEY);
  if (!raw || typeof raw !== "object") {
    return createEmptyTelemetryState();
  }

  return {
    scansStarted: Number(raw.scansStarted ?? 0),
    scansCompleted: Number(raw.scansCompleted ?? 0),
    scansFailed: Number(raw.scansFailed ?? 0),
    fixesApplied: Number(raw.fixesApplied ?? 0),
    aiPasteSignals: Number(raw.aiPasteSignals ?? 0),
    findingsPublished: Number(raw.findingsPublished ?? 0),
    diagnosticsDropped: Number(raw.diagnosticsDropped ?? 0),
    eventsSampled: Number(raw.eventsSampled ?? 0),
    scanDurationsMs: Array.isArray(raw.scanDurationsMs)
      ? raw.scanDurationsMs.filter((value): value is number => Number.isFinite(value)).slice(-MAX_SCAN_DURATION_SAMPLES)
      : [],
    lastUpdated: typeof raw.lastUpdated === "string" ? raw.lastUpdated : new Date().toISOString(),
    performanceHintShownCount: Number(raw.performanceHintShownCount ?? 0),
  };
}

function telemetrySummaryText(state: TelemetryState): string {
  const p50 = percentileNumbers(state.scanDurationsMs, 0.5);
  const p95 = percentileNumbers(state.scanDurationsMs, 0.95);
  return [
    `scans_started=${state.scansStarted}`,
    `scans_completed=${state.scansCompleted}`,
    `scans_failed=${state.scansFailed}`,
    `fixes_applied=${state.fixesApplied}`,
    `ai_paste_signals=${state.aiPasteSignals}`,
    `findings_published=${state.findingsPublished}`,
    `diagnostics_dropped=${state.diagnosticsDropped}`,
    `events_sampled=${state.eventsSampled}`,
    `scan_latency_p50_ms=${p50.toFixed(1)}`,
    `scan_latency_p95_ms=${p95.toFixed(1)}`,
    `last_updated=${state.lastUpdated}`,
  ].join("\n");
}
