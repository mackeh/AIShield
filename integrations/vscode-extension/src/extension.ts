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
};

type AiShieldScanResult = {
  summary?: { total?: number };
  findings?: AiShieldFinding[];
};

type CliInvocation = {
  command: string;
  args: string[];
};

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("aishield");
  const output = vscode.window.createOutputChannel("AIShield");

  context.subscriptions.push(diagnostics, output);

  context.subscriptions.push(
    vscode.commands.registerCommand("aishield.scanWorkspace", async () => {
      const workspace = vscode.workspace.workspaceFolders?.[0];
      if (!workspace) {
        vscode.window.showWarningMessage("AIShield: open a workspace folder first.");
        return;
      }

      await runScan({
        targetPath: workspace.uri.fsPath,
        workspaceRoot: workspace.uri.fsPath,
        diagnostics,
        output,
      });
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aishield.scanCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("AIShield: no active file to scan.");
        return;
      }

      const workspace = vscode.workspace.getWorkspaceFolder(editor.document.uri);
      const workspaceRoot = workspace?.uri.fsPath ?? path.dirname(editor.document.uri.fsPath);
      await runScan({
        targetPath: editor.document.uri.fsPath,
        workspaceRoot,
        diagnostics,
        output,
      });
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aishield.clearDiagnostics", () => {
      diagnostics.clear();
      vscode.window.showInformationMessage("AIShield diagnostics cleared.");
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      const config = vscode.workspace.getConfiguration("aishield");
      if (!config.get<boolean>("scanOnSave", false)) {
        return;
      }
      if (document.uri.scheme !== "file") {
        return;
      }

      const workspace = vscode.workspace.getWorkspaceFolder(document.uri);
      const workspaceRoot = workspace?.uri.fsPath ?? path.dirname(document.uri.fsPath);
      await runScan({
        targetPath: document.uri.fsPath,
        workspaceRoot,
        diagnostics,
        output,
      });
    }),
  );
}

export function deactivate(): void {}

async function runScan(params: {
  targetPath: string;
  workspaceRoot: string;
  diagnostics: vscode.DiagnosticCollection;
  output: vscode.OutputChannel;
}): Promise<void> {
  const config = vscode.workspace.getConfiguration("aishield");
  const baseInvocation = parseCliCommand(
    config.get<string>("cliCommand", "cargo run -p aishield-cli --"),
  );

  const minSeverity = config.get<string>("minSeverity", "low");
  const extraScanArgs = config.get<string[]>("extraScanArgs", []);
  const useOnnx = config.get<boolean>("useOnnx", false);
  const onnxModelPath = config.get<string>("onnxModelPath", "").trim();

  const args = [
    ...baseInvocation.args,
    "scan",
    params.targetPath,
    "--format",
    "json",
    "--dedup",
    "normalized",
    "--severity",
    minSeverity,
    ...extraScanArgs,
  ];

  if (useOnnx && onnxModelPath.length > 0) {
    args.push("--ai-model", "onnx", "--onnx-model", onnxModelPath);
  }

  const commandLabel = `${baseInvocation.command} ${args.join(" ")}`;
  params.output.appendLine(`[AIShield] Running: ${commandLabel}`);

  const started = Date.now();
  const result = await execCommand(baseInvocation.command, args);
  const elapsedMs = Date.now() - started;

  if (result.code !== 0 && result.code !== 2) {
    params.output.appendLine(`[AIShield] stderr:\n${result.stderr}`);
    vscode.window.showErrorMessage(
      `AIShield scan failed (exit ${result.code ?? "unknown"}). See AIShield output channel.`,
    );
    return;
  }

  const parsed = tryParseScanJson(result.stdout);
  if (!parsed) {
    params.output.appendLine("[AIShield] Unable to parse JSON output.");
    params.output.appendLine(`[AIShield] stdout:\n${result.stdout}`);
    if (result.stderr.trim().length > 0) {
      params.output.appendLine(`[AIShield] stderr:\n${result.stderr}`);
    }
    vscode.window.showErrorMessage("AIShield returned non-JSON output.");
    return;
  }

  publishDiagnostics(parsed.findings ?? [], params.targetPath, params.workspaceRoot, params.diagnostics);
  const total = parsed.summary?.total ?? (parsed.findings?.length ?? 0);
  vscode.window.showInformationMessage(
    `AIShield: ${total} finding(s) in ${(elapsedMs / 1000).toFixed(2)}s.`,
  );
}

function publishDiagnostics(
  findings: AiShieldFinding[],
  targetPath: string,
  workspaceRoot: string,
  collection: vscode.DiagnosticCollection,
): void {
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const finding of findings) {
    const filePath = resolveFindingPath(finding.file, targetPath, workspaceRoot);
    const line = Math.max(0, (finding.line || 1) - 1);
    const column = Math.max(0, (finding.column || 1) - 1);
    const range = new vscode.Range(line, column, line, column + 1);
    const severity = mapSeverity(finding.severity);
    const aiConfidence = finding.ai_confidence ?? 0.0;
    const riskScore = finding.risk_score ?? 0.0;
    const message = `[${finding.id}] ${finding.title}\nAI confidence: ${aiConfidence.toFixed(1)} | Risk: ${riskScore.toFixed(1)}\n${finding.snippet}`;

    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.source = "AIShield";
    diagnostic.code = finding.id;

    const existing = byFile.get(filePath) ?? [];
    existing.push(diagnostic);
    byFile.set(filePath, existing);
  }

  collection.clear();
  for (const [filePath, diagnostics] of byFile.entries()) {
    collection.set(vscode.Uri.file(filePath), diagnostics);
  }
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
  return {
    command: tokens[0],
    args: tokens.slice(1),
  };
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
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve) => {
    const child = cp.spawn(command, args, { cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });
    child.on("error", (error) => {
      resolve({
        stdout,
        stderr: `${stderr}\n${error.message}`,
        code: -1,
      });
    });
    child.on("close", (code) => resolve({ stdout, stderr, code }));
  });
}

function tryParseScanJson(raw: string): AiShieldScanResult | null {
  try {
    return JSON.parse(raw) as AiShieldScanResult;
  } catch (_error) {
    return null;
  }
}
