# VS Code Extension

AIShield includes a TypeScript extension scaffold at:

- `integrations/vscode-extension`

It provides:

- `AIShield: Scan Workspace`
- `AIShield: Scan Current File`
- `AIShield: Clear Diagnostics`
- `AIShield: Refresh Findings`
- Diagnostics integration in VS Code Problems panel
- Hover detail cards with severity, risk, confidence, and snippet context
- Quick-fix code actions that invoke `aishield fix <file:line:col> --write`
- Explorer panel: **AIShield Findings**
- Beta AI Security Lens line highlighting for medium/high/critical findings
- AI paste-detection heuristics with scan prompt/auto-scan options
- Optional scan-on-save behavior

## Run Extension Locally

```bash
cd integrations/vscode-extension
npm install
npm run build
```

Then open `integrations/vscode-extension` in VS Code and launch extension host with `F5`.

## Extension Settings

- `aishield.cliCommand` (default `cargo run -p aishield-cli --`)
- `aishield.extraScanArgs` (extra CLI args)
- `aishield.minSeverity` (`critical|high|medium|low|info`)
- `aishield.useOnnx`
- `aishield.onnxModelPath`
- `aishield.scanOnSave`
- `aishield.aiPasteDetection`
- `aishield.aiPasteMinLines`
- `aishield.aiPasteHeuristicThreshold`
- `aishield.scanOnAIPaste`
- `aishield.securityLens`

## Notes

- The extension shells out to `aishield-cli` and parses JSON output.
- Diagnostics severity is mapped from AIShield severities:
  - `critical/high` -> VS Code Error
  - `medium` -> VS Code Warning
  - `low/info` -> VS Code Information
