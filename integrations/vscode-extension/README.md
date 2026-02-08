# AIShield VS Code Extension (Bootstrap)

This extension provides a local-first AIShield integration for VS Code:

- workspace and current-file scan commands
- Diagnostics panel publishing from AIShield JSON output
- optional scan-on-save mode
- optional ONNX scorer flags passthrough (model path or manifest)
- status bar scan summaries
- local telemetry summary + performance tuning hints

## Commands

- `AIShield: Scan Workspace`
- `AIShield: Scan Current File`
- `AIShield: Clear Diagnostics`
- `AIShield: Refresh Findings`
- `AIShield: Show Telemetry Summary`
- `AIShield: Reset Telemetry Summary`

## Settings

- `aishield.cliCommand` (default: `cargo run -p aishield-cli --`)
- `aishield.extraScanArgs` (array of extra CLI args)
- `aishield.minSeverity` (`critical|high|medium|low|info`)
- `aishield.useOnnx` (boolean)
- `aishield.onnxModelPath` (string path)
- `aishield.onnxManifestPath` (string path)
- `aishield.aiCalibration` (`conservative|balanced|aggressive`)
- `aishield.scanOnSave` (boolean)
- `aishield.scanDebounceMs` (number)
- `aishield.maxDiagnostics` (number)
- `aishield.statusBarEnabled` (boolean)
- `aishield.telemetryEnabled` (boolean, local-only counters)
- `aishield.telemetrySampleRate` (0..1)
- `aishield.performanceHints` (boolean)

## Development

```bash
cd integrations/vscode-extension
npm install
npm run build
```

Then open this folder in VS Code and run the extension host (`F5`).
