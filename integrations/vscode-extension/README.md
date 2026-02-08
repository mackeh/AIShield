# AIShield VS Code Extension (Bootstrap)

This extension provides a local-first AIShield integration for VS Code:

- workspace and current-file scan commands
- Diagnostics panel publishing from AIShield JSON output
- optional scan-on-save mode
- optional ONNX scorer flags passthrough

## Commands

- `AIShield: Scan Workspace`
- `AIShield: Scan Current File`
- `AIShield: Clear Diagnostics`

## Settings

- `aishield.cliCommand` (default: `cargo run -p aishield-cli --`)
- `aishield.extraScanArgs` (array of extra CLI args)
- `aishield.minSeverity` (`critical|high|medium|low|info`)
- `aishield.useOnnx` (boolean)
- `aishield.onnxModelPath` (string path)
- `aishield.scanOnSave` (boolean)

## Development

```bash
cd integrations/vscode-extension
npm install
npm run build
```

Then open this folder in VS Code and run the extension host (`F5`).
