# VS Code Extension

AIShield includes a TypeScript extension scaffold at:

- `integrations/vscode-extension`

It provides:

- `AIShield: Scan Workspace`
- `AIShield: Scan Current File`
- `AIShield: Clear Diagnostics`
- Diagnostics integration in VS Code Problems panel
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

## Notes

- The extension currently shells out to `aishield-cli` and parses JSON output.
- Diagnostics severity is mapped from AIShield severities:
  - `critical/high` -> VS Code Error
  - `medium` -> VS Code Warning
  - `low/info` -> VS Code Information
