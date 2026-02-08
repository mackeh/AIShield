# Getting Started

AIShield is a Rust-first security scanner for AI-assisted codebases. It combines curated rulepacks, AI-likelihood heuristics, risk scoring, and CI-friendly output formats.

Supported scan targets now include application code plus infrastructure config patterns (Terraform/HCL, Kubernetes manifests, and Dockerfiles).

## Prerequisites

- Rust toolchain (`stable` recommended)
- Git
- Optional bridge tools for richer findings:
  - Python + `bandit`
  - Semgrep
  - Node.js + `eslint`

## Quick Scan

```bash
cargo run -p aishield-cli -- scan .
```

## Bootstrap Project Integrations

```bash
# config only
cargo run -p aishield-cli -- init

# config + GitHub/GitLab/Bitbucket/CircleCI/Jenkins + VS Code + pre-commit
cargo run -p aishield-cli -- init --templates all
```

## CI-Friendly Scan

```bash
cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif
```

## PR Annotation Mode

```bash
cargo run -p aishield-cli -- scan . --format github --changed-from origin/main
```

## ONNX Classifier Mode (Optional)

```bash
python3 -m pip install --upgrade onnxruntime numpy
cargo run -p aishield-cli --features onnx -- \
  scan . \
  --ai-model onnx \
  --onnx-model models/ai-classifier/model.onnx

# or use manifest-driven model + calibration
cargo run -p aishield-cli --features onnx -- \
  scan . \
  --ai-model onnx \
  --onnx-manifest models/ai-classifier/model-manifest.json
```

## Interactive Fix Mode

```bash
cargo run -p aishield-cli -- fix . --interactive
```

Inside the TUI:

- `/` enters search/filter mode
- `space` toggles selected fix
- `enter` applies selected fix(es)
- right pane previews line-level before/after diffs

## Local Docs Development

```bash
npm install
npm run docs:dev
```

Build docs for production:

```bash
npm run docs:build
```

## Dashboard Bootstrap

```bash
npm run dashboard:dev
```

Seed demo history if needed:

```bash
npm run dashboard:sample-history
```

## Next Steps

- Contributor onboarding: `CONTRIBUTING.md` and `/contributing`
- Ecosystem setup guides: `/integrations`
- VS Code extension bootstrap: `/vscode-extension`
