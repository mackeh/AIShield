# AI Classifier (Heuristic + ONNX)

AIShield supports two AI-likelihood scorer modes:

- `heuristic` (default): no external runtime required.
- `onnx`: uses an ONNX model with a Python runner bridge.

## CLI Usage

```bash
# default heuristic mode
cargo run -p aishield-cli -- scan .

# ONNX mode (requires feature + model + runtime deps)
cargo run -p aishield-cli --features onnx -- \
  scan . \
  --ai-model onnx \
  --onnx-model models/ai-classifier/model.onnx \
  --ai-calibration balanced

# ONNX mode with manifest-driven model distribution metadata
cargo run -p aishield-cli --features onnx -- \
  scan . \
  --ai-model onnx \
  --onnx-manifest models/ai-classifier/model-manifest.json
```

## Config Usage

```yaml
ai_model: heuristic
onnx_model_path: ""
onnx_manifest_path: ""
ai_calibration: balanced
```

Set ONNX mode in config:

```yaml
ai_model: onnx
onnx_model_path: models/ai-classifier/model.onnx
onnx_manifest_path: models/ai-classifier/model-manifest.json
ai_calibration: balanced
```

Calibration profiles:

- `conservative`
- `balanced` (default)
- `aggressive`

## Runtime Dependencies

For ONNX mode:

```bash
python3 -m pip install --upgrade onnxruntime numpy
```

Runner script location:

- `models/ai-classifier/onnx_runner.py`
- `models/ai-classifier/model-manifest.json`
- `models/ai-classifier/calibration-notes.md`

Core fallback behavior:

- If ONNX feature is disabled, AIShield falls back to heuristic.
- If ONNX model path is missing (from `--onnx-model` or manifest) or file path does not exist, AIShield falls back to heuristic.
- If the ONNX runner/runtime execution fails, scoring falls back to heuristic per finding.
