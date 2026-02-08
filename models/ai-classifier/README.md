# AIShield ONNX Classifier Assets

This directory stores ONNX-related classifier assets for AI-likelihood scoring.

## Included

- `onnx_runner.py`: lightweight runner used by `aishield-core` in `--ai-model onnx` mode.
- `model-manifest.json`: distribution metadata + calibration settings.
- `calibration-notes.md`: profile and tuning notes.

## Runtime Requirements

- Python 3.9+
- `onnxruntime`
- `numpy`

Install dependencies:

```bash
python3 -m pip install --upgrade onnxruntime numpy
```

## Usage from CLI

Build with ONNX feature enabled:

```bash
cargo run -p aishield-cli --features onnx -- scan . --ai-model onnx --onnx-model models/ai-classifier/model.onnx
```

Manifest-driven usage:

```bash
cargo run -p aishield-cli --features onnx -- \
  scan . \
  --ai-model onnx \
  --onnx-manifest models/ai-classifier/model-manifest.json
```

The core scorer calls `onnx_runner.py` with engineered features and blends ONNX probability with baseline heuristic score using calibration profile/settings.
