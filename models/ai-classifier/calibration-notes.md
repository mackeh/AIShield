# AI Classifier Calibration Notes

The ONNX classifier blends model probability with AIShield heuristic scoring.

## Profiles

- `conservative`: lower ONNX influence, tighter probability range
- `balanced`: default blend for mixed workloads
- `aggressive`: higher ONNX influence for AI-heavy repositories

## Tuning Workflow

1. Collect labeled snippets from internal scan feedback.
2. Evaluate model outputs and false-positive/false-negative tradeoffs.
3. Tune `calibration` fields in `model-manifest.json`.
4. Validate against fixture suites and production-like samples.
5. Ship updated manifest/model in release artifacts.
