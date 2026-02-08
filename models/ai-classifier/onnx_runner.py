#!/usr/bin/env python3
"""
AIShield ONNX model runner.

Input:
  --model <path/to/model.onnx>
  --features "0.1,0.2,0.3,..."

Output:
  Writes a single float probability in range [0.0, 1.0] to stdout.
"""

import argparse
import math
import sys
from typing import List


def _parse_features(raw: str) -> List[float]:
    values = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        values.append(float(token))
    if not values:
        raise ValueError("no features provided")
    return values


def _target_width(shape, fallback: int) -> int:
    if not shape:
        return fallback
    width = shape[-1]
    if isinstance(width, int) and width > 0:
        return width
    return fallback


def _fit_features(values: List[float], width: int) -> List[float]:
    if len(values) == width:
        return values
    if len(values) > width:
        return values[:width]
    return values + [0.0] * (width - len(values))


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


def _softmax(values):
    peak = max(values)
    exps = [math.exp(v - peak) for v in values]
    total = sum(exps)
    if total == 0:
        return [0.0 for _ in values]
    return [v / total for v in exps]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AIShield ONNX inference")
    parser.add_argument("--model", required=True, help="Path to ONNX model file")
    parser.add_argument("--features", required=True, help="Comma-separated feature vector")
    args = parser.parse_args()

    try:
        import numpy as np  # type: ignore
        import onnxruntime as ort  # type: ignore
    except Exception as exc:
        print(f"onnx_runner dependency error: {exc}", file=sys.stderr)
        return 2

    try:
        features = _parse_features(args.features)
        session = ort.InferenceSession(
            args.model, providers=["CPUExecutionProvider"]
        )
        model_input = session.get_inputs()[0]
        width = _target_width(model_input.shape, len(features))
        vector = np.array([_fit_features(features, width)], dtype=np.float32)
        outputs = session.run(None, {model_input.name: vector})
        if not outputs:
            print("no outputs produced by ONNX model", file=sys.stderr)
            return 3

        flat = np.asarray(outputs[0], dtype=np.float32).reshape(-1)
        if flat.size == 0:
            print("empty output tensor", file=sys.stderr)
            return 4

        if flat.size == 1:
            raw_score = float(flat[0])
            probability = raw_score if 0.0 <= raw_score <= 1.0 else _sigmoid(raw_score)
        else:
            probs = _softmax([float(v) for v in flat])
            probability = probs[1] if len(probs) > 1 else probs[0]

        probability = max(0.0, min(1.0, float(probability)))
        print(f"{probability:.6f}")
        return 0
    except Exception as exc:
        print(f"onnx_runner execution error: {exc}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
