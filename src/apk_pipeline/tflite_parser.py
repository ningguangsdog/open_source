"""Lightweight local model metadata extraction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .capability_taxonomy import classify_text
from .utils import printable_strings_from_bytes


MODEL_EXTENSIONS = {
    ".tflite": "tflite",
    ".lite": "tflite",
    ".onnx": "onnx",
    ".pb": "tensorflow_graph",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".mlmodel": "coreml",
}

OPERATOR_HINTS = (
    "conv",
    "depthwise",
    "pool",
    "relu",
    "softmax",
    "reshape",
    "resize",
    "quant",
    "dequant",
    "lstm",
    "gru",
    "embedding",
    "detect",
    "segment",
    "ocr",
    "recogn",
    "yamnet",
    "mobilenet",
    "efficientnet",
    "bert",
    "transformer",
)


def infer_model_format(path: str) -> str:
    return MODEL_EXTENSIONS.get(Path(path).suffix.lower(), "unknown_model")


def parse_model_metadata(path: str, data: bytes) -> dict[str, Any]:
    """Extract conservative model facts from a model file prefix/full payload."""

    model_format = infer_model_format(path)
    strings = printable_strings_from_bytes(data, min_length=4, limit=800)
    lowered_strings = [item.lower() for item in strings]
    operator_hints = sorted(
        {
            hint
            for hint in OPERATOR_HINTS
            if any(hint in item for item in lowered_strings)
        }
    )
    capability_hits = classify_text(" ".join(strings[:300]))

    return {
        "format": model_format,
        "tflite_magic_present": b"TFL3" in data[:128],
        "string_count_sampled": len(strings),
        "operator_hints": operator_hints,
        "capabilities": capability_hits,
        "strings_sample": strings[:120],
    }
