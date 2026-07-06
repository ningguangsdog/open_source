"""Lightweight local model metadata extraction."""

from __future__ import annotations

import math
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


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def _find_magic_offsets(data: bytes, magic: bytes, limit: int = 20) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        index = data.find(magic, start)
        if index < 0:
            break
        offsets.append(index)
        start = index + 1
    return offsets


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
    tflite_offsets = _find_magic_offsets(data[:5_000_000], b"TFL3")
    entropy_sample = data[: min(len(data), 1_000_000)]

    return {
        "format": model_format,
        "tflite_magic_present": b"TFL3" in data[:128],
        "tflite_magic_offsets": tflite_offsets,
        "embedded_tflite_magic_present": bool(tflite_offsets),
        "header_hex": data[:32].hex(),
        "entropy_first_mb": _entropy(entropy_sample),
        "likely_wrapped_or_encrypted": model_format == "tflite" and not (b"TFL3" in data[:128]),
        "string_count_sampled": len(strings),
        "operator_hints": operator_hints,
        "capabilities": capability_hits,
        "strings_sample": strings[:120],
    }
