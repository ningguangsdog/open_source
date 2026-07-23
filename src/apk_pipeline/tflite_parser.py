"""Lightweight local model metadata extraction."""

from __future__ import annotations

import math
import hashlib
import json
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
    ".task": "tflite_task_bundle",
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


def _decode_name(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _tensor_record(tensor: Any, index: int) -> dict[str, Any]:
    try:
        shape = [int(tensor.Shape(i)) for i in range(tensor.ShapeLength())]
    except Exception:
        shape = []
    return {
        "index": index,
        "name": _decode_name(tensor.Name()),
        "shape": shape,
        "tensor_type_code": int(tensor.Type()),
        "buffer_index": int(tensor.Buffer()),
    }


def _parse_tflite_graph(data: bytes, *, complete: bool) -> dict[str, Any]:
    if not complete:
        return {
            "status": "skipped_truncated_input",
            "reason": "Structured parsing requires the complete model payload.",
        }
    if len(data) < 8 or data[4:8] != b"TFL3":
        return {
            "status": "not_plain_tflite",
            "reason": "The FlatBuffer TFL3 identifier is not present at offset 4.",
        }
    try:
        import tflite  # type: ignore[import-not-found]
    except ImportError:
        return {
            "status": "parser_unavailable",
            "reason": "Install tflite==2.18.0 for structured graph metadata.",
        }
    try:
        model = tflite.Model.GetRootAsModel(data, 0)
        operator_counts: dict[str, int] = {}
        subgraphs: list[dict[str, Any]] = []
        total_operators = 0
        total_tensors = 0
        for subgraph_index in range(model.SubgraphsLength()):
            subgraph = model.Subgraphs(subgraph_index)
            if subgraph is None:
                continue
            total_operators += int(subgraph.OperatorsLength())
            total_tensors += int(subgraph.TensorsLength())
            for operator_index in range(subgraph.OperatorsLength()):
                operator = subgraph.Operators(operator_index)
                if operator is None:
                    continue
                opcode = model.OperatorCodes(operator.OpcodeIndex())
                code = int(opcode.BuiltinCode()) if opcode is not None else -1
                try:
                    name = str(tflite.opcode2name(code))
                except Exception:
                    name = f"BUILTIN_{code}"
                operator_counts[name] = operator_counts.get(name, 0) + 1

            def tensor_indexes(method_name: str, length_name: str) -> list[int]:
                length = int(getattr(subgraph, length_name)())
                return [int(getattr(subgraph, method_name)(i)) for i in range(length)]

            inputs = tensor_indexes("Inputs", "InputsLength")
            outputs = tensor_indexes("Outputs", "OutputsLength")
            selected_tensor_indexes = list(dict.fromkeys([*inputs, *outputs]))
            tensor_records = []
            for tensor_index in selected_tensor_indexes:
                tensor = subgraph.Tensors(tensor_index)
                if tensor is not None:
                    tensor_records.append(_tensor_record(tensor, tensor_index))
            subgraphs.append(
                {
                    "index": subgraph_index,
                    "name": _decode_name(subgraph.Name()),
                    "tensor_count": int(subgraph.TensorsLength()),
                    "operator_count": int(subgraph.OperatorsLength()),
                    "input_tensor_indexes": inputs,
                    "output_tensor_indexes": outputs,
                    "input_output_tensors": tensor_records,
                }
            )
        graph_payload = {
            "model_version": int(model.Version()),
            "description": _decode_name(model.Description()),
            "subgraph_count": int(model.SubgraphsLength()),
            "operator_code_count": int(model.OperatorCodesLength()),
            "operator_count": total_operators,
            "tensor_count": total_tensors,
            "buffer_count": int(model.BuffersLength()),
            "operator_counts": dict(sorted(operator_counts.items())),
            "subgraphs": subgraphs[:50],
        }
        return {
            "status": "parsed",
            "parser": "tflite-2.18.0-generated-schema",
            "graph_fingerprint": hashlib.sha256(
                json.dumps(
                    graph_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            **graph_payload,
        }
    except Exception as exc:
        return {
            "status": "parse_failed",
            "reason": f"{type(exc).__name__}: {exc}",
        }


def parse_model_metadata(
    path: str,
    data: bytes,
    *,
    complete: bool = True,
) -> dict[str, Any]:
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
    structured_graph = (
        _parse_tflite_graph(data, complete=complete)
        if model_format in {"tflite", "tflite_task_bundle"}
        or (len(data) >= 8 and data[4:8] == b"TFL3")
        else {
            "status": "not_applicable",
            "reason": "No plain TFLite identifier or TFLite file extension was detected.",
        }
    )

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
        "payload_complete": complete,
        "structured_graph": structured_graph,
    }
