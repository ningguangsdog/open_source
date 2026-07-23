"""Conservative semantic labels for native functions and ABIs."""

from __future__ import annotations

import re
from typing import Any


WRAPPER_MARKERS = (
    "thunk",
    "trampoline",
    "wrapper",
    "bridge",
    "forward",
    "dispatch",
    "register_natives",
    "registernatives",
    "jni_onload",
)
MODEL_RUNTIME_MARKERS = (
    "tflite",
    "tensorflow",
    "onnx",
    "mediapipe",
    "interpreter",
    "delegate",
    "invoke",
    "runmodel",
    "run_model",
)
ALGORITHM_MARKERS = (
    "ocr",
    "recogn",
    "segment",
    "classif",
    "detect",
    "deskew",
    "dewarp",
    "encrypt",
    "decrypt",
    "cipher",
    "compress",
    "render",
    "filter",
    "transform",
)
ORCHESTRATION_MARKERS = (
    "pipeline",
    "process",
    "execute",
    "workflow",
    "initialize",
    "prepare",
    "run",
    "apply",
)
UTILITY_MARKERS = (
    "malloc",
    "calloc",
    "realloc",
    "operator new",
    "operator delete",
    "memcpy",
    "memset",
    "strlen",
    "strcmp",
    "log",
    "error",
    "exception",
    "destructor",
)
ACCESSOR_RE = re.compile(
    r"(?:^|[_:.])(?:get|set|is|has)[A-Z_]|(?:getter|setter)(?:$|[_:.])"
)
LOOP_RE = re.compile(r"\b(?:for|while|do)\s*(?:\(|\{)")
ARITHMETIC_RE = re.compile(
    r"(?:\+\+|--|<<|>>|\+=|-=|\*=|/=|%=|\^=|\|=|&=)"
)
INDEXED_DATA_RE = re.compile(r"\[[^\]\n]{1,80}\]")


def abi_analysis_role(abi: str | None, *, arm64_available: bool) -> str:
    """Describe how one ABI should be used in manual native review."""

    normalized = str(abi or "").lower()
    if normalized == "arm64-v8a":
        return "primary_production"
    if normalized in {"armeabi-v7a", "armeabi"}:
        return "secondary_production"
    if normalized in {"x86_64", "x86"}:
        return "cross_validation" if arm64_available else "fallback_cross_validation"
    return "unknown_abi"


def _feature_int(features: dict[str, Any], name: str) -> int:
    try:
        return int(features.get(name) or 0)
    except (TypeError, ValueError):
        return 0


def classify_native_semantics(
    name: str | None,
    *,
    pseudocode: str = "",
    features: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assign an evidence-bounded native role without claiming algorithm recovery."""

    features = features or {}
    symbol = str(name or "")
    lowered_name = symbol.lower()
    lowered_text = pseudocode.lower()
    combined = f"{lowered_name}\n{lowered_text}"
    nonempty_lines = [line for line in pseudocode.splitlines() if line.strip()]
    instruction_count = _feature_int(features, "instruction_count")
    block_count = _feature_int(features, "basic_block_count")
    call_count = len(features.get("call_targets") or [])

    wrapper_hits = [marker for marker in WRAPPER_MARKERS if marker in lowered_name]
    if symbol.startswith("Java_") and (
        (bool(pseudocode.strip()) and len(nonempty_lines) <= 12)
        or (0 < instruction_count <= 24)
        or any(marker in lowered_text for marker in ("jmp ", "goto "))
    ):
        wrapper_hits.append("short_jni_entry")
    if ACCESSOR_RE.search(symbol) and len(nonempty_lines) <= 15:
        wrapper_hits.append("short_accessor")
    if wrapper_hits:
        return {
            "role": "wrapper",
            "confidence": "high" if pseudocode or instruction_count else "medium",
            "reasons": sorted(set(wrapper_hits)),
        }

    runtime_hits = [marker for marker in MODEL_RUNTIME_MARKERS if marker in combined]
    if runtime_hits:
        return {
            "role": "model_runtime",
            "confidence": "high" if pseudocode or instruction_count else "medium",
            "reasons": sorted(set(runtime_hits))[:8],
        }

    utility_hits = [marker for marker in UTILITY_MARKERS if marker in combined]
    algorithm_hits = [marker for marker in ALGORITHM_MARKERS if marker in combined]
    orchestration_hits = [
        marker for marker in ORCHESTRATION_MARKERS if marker in lowered_name
    ]

    substantive = (
        len(nonempty_lines) >= 18
        or instruction_count >= 60
        or block_count >= 8
    )
    algorithm_structure_hits: list[str] = []
    if LOOP_RE.search(pseudocode):
        algorithm_structure_hits.append("loop_structure")
    if len(ARITHMETIC_RE.findall(pseudocode)) >= 2:
        algorithm_structure_hits.append("repeated_arithmetic_or_bitwise_operations")
    if len(INDEXED_DATA_RE.findall(pseudocode)) >= 3:
        algorithm_structure_hits.append("indexed_buffer_or_tensor_access")
    if instruction_count >= 80 and block_count >= 8:
        algorithm_structure_hits.append("substantive_instruction_and_cfg_structure")
    if algorithm_hits and substantive and algorithm_structure_hits:
        return {
            "role": "algorithm",
            "confidence": "high" if pseudocode and block_count >= 5 else "medium",
            "reasons": sorted(
                set(algorithm_hits).union(algorithm_structure_hits)
            )[:8],
        }
    if orchestration_hits and (call_count >= 3 or len(nonempty_lines) >= 15):
        return {
            "role": "orchestration",
            "confidence": "high" if pseudocode else "medium",
            "reasons": sorted(set(orchestration_hits))[:8],
        }
    if utility_hits and not algorithm_hits:
        return {
            "role": "utility",
            "confidence": "high" if pseudocode or instruction_count else "medium",
            "reasons": sorted(set(utility_hits))[:8],
        }
    if algorithm_hits:
        return {
            "role": "uncertain",
            "confidence": "low",
            "reasons": [
                "algorithm_name_signal_without_substantive_body",
                *sorted(set(algorithm_hits))[:7],
            ],
        }
    return {
        "role": "uncertain",
        "confidence": "low",
        "reasons": ["insufficient_semantic_evidence"],
    }
