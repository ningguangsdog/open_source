"""Deterministic, representation-aware function fingerprints.

The pipeline compares source methods, disassembly inventories, and decompiler
output.  This module keeps their common identity and lightweight comparison
features in one schema without pretending that unlike representations are
directly equivalent.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import math
import re
from typing import Any, Iterable, Mapping


FINGERPRINT_SCHEMA = "2026-08-24.unified-function-fingerprint.v2"

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_CAMEL_1_RE = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_2_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_ADDRESS_LIKE_RE = re.compile(r"^(?:sub|loc|off|unk|a|v)[0-9a-f]+$", re.I)
_GENERIC_TOKENS = {
    "android",
    "array",
    "bool",
    "byte",
    "char",
    "const",
    "double",
    "fastcall",
    "float",
    "function",
    "int",
    "int32",
    "int64",
    "java",
    "jni",
    "native",
    "null",
    "nullptr",
    "operator",
    "result",
    "size",
    "static",
    "std",
    "string",
    "this",
    "unsigned",
    "void",
}
_ALIASES = {
    "binarization": "binarize",
    "binarisation": "binarize",
    "binarized": "binarize",
    "segmentation": "segment",
    "segmented": "segment",
    "detection": "detect",
    "detector": "detect",
    "detected": "detect",
    "classification": "classify",
    "classifier": "classify",
    "inference": "infer",
    "interpreter": "infer",
    "recognition": "recognize",
    "recognizer": "recognize",
    "rectification": "rectify",
    "dewarping": "dewarp",
    "dewarped": "dewarp",
    "documents": "document",
    "images": "image",
    "lines": "line",
    "pages": "page",
}


def stable_id(*parts: object, length: int = 32) -> str:
    payload = "\x1f".join(str(part) for part in parts if part is not None)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:length]


def identifier_tokens(values: str | Iterable[object]) -> list[str]:
    chunks = [values] if isinstance(values, str) else values
    output: list[str] = []
    for value in chunks:
        text = _CAMEL_1_RE.sub(r"\1 \2", str(value or ""))
        text = _CAMEL_2_RE.sub(r"\1 \2", text)
        for token in _WORD_RE.findall(text):
            normalized = _ALIASES.get(token.lower(), token.lower())
            if (
                normalized in _GENERIC_TOKENS
                or _ADDRESS_LIKE_RE.fullmatch(normalized)
                or (len(normalized) < 3 and normalized != "ml")
            ):
                continue
            output.append(normalized)
    return output


def bottom_k_token_signature(
    tokens: Iterable[object],
    *,
    shingle_size: int = 4,
    max_hashes: int = 128,
) -> dict[str, Any]:
    normalized = [str(token).strip().lower() for token in tokens if str(token).strip()]
    hashes: set[str] = set()
    if len(normalized) >= shingle_size:
        for index in range(len(normalized) - shingle_size + 1):
            digest = hashlib.blake2b(
                "\x1f".join(normalized[index : index + shingle_size]).encode(
                    "utf-8", errors="ignore"
                ),
                digest_size=8,
            ).hexdigest()
            hashes.add(digest)
            if len(hashes) > max_hashes * 8:
                hashes = set(sorted(hashes)[:max_hashes])
    retained = sorted(hashes)[:max_hashes]
    return {
        "algorithm": "bottom_k_blake2b_64",
        "shingle_size": shingle_size,
        "token_count": len(normalized),
        "shingle_count": max(0, len(normalized) - shingle_size + 1),
        "retained_hash_count": len(retained),
        "hashes": retained,
    }


def jaccard(left: Iterable[object], right: Iterable[object]) -> float:
    left_set = {str(value) for value in left if str(value)}
    right_set = {str(value) for value in right if str(value)}
    if not left_set or not right_set:
        return 0.0
    return len(left_set & right_set) / len(left_set | right_set)


def counter_cosine(
    left: Mapping[str, int] | Counter[str],
    right: Mapping[str, int] | Counter[str],
) -> float:
    if not left or not right:
        return 0.0
    shared = set(left).intersection(right)
    numerator = sum(float(left[key]) * float(right[key]) for key in shared)
    left_norm = math.sqrt(sum(float(value) ** 2 for value in left.values()))
    right_norm = math.sqrt(sum(float(value) ** 2 for value in right.values()))
    if not left_norm or not right_norm:
        return 0.0
    return numerator / (left_norm * right_norm)


def size_similarity(left: int | None, right: int | None) -> float:
    if not left or not right or left <= 0 or right <= 0:
        return 0.0
    return min(left, right) / max(left, right)


def build_fingerprint(
    *,
    function_id: str,
    representation: str,
    name: str,
    capabilities: Iterable[object] = (),
    call_targets: Iterable[object] = (),
    strings: Iterable[object] = (),
    branch_counts: Mapping[str, int] | None = None,
    cfg_counts: Mapping[str, int] | None = None,
    size_measure: int | None = None,
    instruction_tokens: Iterable[object] = (),
) -> dict[str, Any]:
    capabilities_list = [value for value in capabilities if value]
    call_targets_list = [value for value in call_targets if value]
    strings_list = [value for value in strings if value]
    semantic_tokens = sorted(
        set(identifier_tokens([name, *capabilities_list]))
    )
    call_tokens = sorted(set(identifier_tokens(call_targets_list)))
    string_tokens = sorted(set(identifier_tokens(strings_list)))
    instruction_tokens_list = [
        str(value).strip().lower()
        for value in instruction_tokens
        if str(value).strip()
    ]
    signature = bottom_k_token_signature(instruction_tokens_list)
    structural_payload = {
        "branches": dict(sorted((branch_counts or {}).items())),
        "cfg": dict(sorted((cfg_counts or {}).items())),
        "instruction_signature": signature,
        "size_measure": int(size_measure or 0),
    }
    structural_sha256 = hashlib.sha256(
        repr(structural_payload).encode("utf-8", errors="ignore")
    ).hexdigest()
    return {
        "schema_version": FINGERPRINT_SCHEMA,
        "function_id": function_id,
        "representation": representation,
        "name": name,
        "semantic_tokens": semantic_tokens,
        "call_tokens": call_tokens,
        "string_tokens": string_tokens,
        "capabilities": sorted({str(value) for value in capabilities_list}),
        "branch_counts": dict(sorted((branch_counts or {}).items())),
        "cfg_counts": dict(sorted((cfg_counts or {}).items())),
        "size_measure": int(size_measure or 0),
        "instruction_signature": signature,
        "structural_sha256": structural_sha256,
    }
