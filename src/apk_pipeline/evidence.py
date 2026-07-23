"""Shared evidence-unit helpers for similarity-ready exports."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .utils import atomic_text_writer


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[^\sA-Za-z0-9_]")
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def normalize_text(text: str, *, max_chars: int = 20000) -> str:
    sample = text[:max_chars]
    sample = re.sub(r"https?://\S+", " URL ", sample)
    sample = re.sub(r"0x[0-9A-Fa-f]+", " HEX ", sample)
    sample = re.sub(r"\b\d+\b", " NUM ", sample)
    return " ".join(TOKEN_RE.findall(sample.lower()))


def token_fingerprint(text: str, *, max_chars: int = 20000) -> str:
    normalized = normalize_text(text, max_chars=max_chars)
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def unit_id(*parts: object) -> str:
    joined = "\x1f".join(str(part) for part in parts if part is not None)
    return hashlib.sha256(joined.encode("utf-8", errors="ignore")).hexdigest()[:24]


def compact_list(values: Iterable[Any], limit: int = 50) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def capability_confidence(capabilities: Iterable[str], evidence_count: int = 1) -> float:
    count = len({str(item) for item in capabilities if item})
    if count == 0:
        return 0.2
    return min(0.95, 0.35 + (0.08 * count) + (0.03 * min(evidence_count, 8)))


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    with atomic_text_writer(path) as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            fh.write("\n")
            count += 1
    return count
