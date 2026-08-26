"""Method-level index over complete JADX Java/Kotlin output."""

from __future__ import annotations

from collections import Counter
import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from .capability_taxonomy import capability_names, classify_text
from .evidence import token_shingle_signature
from .function_fingerprint import build_fingerprint, identifier_tokens, stable_id
from .utils import sha256_file


METHOD_INDEX_SCHEMA = "2026-08-24.jadx-method-index.v1"
METHOD_SIGNATURES = {
    ".java": re.compile(
        r"(?ms)^[ \t]*(?:@[A-Za-z_][A-Za-z0-9_.]*(?:\([^\n]*\))?[ \t\n]*)*"
        r"(?:(?:public|protected|private|static|final|native|synchronized|abstract|default|strictfp)[ \t]+)*"
        r"(?:[A-Za-z_$][A-Za-z0-9_$<>.?\[\],]*[ \t]+)?"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)[ \t]*\([^;{}]*?\)"
        r"\s*(?:throws[^{]+)?\{"
    ),
    ".kt": re.compile(
        r"(?ms)^[ \t]*(?:(?:public|private|protected|internal|open|final|override|suspend|inline|tailrec|operator|infix|external)[ \t]+)*"
        r"fun[ \t]+(?:<[^;{}]+>[ \t]*)?(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
        r"[ \t]*\([^;{}]*?\)[^{=]*\{"
    ),
}
CONTROL_NAMES = {"if", "for", "while", "switch", "catch", "when", "synchronized"}
CALL_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(")
STRING_RE = re.compile(r'"((?:\\.|[^"\\]){3,300})"')
NUMBER_RE = re.compile(r"(?<![A-Za-z0-9_])(?:0x[0-9A-Fa-f]+|[-+]?\d+(?:\.\d+)?)(?![A-Za-z0-9_])")
BRANCH_PATTERNS = {
    "if": re.compile(r"\bif\s*\("),
    "for": re.compile(r"\bfor\s*\("),
    "while": re.compile(r"\bwhile\s*\("),
    "switch": re.compile(r"\b(?:switch|when)\b"),
    "try": re.compile(r"\btry\b"),
    "catch": re.compile(r"\bcatch\s*\("),
    "return": re.compile(r"\breturn\b"),
}


def _matching_brace(text: str, opening: int) -> int | None:
    depth = 0
    state = "code"
    quote = ""
    index = opening
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state == "string":
            if char == "\\":
                index += 1
            elif char == quote:
                state = "code"
        else:
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block_comment"
                index += 1
            elif char in {'"', "'"}:
                state = "string"
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    return None


def _methods_in_text(text: str, suffix: str) -> Iterable[tuple[re.Match[str], str, int]]:
    pattern = METHOD_SIGNATURES[suffix]
    occupied_until = -1
    for match in pattern.finditer(text):
        name = match.group("name")
        if name.lower() in CONTROL_NAMES or match.start() < occupied_until:
            continue
        opening = text.find("{", match.start(), match.end())
        if opening < 0:
            continue
        closing = _matching_brace(text, opening)
        if closing is None:
            continue
        occupied_until = closing + 1
        yield match, text[match.start() : closing + 1], closing + 1


def build_jadx_method_index(
    decompile_root: Path,
    code_index: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    ownership_by_file = {
        str(record.get("file")): record.get("ownership") or {}
        for record in code_index.get("files") or []
        if isinstance(record, dict)
    }
    package_by_file = {
        str(record.get("file")): record.get("package")
        for record in code_index.get("files") or []
        if isinstance(record, dict)
    }
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    file_count = 0
    for path in sorted(
        (
            item
            for item in decompile_root.rglob("*")
            if item.is_file() and item.suffix.lower() in METHOD_SIGNATURES
        ),
        key=lambda item: str(item.relative_to(decompile_root)),
    ):
        relative = str(path.relative_to(decompile_root))
        file_count += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as error:
            errors.append({"file": relative, "error": f"{type(error).__name__}: {error}"})
            continue
        file_sha256 = sha256_file(path)
        for match, body, end_offset in _methods_in_text(text, path.suffix.lower()):
            start_line = text.count("\n", 0, match.start()) + 1
            end_line = text.count("\n", 0, end_offset) + 1
            signature = text[match.start() : text.find("{", match.start(), match.end())].strip()
            name = match.group("name")
            calls = Counter(
                value
                for value in CALL_RE.findall(body)
                if value.rsplit(".", 1)[-1] not in CONTROL_NAMES
                and value.rsplit(".", 1)[-1] != name
            )
            strings = sorted(set(STRING_RE.findall(body)))[:80]
            constants = sorted(set(NUMBER_RE.findall(body)))[:80]
            branch_counts = {
                key: len(pattern.findall(body))
                for key, pattern in BRANCH_PATTERNS.items()
            }
            capabilities = capability_names(classify_text(f"{signature}\n{body}").keys())
            function_id = stable_id("jadx_method", file_sha256, match.start(), name)
            fingerprint = build_fingerprint(
                function_id=function_id,
                representation="jadx_source_method",
                name=name,
                capabilities=capabilities,
                call_targets=calls.keys(),
                strings=strings,
                branch_counts=branch_counts,
                size_measure=max(1, end_line - start_line + 1),
                instruction_tokens=identifier_tokens(body),
            )
            rows.append(
                {
                    **fingerprint,
                    "index_schema_version": METHOD_INDEX_SCHEMA,
                    "language": "java" if path.suffix.lower() == ".java" else "kotlin",
                    "file": relative,
                    "file_sha256": file_sha256,
                    "package": package_by_file.get(relative),
                    "ownership": ownership_by_file.get(relative) or {"category": "unknown"},
                    "function_name": name,
                    "signature": signature[:2000],
                    "start_line": start_line,
                    "end_line": end_line,
                    "line_count": max(1, end_line - start_line + 1),
                    "body_sha256": hashlib.sha256(
                        body.encode("utf-8", errors="ignore")
                    ).hexdigest(),
                    "token_shingle_signature": token_shingle_signature(
                        body,
                        shingle_size=5,
                        max_hashes=128,
                    ),
                    "top_calls": [
                        {"name": value, "count": count}
                        for value, count in calls.most_common(50)
                    ],
                    "strings": strings,
                    "constants": constants,
                    "coverage_note": (
                        "Method body recovered from JADX output; this is not a raw-Dex "
                        "instruction index when JADX could not reconstruct a method."
                    ),
                }
            )
    rows.sort(key=lambda row: (str(row.get("file")), int(row.get("start_line") or 0)))
    ownership_counts = Counter(
        str((row.get("ownership") or {}).get("category") or "unknown") for row in rows
    )
    status = "completed"
    if errors and rows:
        status = "partial"
    elif errors and not rows:
        status = "failed"
    summary = {
        "schema_version": METHOD_INDEX_SCHEMA,
        "status": status,
        "representation": "jadx_source_method",
        "source_file_count": file_count,
        "indexed_method_count": len(rows),
        "ownership_method_counts": dict(sorted(ownership_counts.items())),
        "read_error_count": len(errors),
        "read_errors": errors[:100],
        "coverage_limit": (
            "Covers methods reconstructed in complete JADX output. Methods that JADX "
            "could not emit are reported by Phase 2 completeness and are not invented."
        ),
    }
    return summary, rows
