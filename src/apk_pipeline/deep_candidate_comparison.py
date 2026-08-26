"""Post-decompilation comparison for bounded open-source reuse candidates."""

from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable

from .function_fingerprint import identifier_tokens, jaccard, size_similarity, stable_id
from .source_candidate_policy import (
    annotate_source_policy,
    effective_source_role,
    source_analysis_lane,
)
from .utils import safe_read_text, safe_write_json


DEEP_COMPARISON_SCHEMA = "2026-08-25.open-source-deep-comparison.v3"
VALID_ANALYSIS_LANES = {"usage", "adaptation", "control"}
_QUOTED_RE = re.compile(r'(?P<quote>["\'])(?P<value>(?:\\.|(?!\1).){4,}?)\1')
_NUMBER_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:0x[0-9A-Fa-f]{2,}|[-+]?(?:\d+\.\d+|\d{2,}))(?![A-Za-z0-9_])"
)
_COMMON_NUMBERS = {
    "-1",
    "0",
    "1",
    "2",
    "3",
    "4",
    "8",
    "10",
    "16",
    "32",
    "64",
    "100",
    "128",
    "255",
    "256",
    "512",
    "1024",
}
_GENERIC_STRING_TOKENS = {
    "error",
    "failed",
    "invalid",
    "null",
    "success",
    "true",
    "false",
    "unknown",
}
_GENERIC_FUNCTION_TOKENS = {
    "add",
    "apply",
    "build",
    "call",
    "close",
    "create",
    "delete",
    "destroy",
    "get",
    "handle",
    "init",
    "load",
    "main",
    "make",
    "new",
    "open",
    "process",
    "read",
    "release",
    "run",
    "set",
    "start",
    "stop",
    "update",
    "write",
}
_GENERIC_CALL_TOKENS = {
    "alloc",
    "calloc",
    "delete",
    "error",
    "fprintf",
    "free",
    "log",
    "log10",
    "malloc",
    "memcpy",
    "memmove",
    "memset",
    "new",
    "printf",
    "realloc",
    "sin",
    "cos",
}
_BRANCH_PATTERNS = {
    "if": re.compile(r"\bif\s*\("),
    "switch": re.compile(r"\bswitch\s*\("),
    "for": re.compile(r"\bfor\s*\("),
    "while": re.compile(r"\bwhile\s*\("),
    "try": re.compile(r"\btry\b"),
    "return": re.compile(r"\breturn\b"),
}


def _iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, OSError):
                continue
            if isinstance(value, dict):
                yield value


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def _normalized_strings(values: Iterable[object]) -> set[str]:
    normalized: set[str] = set()
    for raw in values:
        value = " ".join(str(raw).strip().split()).lower()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"\"", "'"}
        ):
            value = value[1:-1].strip()
        if len(value) < 6 or value in _GENERIC_STRING_TOKENS:
            continue
        normalized.add(value)
    return normalized


def _pseudocode_strings(text: str) -> set[str]:
    return _normalized_strings(match.group("value") for match in _QUOTED_RE.finditer(text))


def _constants(values: Iterable[object]) -> set[str]:
    result: set[str] = set()
    for raw in values:
        value = str(raw).strip().lower()
        if not value:
            continue
        for match in _NUMBER_RE.findall(value):
            normalized = _normalized_number(match)
            if normalized not in _COMMON_NUMBERS:
                result.add(normalized)
    return result


def _normalized_number(value: object) -> str:
    raw = str(value).strip().lower().lstrip("+")
    if raw.startswith("0x"):
        return raw
    try:
        number = Decimal(raw)
    except InvalidOperation:
        return raw
    if number == number.to_integral_value():
        return str(int(number))
    return format(number.normalize(), "f")


def _overlap_coefficient(left: set[str], right: set[str]) -> float:
    """Measure containment when one representation expands the other."""

    if not left or not right:
        return 0.0
    return len(left.intersection(right)) / min(len(left), len(right))


def _specific_call_tokens(values: Iterable[object]) -> set[str]:
    return {
        token
        for token in identifier_tokens(values)
        if token not in _GENERIC_CALL_TOKENS
    }


def _branch_profile(text: str) -> dict[str, int]:
    return {
        name: len(pattern.findall(text))
        for name, pattern in _BRANCH_PATTERNS.items()
    }


def _normalized_branch_profile(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    profile: dict[str, int] = {}
    for name in _BRANCH_PATTERNS:
        try:
            count = int(value.get(name) or 0)
            if name == "if":
                count += int(value.get("guard") or 0)
        except (TypeError, ValueError):
            count = 0
        profile[name] = max(0, count)
    return profile


def _counter_similarity(left: dict[str, int], right: dict[str, int]) -> float:
    keys = sorted(set(left).union(right))
    if not keys:
        return 0.0
    dot = sum(left.get(key, 0) * right.get(key, 0) for key in keys)
    left_norm = math.sqrt(sum(left.get(key, 0) ** 2 for key in keys))
    right_norm = math.sqrt(sum(right.get(key, 0) ** 2 for key in keys))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)


def _source_identity(source: dict[str, Any]) -> tuple[str, ...]:
    provenance = (
        "provenance",
        str(source.get("repository_full_name") or source.get("corpus_id") or ""),
        str(source.get("commit_sha") or ""),
        str(source.get("source_path") or ""),
        str(source.get("start_line") or ""),
        str(source.get("function_name") or source.get("name") or ""),
        str(source.get("representation") or "source_code_function"),
        str(source.get("build_variant") or ""),
        str(source.get("abi") or ""),
        _canonical_address(source.get("address")),
    )
    # Retrieval assigns a stable function_id even when the frozen source index
    # predates that field. Prefer the reproducible source location so both
    # representations resolve to the same evidence row.
    if any(provenance[index] for index in (1, 2, 3, 4, 5)):
        return provenance
    function_id = str(source.get("function_id") or "")
    if function_id:
        return ("function_id", function_id)
    return provenance


def _source_family(source: dict[str, Any]) -> str:
    representation = str(source.get("representation") or "")
    name = str(source.get("function_name") or source.get("name") or "")
    if (
        representation == "oss_compiled_binary_function"
        and name
        and not name.startswith(("sub_", "loc_", "j_", "nullsub_", "imp_"))
    ):
        return "compiled-source:" + stable_id(
            source.get("repository_full_name") or source.get("corpus_id"),
            source.get("commit_sha"),
            source.get("source_path"),
            name,
        )
    body = str(source.get("body_sha256") or "")
    structural = str(source.get("structural_sha256") or "")
    if body:
        return f"body:{body}"
    if structural:
        return f"structural:{structural}"
    return "source:" + stable_id(*_source_identity(source))


def _decompiled_seed(result: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    target = result.get("target") or {}
    commercial_id = str(target.get("commercial_function_id") or "")
    candidate = target.get("reuse_candidate")
    if not isinstance(candidate, dict):
        candidate = {}
    if not commercial_id:
        commercial_id = str(
            (candidate.get("commercial") or {}).get("function_id") or ""
        )
    return commercial_id, candidate


def _candidate_pair_id(candidate: dict[str, Any]) -> str:
    commercial = candidate.get("commercial") or {}
    source = candidate.get("source") or {}
    existing = str(candidate.get("candidate_pair_id") or "")
    if existing:
        return existing
    return stable_id(
        "reuse_candidate_pair",
        candidate.get("commercial_function_id") or commercial.get("function_id"),
        candidate.get("source_function_id") or source.get("function_id"),
        source.get("repository_full_name") or source.get("corpus_id"),
    )


def _normalized_lane(value: object) -> str:
    lane = str(value or "").strip().lower()
    return lane if lane in VALID_ANALYSIS_LANES else "control"


def _normalized_seed_candidate(
    result: dict[str, Any],
    commercial_id: str,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Build the authoritative candidate carried by the selected IDA target."""

    target = result.get("target") or {}
    normalized = dict(candidate)
    commercial = {
        **(candidate.get("commercial") or {}),
        "function_id": commercial_id
        or candidate.get("commercial_function_id")
        or (candidate.get("commercial") or {}).get("function_id"),
        "library": target.get("library")
        or (candidate.get("commercial") or {}).get("library"),
        "library_sha256": target.get("library_sha256")
        or (candidate.get("commercial") or {}).get("library_sha256"),
        "abi": target.get("abi")
        or (candidate.get("commercial") or {}).get("abi"),
        "address": target.get("address")
        or (candidate.get("commercial") or {}).get("address"),
        "name": target.get("name")
        or (candidate.get("commercial") or {}).get("name"),
        "ownership": target.get("ownership")
        or (candidate.get("commercial") or {}).get("ownership")
        or {},
    }
    source = dict(candidate.get("source") or {})
    normalized.update(
        {
            "commercial_function_id": commercial.get("function_id"),
            "source_function_id": candidate.get("source_function_id")
            or source.get("function_id"),
            "analysis_lane": _normalized_lane(
                target.get("analysis_lane") or candidate.get("analysis_lane")
            ),
            "commercial": commercial,
            "source": source,
            "source_project": candidate.get("source_project")
            or source.get("repository_full_name")
            or source.get("corpus_id"),
        }
    )
    normalized["candidate_pair_id"] = str(
        target.get("candidate_pair_id")
        or candidate.get("candidate_pair_id")
        or _candidate_pair_id(normalized)
    )
    return normalized


def _merge_candidate_metadata(
    authoritative: dict[str, Any],
    supplement: dict[str, Any],
) -> dict[str, Any]:
    """Enrich an IDA seed without allowing raw retrieval rows to replace identity."""

    merged = dict(supplement)
    merged.update(authoritative)
    merged["commercial"] = {
        **(supplement.get("commercial") or {}),
        **(authoritative.get("commercial") or {}),
    }
    merged["source"] = {
        **(supplement.get("source") or {}),
        **(authoritative.get("source") or {}),
    }
    merged["analysis_lane"] = _normalized_lane(
        authoritative.get("analysis_lane")
    )
    merged["candidate_pair_id"] = _candidate_pair_id(authoritative)
    return merged


def _canonical_address(value: object) -> str:
    raw = str(value or "").strip().lower()
    try:
        return hex(int(raw, 0))
    except (TypeError, ValueError):
        return raw


def _commercial_identity(value: dict[str, Any]) -> tuple[str, str]:
    return (
        str(value.get("library_sha256") or "").strip().lower(),
        _canonical_address(value.get("address")),
    )


def _load_source_rows(
    source_index_paths: Iterable[Path],
    identities: set[tuple[str, ...]],
) -> dict[tuple[str, ...], dict[str, Any]]:
    rows: dict[tuple[str, ...], dict[str, Any]] = {}
    if not identities:
        return rows
    for path in source_index_paths:
        for row in _iter_jsonl(path):
            identity = _source_identity(row)
            if identity in identities:
                rows[identity] = row
    return rows


def _load_all_source_rows(
    source_index_paths: Iterable[Path],
) -> list[dict[str, Any]]:
    rows: dict[tuple[str, ...], dict[str, Any]] = {}
    for path in source_index_paths:
        for row in _iter_jsonl(path):
            rows[_source_identity(row)] = row
    return list(rows.values())


def _source_function_id(source: dict[str, Any]) -> str:
    existing = str(source.get("function_id") or "")
    if existing:
        return existing
    return stable_id("open_source_function", *_source_identity(source))


def _function_name_key(value: object) -> tuple[str, ...]:
    raw = str(value or "").strip()
    raw = re.sub(r"^(?:\.|j_|imp_|thunk_)+", "", raw, flags=re.IGNORECASE)
    return tuple(identifier_tokens(raw))


def _generic_function_key(key: tuple[str, ...]) -> bool:
    return not key or set(key).issubset(_GENERIC_FUNCTION_TOKENS)


def _result_identity(result: dict[str, Any]) -> tuple[str, str]:
    return _commercial_identity(result.get("target") or {})


def _result_metrics(result: dict[str, Any]) -> dict[str, Any]:
    target = result.get("target") or {}
    features = result.get("function_features") or {}
    instructions = int(features.get("instruction_count") or 0)
    blocks = int(features.get("basic_block_count") or 0)
    lines = int(features.get("pseudocode_nonempty_line_count") or 0)
    strings = len(_normalized_strings(features.get("string_refs") or []))
    callees = [
        _canonical_address(value)
        for value in features.get("callee_addresses") or []
        if _canonical_address(value)
    ]
    name = str(target.get("name") or "")
    wrapper_like = bool(
        name.startswith((".", "j_", "imp_", "thunk_"))
        or (instructions <= 12 and blocks <= 4 and lines <= 12 and callees)
    )
    substantive = bool(
        instructions >= 20
        or lines >= 15
        or blocks >= 8
        or strings >= 2
    )
    score = (
        min(instructions, 5000) * 0.020
        + min(lines, 3000) * 0.025
        + min(blocks, 1000) * 0.30
        + min(strings, 50) * 2.0
        - (40.0 if wrapper_like else 0.0)
    )
    return {
        "instruction_count": instructions,
        "basic_block_count": blocks,
        "pseudocode_nonempty_line_count": lines,
        "distinctive_string_count": strings,
        "callee_addresses": callees,
        "wrapper_like": wrapper_like,
        "substantive": substantive,
        "substantiveness_score": round(score, 6),
    }


def _origin_pair_id(result: dict[str, Any]) -> str:
    target = result.get("target") or {}
    origin = target.get("origin_seed_candidate") or {}
    return str(
        origin.get("candidate_pair_id")
        or target.get("origin_candidate_pair_id")
        or ""
    )


def _resolve_canonical_implementation(
    seed_result: dict[str, Any],
    pair_id: str,
    result_by_identity: dict[tuple[str, str], dict[str, Any]],
    origin_results: dict[str, list[dict[str, Any]]],
    *,
    max_depth: int = 3,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve a selected seed to the most substantive reached function body."""

    seed_identity = _result_identity(seed_result)
    seed_metrics = _result_metrics(seed_result)
    library_hash = seed_identity[0]
    candidates: dict[tuple[str, str], tuple[dict[str, Any], int, list[str]]] = {}
    if seed_result.get("success") is True:
        candidates[seed_identity] = (seed_result, 0, [seed_identity[1]])

    queue: list[tuple[dict[str, Any], int, list[str]]] = [
        (seed_result, 0, [seed_identity[1]])
    ]
    visited = {seed_identity}
    while queue:
        current, depth, path = queue.pop(0)
        if depth >= max_depth:
            continue
        metrics = _result_metrics(current)
        for address in metrics["callee_addresses"]:
            identity = (library_hash, address)
            child = result_by_identity.get(identity)
            if child is None or identity in visited:
                continue
            visited.add(identity)
            child_path = [*path, address]
            if child.get("success") is True:
                candidates[identity] = (child, depth + 1, child_path)
            queue.append((child, depth + 1, child_path))

    for child in origin_results.get(pair_id, []):
        identity = _result_identity(child)
        if child.get("success") is True and all(identity):
            candidates.setdefault(identity, (child, 1, [seed_identity[1], identity[1]]))

    ranked = sorted(
        candidates.values(),
        key=lambda item: (
            not _result_metrics(item[0])["substantive"],
            -float(_result_metrics(item[0])["substantiveness_score"]),
            item[1],
            str((item[0].get("target") or {}).get("address") or ""),
        ),
    )
    canonical, depth, path = ranked[0] if ranked else (seed_result, 0, [seed_identity[1]])
    canonical_metrics = _result_metrics(canonical)
    if (
        seed_result.get("success") is True
        and not seed_metrics["wrapper_like"]
        and seed_metrics["substantive"]
    ):
        canonical, depth, path = seed_result, 0, [seed_identity[1]]
        canonical_metrics = seed_metrics
    elif canonical is not seed_result and not canonical_metrics["substantive"]:
        canonical, depth, path = seed_result, 0, [seed_identity[1]]
        canonical_metrics = seed_metrics

    canonical_identity = _result_identity(canonical)
    resolution = {
        "schema_version": "2026-08-25.canonical-implementation.v1",
        "candidate_pair_id": pair_id,
        "seed": {
            "library_sha256": seed_identity[0],
            "address": seed_identity[1],
            "name": (seed_result.get("target") or {}).get("name"),
            **seed_metrics,
        },
        "canonical": {
            "library_sha256": canonical_identity[0],
            "address": canonical_identity[1],
            "name": (canonical.get("target") or {}).get("name"),
            **canonical_metrics,
        },
        "resolution_depth": depth,
        "call_path": path,
        "resolved_away_from_seed": canonical_identity != seed_identity,
        "resolution_reason": (
            "wrapper_or_thunk_resolved_to_substantive_callee"
            if canonical_identity != seed_identity
            else "seed_is_substantive_or_no_better_reached_body"
        ),
    }
    return canonical, resolution


def _source_family_expansions(
    canonical_result: dict[str, Any],
    seed_result: dict[str, Any],
    source_name_index: dict[tuple[str, ...], list[dict[str, Any]]],
    source_string_index: dict[str, list[dict[str, Any]]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Bridge a canonical body to bounded source families missed by retrieval."""

    target = canonical_result.get("target") or {}
    features = canonical_result.get("function_features") or {}
    pseudocode = safe_read_text(
        Path(str(canonical_result.get("output_path") or "")),
        limit=750_000,
    )
    name_keys = {
        _function_name_key(target.get("name")),
        _function_name_key((seed_result.get("target") or {}).get("name")),
    }
    name_keys.discard(())
    commercial_strings = _pseudocode_strings(pseudocode).union(
        _normalized_strings(features.get("string_refs") or [])
    )
    commercial_calls = _specific_call_tokens(features.get("call_targets") or [])
    pool: dict[tuple[str, ...], dict[str, Any]] = {}
    for key in name_keys:
        for source in source_name_index.get(key, []):
            pool[_source_identity(source)] = source
    for value in commercial_strings:
        for source in source_string_index.get(value, []):
            pool[_source_identity(source)] = source

    ranked: list[tuple[float, dict[str, Any], list[str]]] = []
    for source in pool.values():
        source_key = _function_name_key(
            source.get("function_name") or source.get("name")
        )
        exact_name = source_key in name_keys and bool(source_key)
        matched_strings = commercial_strings.intersection(
            _normalized_strings(source.get("strings") or [])
        )
        source_calls = _specific_call_tokens(
            row.get("name")
            for row in source.get("top_calls") or []
            if isinstance(row, dict)
        )
        call_overlap = commercial_calls.intersection(source_calls)
        role, _role_reason = effective_source_role(source)
        source_size = int(
            source.get("structure_token_count")
            or source.get("instruction_count")
            or source.get("line_count")
            or 0
        )
        distinctive_name = exact_name and not _generic_function_key(source_key)
        independent_channels = sum(
            (
                distinctive_name,
                bool(matched_strings),
                len(call_overlap) >= 2,
            )
        )
        if _generic_function_key(source_key) and independent_channels < 2:
            continue
        if role == "method_control" and not matched_strings and not call_overlap:
            continue
        if not distinctive_name and independent_channels < 2:
            continue
        bridge_score = (
            (0.50 if distinctive_name else 0.0)
            + min(0.35, 0.10 * len(matched_strings))
            + min(0.15, 0.05 * len(call_overlap))
            + (0.05 if source_size >= 8 else 0.0)
        )
        reasons = []
        if distinctive_name:
            reasons.append("normalized_function_name")
        if matched_strings:
            reasons.append("distinctive_string")
        if len(call_overlap) >= 2:
            reasons.append("call_pattern")
        ranked.append((bridge_score, source, reasons))

    ranked.sort(
        key=lambda item: (
            -item[0],
            str(item[1].get("repository_full_name") or item[1].get("corpus_id") or ""),
            str(item[1].get("source_path") or ""),
            str(item[1].get("start_line") or ""),
        )
    )
    expansions: list[dict[str, Any]] = []
    for bridge_score, raw_source, reasons in ranked[: max(0, limit)]:
        source = annotate_source_policy(raw_source)
        source_id = _source_function_id(source)
        source["function_id"] = source_id
        candidate = {
            "schema_version": "2026-08-25.source-family-expansion.v1",
            "source_function_id": source_id,
            "analysis_lane": source_analysis_lane(source),
            "source_project": source.get("repository_full_name")
            or source.get("corpus_id"),
            "source": source,
            "retrieval_score": 0.0,
            "selection_score": round(bridge_score, 6),
            "components": {},
            "source_family_expansion": {
                "bridge_score": round(bridge_score, 6),
                "reasons": reasons,
                "bounded": True,
            },
        }
        expansions.append(candidate)
    return expansions


def _comparison_features(
    result: dict[str, Any],
    source: dict[str, Any],
    candidate: dict[str, Any],
) -> tuple[float, dict[str, Any], list[str]]:
    target = result.get("target") or {}
    features = result.get("function_features") or {}
    pseudocode = safe_read_text(Path(str(result.get("output_path") or "")), limit=750_000)
    commercial_strings = _pseudocode_strings(pseudocode).union(
        _normalized_strings(features.get("string_refs") or [])
    )
    source_strings = _normalized_strings(source.get("strings") or [])
    exact_strings = sorted(commercial_strings.intersection(source_strings))

    commercial_constants = _constants(_NUMBER_RE.findall(pseudocode))
    source_constants = _constants(source.get("constants") or [])
    exact_constants = sorted(commercial_constants.intersection(source_constants))

    commercial_calls = _specific_call_tokens(features.get("call_targets") or [])
    source_calls = _specific_call_tokens(
        [
            row.get("name")
            for row in source.get("top_calls") or []
            if isinstance(row, dict)
        ]
    )
    call_overlap = sorted(commercial_calls.intersection(source_calls))

    commercial_semantic = set(
        identifier_tokens(
            [target.get("name"), *(target.get("capabilities") or [])]
        )
    )
    source_semantic = set(
        identifier_tokens(
            [
                source.get("function_name") or source.get("name"),
                Path(str(source.get("source_path") or "")).stem,
                *(source.get("capabilities") or []),
            ]
        )
    )
    semantic_overlap = sorted(commercial_semantic.intersection(source_semantic))
    commercial_branches = _branch_profile(pseudocode)
    source_branches = _normalized_branch_profile(source.get("branch_counts"))
    commercial_branch_total = sum(commercial_branches.values())
    source_branch_total = sum(source_branches.values())

    source_size = int(
        source.get("structure_token_count")
        or source.get("instruction_count")
        or source.get("line_count")
        or 0
    )
    commercial_size = int(
        features.get("instruction_count")
        or features.get("pseudocode_nonempty_line_count")
        or 0
    )
    retrieval_components = candidate.get("components") or {}
    exact_compiled_body = float(retrieval_components.get("exact_body") or 0)
    exact_compiled_structure = float(
        retrieval_components.get("exact_structural") or 0
    )
    compiled_instruction_overlap = float(
        retrieval_components.get("instruction") or 0
    )
    components = {
        # Containment is representation-aware: decompiled functions commonly
        # inline or retain more literals and calls than their source body.
        "distinctive_strings": _overlap_coefficient(
            commercial_strings,
            source_strings,
        ),
        "distinctive_constants": _overlap_coefficient(
            commercial_constants,
            source_constants,
        ),
        "call_pattern": _overlap_coefficient(commercial_calls, source_calls),
        "control_flow_profile": _counter_similarity(
            commercial_branches,
            source_branches,
        ),
        "semantic": jaccard(commercial_semantic, source_semantic),
        "structure_size": size_similarity(commercial_size, source_size),
        "retrieval_prior": float(candidate.get("retrieval_score") or 0),
    }
    available = {
        "distinctive_strings": 0.25 if commercial_strings and source_strings else 0.0,
        "distinctive_constants": 0.15 if commercial_constants and source_constants else 0.0,
        "call_pattern": 0.20 if commercial_calls and source_calls else 0.0,
        "control_flow_profile": (
            0.15
            if commercial_branch_total >= 3 and source_branch_total >= 3
            else 0.0
        ),
        "semantic": 0.10 if commercial_semantic and source_semantic else 0.0,
        "structure_size": 0.10 if commercial_size and source_size else 0.0,
        "retrieval_prior": 0.05,
    }
    denominator = sum(available.values()) or 1.0
    score = sum(components[key] * weight for key, weight in available.items()) / denominator

    signals: list[str] = []
    if exact_compiled_body > 0:
        signals.append("exact_compiled_body")
    if exact_compiled_structure > 0:
        signals.append("exact_compiled_structure")
    if compiled_instruction_overlap >= 0.8:
        signals.append("compiled_instruction_overlap")
    if len(exact_strings) >= 2 or any(len(value) >= 20 for value in exact_strings):
        signals.append("exact_distinctive_string")
    if len(exact_constants) >= 2:
        signals.append("distinctive_constant_bundle")
    if len(call_overlap) >= 2 or components["call_pattern"] >= 0.5:
        signals.append("call_pattern")
    if (
        commercial_branch_total >= 3
        and source_branch_total >= 3
        and components["control_flow_profile"] >= 0.8
    ):
        signals.append("control_flow_profile")
    if len(semantic_overlap) >= 2 and components["semantic"] >= 0.5:
        signals.append("semantic_operation")
    if (
        components["structure_size"] >= 0.8
        and (commercial_size >= 20 and source_size >= 20)
    ):
        signals.append("compatible_structure_scale")

    detail = {
        "components": {key: round(value, 6) for key, value in components.items()},
        "available_weight": round(sum(available.values()), 6),
        "matched_distinctive_strings": exact_strings[:100],
        "matched_distinctive_constants": exact_constants[:100],
        "matched_call_tokens": call_overlap[:100],
        "matched_semantic_tokens": semantic_overlap[:100],
        "set_similarity_basis": {
            "distinctive_strings": "overlap_coefficient",
            "distinctive_constants": "overlap_coefficient",
            "call_pattern": "overlap_coefficient_after_runtime_token_filter",
            "semantic": "jaccard",
        },
        "commercial_branch_profile": commercial_branches,
        "source_branch_profile": source_branches,
        "commercial_pseudocode_lines": int(
            features.get("pseudocode_nonempty_line_count") or 0
        ),
        "commercial_instruction_count": commercial_size,
        "source_structure_size": source_size,
        "retrieval_exact_binary_evidence": {
            "exact_body": round(exact_compiled_body, 6),
            "exact_structural": round(exact_compiled_structure, 6),
            "instruction_overlap": round(compiled_instruction_overlap, 6),
        },
    }
    return round(score, 6), detail, signals


def _relationship(
    lane: str,
    signals: list[str],
    score: float,
    detail: dict[str, Any],
    candidate: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Apply conservative claim gates after the numerical reranking step."""

    exact_compiled = {
        "exact_compiled_body",
        "exact_compiled_structure",
        "compiled_instruction_overlap",
    }.intersection(signals)
    independent_signal_families: set[str] = set()
    if exact_compiled:
        independent_signal_families.add("compiled_identity")
    signal_families = {
        "exact_distinctive_string": "distinctive_string",
        "distinctive_constant_bundle": "distinctive_constant",
        "call_pattern": "call_pattern",
        "control_flow_profile": "control_flow",
    }
    independent_signal_families.update(
        family for signal, family in signal_families.items() if signal in signals
    )
    supporting_signals = {
        "semantic_operation",
        "compatible_structure_scale",
    }.intersection(signals)
    commercial = candidate.get("commercial") or {}
    ownership = commercial.get("ownership") or {}
    ownership_category = str(ownership.get("category") or "unknown")
    available_weight = float(detail.get("available_weight") or 0)
    commercial_lines = int(detail.get("commercial_pseudocode_lines") or 0)
    source_size = int(detail.get("source_structure_size") or 0)
    semantic_token_count = len(detail.get("matched_semantic_tokens") or [])
    exact_usage_evidence = bool(exact_compiled) and score >= 0.25
    corroborated_usage_evidence = bool(
        available_weight >= 0.40
        and commercial_lines >= 5
        and source_size >= 2
        and score >= 0.60
        and independent_signal_families
        and supporting_signals
        and semantic_token_count >= 3
    )
    adaptation_evidence = bool(
        (bool(exact_compiled) or (
            available_weight >= 0.35
            and commercial_lines >= 5
            and source_size >= 5
        ))
        and score >= 0.45
        and len(independent_signal_families) >= 2
        and ownership_category not in {"platform", "third_party"}
    )
    reasons: list[str] = []
    if lane == "usage":
        if not exact_usage_evidence and not corroborated_usage_evidence:
            if available_weight < 0.40:
                reasons.append("insufficient_comparable_evidence_weight")
            if commercial_lines < 5 or source_size < 2:
                reasons.append("function_body_too_small_for_usage_review")
            if score < 0.60:
                reasons.append("deep_score_below_usage_review_threshold")
            if not independent_signal_families:
                reasons.append("missing_independent_usage_signal")
            if not supporting_signals:
                reasons.append("missing_supporting_usage_signal")
            if semantic_token_count < 3:
                reasons.append("insufficient_specific_semantic_overlap")
    elif lane == "adaptation":
        if available_weight < 0.35 and not exact_compiled:
            reasons.append("insufficient_comparable_evidence_weight")
        if (commercial_lines < 5 or source_size < 5) and not exact_compiled:
            reasons.append("function_body_too_small_for_nonexact_claim")
        if ownership_category in {"platform", "third_party"}:
            reasons.append("commercial_function_not_proprietary_eligible")
        if score < 0.45:
            reasons.append("deep_score_below_review_threshold")
        if len(independent_signal_families) < 2:
            reasons.append("fewer_than_two_independent_signal_families")
    else:
        reasons.append("control_lane_is_not_claim_eligible")

    gate = {
        "eligible": not reasons,
        "reasons": reasons,
        "independent_signal_families": sorted(independent_signal_families),
        "independent_signal_family_count": len(independent_signal_families),
        "supporting_signals": sorted(supporting_signals),
        "available_weight": round(available_weight, 6),
        "commercial_ownership_category": ownership_category,
        "exact_compiled_identity_present": bool(exact_compiled),
        "gate_profile": lane,
        "exact_usage_evidence": exact_usage_evidence,
        "corroborated_usage_evidence": corroborated_usage_evidence,
        "adaptation_evidence": adaptation_evidence,
        "matched_semantic_token_count": semantic_token_count,
    }
    if reasons:
        return "insufficient_deep_evidence", gate
    if lane == "usage":
        return "open_source_or_external_usage_candidate", gate
    if lane == "adaptation" and adaptation_evidence:
        return "open_source_implementation_match_candidate", gate
    return "control_match_candidate", gate


def compare_decompiled_candidates(
    decompile_result: dict[str, Any],
    candidate_path: Path,
    source_index_paths: Iterable[Path],
    output_path: Path,
    summary_path: Path,
    *,
    max_candidates_per_function: int = 20,
    canonical_mapping_path: Path | None = None,
) -> dict[str, Any]:
    """Rerank candidates against the substantive body reached from each seed."""

    source_index_paths = [Path(path) for path in source_index_paths]
    all_source_rows = _load_all_source_rows(source_index_paths)
    source_rows_by_identity = {
        _source_identity(row): row for row in all_source_rows
    }
    source_name_index: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    source_string_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in all_source_rows:
        key = _function_name_key(row.get("function_name") or row.get("name"))
        if key:
            source_name_index[key].append(row)
        for value in _normalized_strings(row.get("strings") or []):
            source_string_index[value].append(row)

    all_results = [
        result
        for result in decompile_result.get("results") or []
        if isinstance(result, dict)
    ]
    result_by_identity = {
        _result_identity(result): result
        for result in all_results
        if all(_result_identity(result))
    }
    origin_results: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in all_results:
        origin_pair_id = _origin_pair_id(result)
        if origin_pair_id:
            origin_results[origin_pair_id].append(result)

    seed_results: list[
        tuple[dict[str, Any], str, dict[str, Any], tuple[str, str]]
    ] = []
    commercial_ids: set[str] = set()
    commercial_identities: set[tuple[str, str]] = set()
    for result in all_results:
        commercial_id, raw_seed_candidate = _decompiled_seed(result)
        target = result.get("target") or {}
        identity = _commercial_identity(target)
        if not commercial_id and not all(identity):
            continue
        seed_candidate = (
            _normalized_seed_candidate(
                result,
                commercial_id,
                raw_seed_candidate,
            )
            if raw_seed_candidate
            else {}
        )
        seed_results.append(
            (result, commercial_id, seed_candidate, identity)
        )
        if commercial_id:
            commercial_ids.add(commercial_id)
        if all(identity):
            commercial_identities.add(identity)

    candidate_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    candidate_ids_by_identity: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in _iter_jsonl(candidate_path):
        commercial = row.get("commercial") or {}
        commercial_id = str(commercial.get("function_id") or "")
        identity = _commercial_identity(commercial)
        if (
            commercial_id not in commercial_ids
            and identity not in commercial_identities
        ):
            continue
        if not commercial_id:
            continue
        candidate_rows[commercial_id].append(row)
        if all(identity):
            candidate_ids_by_identity[identity].add(commercial_id)
    for rows in candidate_rows.values():
        rows.sort(key=lambda row: -float(row.get("selection_score") or row.get("retrieval_score") or 0))
        del rows[max_candidates_per_function:]

    successful: list[
        tuple[
            dict[str, Any],
            dict[str, Any],
            str,
            list[tuple[dict[str, Any], str]],
            dict[str, Any],
        ]
    ] = []
    canonical_mappings: list[dict[str, Any]] = []
    source_family_expansion_count = 0
    for seed_result, commercial_id, seed_candidate, identity in seed_results:
        resolved_ids = (
            [commercial_id]
            if commercial_id
            else sorted(candidate_ids_by_identity.get(identity) or [])
        )
        for resolved_id in resolved_ids:
            supplementary = list(candidate_rows.get(resolved_id) or [])
            seed_candidate_for_id = dict(seed_candidate)
            if not seed_candidate_for_id:
                if not supplementary:
                    continue
                seed_candidate_for_id = _normalized_seed_candidate(
                    seed_result,
                    resolved_id,
                    supplementary.pop(0),
                )
            pair_id = _candidate_pair_id(seed_candidate_for_id)
            canonical_result, canonical_resolution = _resolve_canonical_implementation(
                seed_result,
                pair_id,
                result_by_identity,
                origin_results,
            )
            if canonical_result.get("success") is not True:
                continue
            canonical_resolution["commercial_function_id"] = resolved_id
            canonical_resolution["selected_seed_analysis_lane"] = _normalized_lane(
                seed_candidate_for_id.get("analysis_lane")
            )
            unresolved_wrapper = bool(
                (canonical_resolution.get("seed") or {}).get("wrapper_like")
                and not canonical_resolution.get("resolved_away_from_seed")
            )
            canonical_resolution["comparison_claim_eligible"] = not unresolved_wrapper
            if unresolved_wrapper:
                canonical_resolution["comparison_boundary"] = (
                    "The saved body is an unresolved wrapper or import trampoline. "
                    "It remains in the audit trail but cannot support source-family "
                    "expansion or an implementation claim."
                )
            canonical_mappings.append(canonical_resolution)
            candidates: list[tuple[dict[str, Any], str]] = []
            seed_source_identity = _source_identity(
                seed_candidate_for_id.get("source") or {}
            )
            matching_supplement = next(
                (
                    row
                    for row in supplementary
                    if _source_identity(row.get("source") or {})
                    == seed_source_identity
                ),
                None,
            )
            authoritative = (
                _merge_candidate_metadata(seed_candidate_for_id, matching_supplement)
                if matching_supplement is not None
                else seed_candidate_for_id
            )
            candidates.append((authoritative, "selected_ida_seed"))
            supplementary = [
                row
                for row in supplementary
                if _source_identity(row.get("source") or {})
                != seed_source_identity
            ]

            expansions = (
                []
                if unresolved_wrapper
                else _source_family_expansions(
                    canonical_result,
                    seed_result,
                    source_name_index,
                    source_string_index,
                    limit=max_candidates_per_function,
                )
            )
            existing_source_identities = {
                _source_identity(candidate.get("source") or {})
                for candidate, _origin in candidates
            }
            for candidate in expansions:
                source_identity = _source_identity(candidate.get("source") or {})
                if source_identity in existing_source_identities:
                    continue
                candidate["commercial_function_id"] = resolved_id
                candidate["commercial"] = dict(
                    authoritative.get("commercial") or {}
                )
                candidate["candidate_pair_id"] = _candidate_pair_id(candidate)
                candidates.append((candidate, "post_ida_source_family_expansion"))
                existing_source_identities.add(source_identity)
                source_family_expansion_count += 1
                if len(candidates) >= max_candidates_per_function:
                    break
            for row in supplementary:
                if len(candidates) >= max_candidates_per_function:
                    break
                source_identity = _source_identity(row.get("source") or {})
                if source_identity in existing_source_identities:
                    continue
                candidates.append((row, "supplemental_review_candidate"))
                existing_source_identities.add(source_identity)

            normalized_candidates: list[tuple[dict[str, Any], str]] = []
            for candidate, origin in candidates:
                normalized = dict(candidate)
                source_summary = dict(candidate.get("source") or {})
                source_summary.update(
                    source_rows_by_identity.get(_source_identity(source_summary), {})
                )
                source = annotate_source_policy(source_summary)
                source_id = _source_function_id(source)
                source["function_id"] = source_id
                normalized["source"] = source
                normalized["source_function_id"] = source_id
                normalized["commercial_function_id"] = resolved_id
                normalized["commercial"] = {
                    **(candidate.get("commercial") or {}),
                    "function_id": resolved_id,
                }
                declared_lane = _normalized_lane(
                    candidate.get("analysis_lane")
                )
                normalized["retrieval_analysis_lane"] = declared_lane
                normalized["canonical_comparison_claim_eligible"] = (
                    not unresolved_wrapper
                )
                if unresolved_wrapper:
                    normalized["analysis_lane"] = "control"
                else:
                    normalized["analysis_lane"] = (
                        declared_lane
                        if origin == "selected_ida_seed" and declared_lane == "usage"
                        else source_analysis_lane(source)
                    )
                normalized["source_project"] = (
                    candidate.get("source_project")
                    or source.get("repository_full_name")
                    or source.get("corpus_id")
                )
                if origin != "selected_ida_seed":
                    normalized["candidate_pair_id"] = _candidate_pair_id(normalized)
                normalized_candidates.append((normalized, origin))

            successful.append(
                (
                    canonical_result,
                    seed_result,
                    resolved_id,
                    normalized_candidates,
                    canonical_resolution,
                )
            )
            commercial_ids.add(resolved_id)

    canonical_mapping_path = canonical_mapping_path or (
        summary_path.parent / "reuse_canonical_implementations.jsonl"
    )
    _write_jsonl(canonical_mapping_path, canonical_mappings)
    comparisons: list[dict[str, Any]] = []
    missing_candidate_count = 0
    selected_seed_lanes: dict[str, str] = {}
    compared_seed_lanes: dict[str, str] = {}
    for _canonical, _seed, _commercial_id, candidates, _resolution in successful:
        for candidate, origin in candidates:
            if origin != "selected_ida_seed":
                continue
            pair_id = _candidate_pair_id(candidate)
            if pair_id:
                selected_seed_lanes[pair_id] = _normalized_lane(
                    candidate.get("analysis_lane")
                )
    for canonical_result, seed_result, commercial_id, candidates, resolution in successful:
        if not candidates:
            missing_candidate_count += 1
            continue
        for candidate, candidate_origin in candidates:
            source = dict(candidate.get("source") or {})
            source_summary = source
            score, detail, signals = _comparison_features(
                canonical_result,
                source,
                candidate,
            )
            lane = _normalized_lane(candidate.get("analysis_lane"))
            relationship, review_gate = _relationship(
                lane,
                signals,
                score,
                detail,
                candidate,
            )
            target = canonical_result.get("target") or {}
            seed_target = seed_result.get("target") or {}
            pair_id = _candidate_pair_id(candidate)
            if candidate_origin == "selected_ida_seed" and pair_id:
                compared_seed_lanes[pair_id] = lane
            comparisons.append(
                {
                    "schema_version": DEEP_COMPARISON_SCHEMA,
                    "comparison_id": stable_id(
                        commercial_id,
                        str(candidate.get("source_function_id") or ""),
                        str(target.get("address") or ""),
                        str(canonical_result.get("pseudocode_sha256") or ""),
                    ),
                    "candidate_pair_id": pair_id,
                    "candidate_origin": candidate_origin,
                    "commercial_function_id": commercial_id,
                    "source_function_id": candidate.get("source_function_id"),
                    "analysis_lane": lane,
                    "deep_comparison_score": score,
                    "independent_signal_count": review_gate.get(
                        "independent_signal_family_count", 0
                    ),
                    "independent_signals": signals,
                    "review_gate": review_gate,
                    "relationship_assessment": relationship,
                    "commercial": {
                        **(candidate.get("commercial") or {}),
                        "decompiled_name": target.get("name"),
                        "decompiled_address": target.get("address"),
                        "pseudocode_path": canonical_result.get("output_path"),
                        "pseudocode_sha256": canonical_result.get("pseudocode_sha256"),
                        "selection_source": target.get("selection_source"),
                    },
                    "seed_commercial": {
                        **(candidate.get("commercial") or {}),
                        "decompiled_name": seed_target.get("name"),
                        "decompiled_address": seed_target.get("address"),
                        "selection_source": seed_target.get("selection_source"),
                    },
                    "canonical_implementation": resolution.get("canonical") or {},
                    "canonical_resolution": resolution,
                    "source": {
                        **source_summary,
                        "name": source.get("name") or source_summary.get("name"),
                        "function_name": source.get("function_name")
                        or source_summary.get("function_name"),
                    },
                    "source_family": _source_family(source),
                    "source_project": candidate.get("source_project")
                    or source_summary.get("repository_full_name")
                    or source_summary.get("corpus_id"),
                    "retrieval_score": candidate.get("retrieval_score"),
                    "retrieval_components": candidate.get("components") or {},
                    "source_family_expansion": candidate.get(
                        "source_family_expansion"
                    )
                    or {},
                    "deep_components": detail,
                    "claim_eligibility": {
                        "usage_review": relationship
                        == "open_source_or_external_usage_candidate",
                        "adaptation_review": relationship
                        == "open_source_implementation_match_candidate",
                        "copying_conclusion": False,
                    },
                    "conclusion_boundary": (
                        "This is a post-decompilation research candidate, not a copying "
                        "probability. Attribution and independent corroboration remain required."
                    ),
                }
            )

    comparisons.sort(
        key=lambda row: (
            -float(row.get("deep_comparison_score") or 0),
            -int(row.get("independent_signal_count") or 0),
            str(row.get("commercial_function_id") or ""),
        )
    )
    family_members: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in comparisons:
        canonical = row.get("canonical_implementation") or {}
        canonical_key = ":".join(
            (
                str(canonical.get("library_sha256") or ""),
                _canonical_address(canonical.get("address")),
            )
        ).strip(":")
        if not canonical_key:
            canonical_key = str(row.get("commercial_function_id") or "")
        family_members[(canonical_key, str(row.get("source_family")))].append(row)
    family_rows: list[dict[str, Any]] = []
    for members in family_members.values():
        representative = dict(
            max(
                members,
                key=lambda member: (
                    float(member.get("deep_comparison_score") or 0),
                    int(member.get("independent_signal_count") or 0),
                    member.get("candidate_origin") == "selected_ida_seed",
                ),
            )
        )
        representative["source_family_members"] = sorted(
            {
                str(member.get("source_project") or "unknown_project")
                for member in members
            }
        )
        representative["source_family_variants"] = sorted(
            (
                {
                    "source_project": member.get("source_project"),
                    "function_id": member.get("source_function_id"),
                    "commit_sha": (member.get("source") or {}).get("commit_sha"),
                    "build_variant": (member.get("source") or {}).get(
                        "build_variant"
                    ),
                    "abi": (member.get("source") or {}).get("abi"),
                    "candidate_pair_id": member.get("candidate_pair_id"),
                    "candidate_origin": member.get("candidate_origin"),
                }
                for member in members
            ),
            key=lambda value: (
                str(value.get("source_project") or ""),
                str(value.get("commit_sha") or ""),
                str(value.get("build_variant") or ""),
                str(value.get("abi") or ""),
                str(value.get("function_id") or ""),
            ),
        )
        seed_variants: dict[str, dict[str, Any]] = {}
        for member in members:
            seed = member.get("seed_commercial") or {}
            pair_id = str(member.get("candidate_pair_id") or "")
            key = pair_id or ":".join(
                (
                    str(member.get("commercial_function_id") or ""),
                    _canonical_address(seed.get("decompiled_address") or seed.get("address")),
                )
            )
            seed_variants[key] = {
                "candidate_pair_id": member.get("candidate_pair_id"),
                "commercial_function_id": member.get("commercial_function_id"),
                "name": seed.get("decompiled_name") or seed.get("name"),
                "address": seed.get("decompiled_address") or seed.get("address"),
                "analysis_lane": member.get("analysis_lane"),
            }
        representative["commercial_seed_variants"] = sorted(
            seed_variants.values(),
            key=lambda value: (
                str(value.get("name") or ""),
                str(value.get("address") or ""),
                str(value.get("candidate_pair_id") or ""),
            ),
        )
        representative["commercial_seed_count"] = len(seed_variants)
        representative["source_family_member_count"] = len(members)
        family_rows.append(representative)
    family_rows.sort(
        key=lambda row: (
            -float(row.get("deep_comparison_score") or 0),
            -int(row.get("independent_signal_count") or 0),
        )
    )
    row_count = _write_jsonl(output_path, family_rows)
    relationships = Counter(str(row.get("relationship_assessment")) for row in family_rows)
    lanes = Counter(str(row.get("analysis_lane")) for row in family_rows)
    missing_seed_pair_ids = sorted(
        set(selected_seed_lanes).difference(compared_seed_lanes)
    )
    lane_mismatches = sorted(
        pair_id
        for pair_id in set(selected_seed_lanes).intersection(compared_seed_lanes)
        if selected_seed_lanes[pair_id] != compared_seed_lanes[pair_id]
    )
    null_candidate_pair_id_count = sum(
        not str(row.get("candidate_pair_id") or "") for row in comparisons
    )
    incomplete_source_metadata_count = sum(
        not str(row.get("source_function_id") or "")
        or not str(row.get("source_project") or "")
        for row in comparisons
    )
    incomplete_commercial_metadata_count = sum(
        not str(row.get("commercial_function_id") or "")
        or not str((row.get("commercial") or {}).get("library_sha256") or "")
        or not str(
            (row.get("commercial") or {}).get("decompiled_address")
            or (row.get("commercial") or {}).get("address")
            or ""
        )
        for row in comparisons
    )
    metadata_integrity_status = (
        "passed"
        if not missing_seed_pair_ids
        and not lane_mismatches
        and not null_candidate_pair_id_count
        and not incomplete_source_metadata_count
        and not incomplete_commercial_metadata_count
        else "failed"
    )
    summary = {
        "schema_version": DEEP_COMPARISON_SCHEMA,
        "status": "completed",
        "successful_candidate_seed_result_count": len(successful),
        "successful_decompilation_result_count": sum(
            result.get("success") is True for result in all_results
        ),
        "identity_fallback_resolution_count": sum(
            1
            for _result, commercial_id, _candidate, identity in seed_results
            if not commercial_id and candidate_ids_by_identity.get(identity)
        ),
        "commercial_function_count": len(commercial_ids),
        "comparison_pair_count": len(comparisons),
        "source_family_comparison_count": row_count,
        "collapsed_duplicate_source_count": max(0, len(comparisons) - row_count),
        "missing_candidate_count": missing_candidate_count,
        "selected_seed_pair_id_count": len(selected_seed_lanes),
        "compared_seed_pair_id_count": len(compared_seed_lanes),
        "missing_seed_pair_ids": missing_seed_pair_ids,
        "lane_mismatch_pair_ids": lane_mismatches,
        "null_candidate_pair_id_count": null_candidate_pair_id_count,
        "incomplete_source_metadata_count": incomplete_source_metadata_count,
        "incomplete_commercial_metadata_count": (
            incomplete_commercial_metadata_count
        ),
        "selected_seed_lane_counts": dict(
            sorted(Counter(selected_seed_lanes.values()).items())
        ),
        "compared_seed_lane_counts": dict(
            sorted(Counter(compared_seed_lanes.values()).items())
        ),
        "metadata_integrity_status": metadata_integrity_status,
        "canonical_mapping_path": str(canonical_mapping_path),
        "canonical_seed_count": len(canonical_mappings),
        "canonical_resolution_count": sum(
            bool(row.get("resolved_away_from_seed")) for row in canonical_mappings
        ),
        "canonical_implementation_count": len(
            {
                (
                    str((row.get("canonical") or {}).get("library_sha256") or ""),
                    _canonical_address((row.get("canonical") or {}).get("address")),
                )
                for row in canonical_mappings
            }
        ),
        "wrapper_seed_count": sum(
            bool((row.get("seed") or {}).get("wrapper_like"))
            for row in canonical_mappings
        ),
        "resolved_wrapper_seed_count": sum(
            bool((row.get("seed") or {}).get("wrapper_like"))
            and bool(row.get("resolved_away_from_seed"))
            for row in canonical_mappings
        ),
        "unresolved_wrapper_seed_count": sum(
            bool((row.get("seed") or {}).get("wrapper_like"))
            and not bool(row.get("resolved_away_from_seed"))
            for row in canonical_mappings
        ),
        "claim_eligible_wrapper_seed_count": sum(
            bool((row.get("seed") or {}).get("wrapper_like"))
            and row.get("selected_seed_analysis_lane") in {"usage", "adaptation"}
            and bool(row.get("comparison_claim_eligible"))
            for row in canonical_mappings
        ),
        "unresolved_claim_eligible_wrapper_seed_count": sum(
            bool((row.get("seed") or {}).get("wrapper_like"))
            and row.get("selected_seed_analysis_lane") in {"usage", "adaptation"}
            and not bool(row.get("resolved_away_from_seed"))
            and bool(row.get("comparison_claim_eligible"))
            for row in canonical_mappings
        ),
        "suppressed_unresolved_claim_lane_wrapper_seed_count": sum(
            bool((row.get("seed") or {}).get("wrapper_like"))
            and row.get("selected_seed_analysis_lane") in {"usage", "adaptation"}
            and not bool(row.get("comparison_claim_eligible"))
            for row in canonical_mappings
        ),
        "source_family_expansion_candidate_count": source_family_expansion_count,
        "source_corpus_function_count": len(all_source_rows),
        "relationship_counts": dict(sorted(relationships.items())),
        "analysis_lane_counts": dict(sorted(lanes.items())),
        "usage_review_ready_count": sum(
            bool((row.get("claim_eligibility") or {}).get("usage_review"))
            for row in family_rows
        ),
        "adaptation_review_ready_count": sum(
            bool((row.get("claim_eligibility") or {}).get("adaptation_review"))
            for row in family_rows
        ),
        "review_ready_project_count": len(
            {
                str(row.get("source_project") or "")
                for row in family_rows
                if (
                    (row.get("claim_eligibility") or {}).get("usage_review")
                    or (row.get("claim_eligibility") or {}).get(
                        "adaptation_review"
                    )
                )
                and row.get("source_project")
            }
        ),
        "copying_conclusion_supported": False,
        "comparison_path": str(output_path),
        "conclusion_boundary": (
            "Deep comparison ranks evidence for human or LLM review. It does not by "
            "itself establish copying, direction, intent, or license noncompliance."
        ),
    }
    safe_write_json(summary_path, summary)
    return summary
