"""Candidate retrieval between APK function indexes and frozen OSS source indexes."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Callable, Iterable, TextIO

from .function_fingerprint import (
    counter_cosine,
    identifier_tokens,
    jaccard,
    size_similarity,
    stable_id,
)
from .source_candidate_policy import (
    annotate_source_policy,
    source_analysis_lane,
)
from .source_provenance import canonical_source_project
from .utils import safe_write_json


RETRIEVAL_SCHEMA = "2026-08-25.reuse-candidate-retrieval.v7"
SELECTION_SCHEMA = "2026-08-25.reuse-candidate-selection.v2"
DEEP_COMPARISON_CANDIDATE_ROLES = {None, "upstream_candidate", "method_control"}
PRIMARY_ANALYSIS_LANES = ("adaptation", "usage")
ANALYSIS_LANES = (*PRIMARY_ANALYSIS_LANES, "control")
REPRESENTATION_GROUPS = ("native", "managed")
REVIEW_BUCKET_WEIGHTS = {
    "adaptation_native": 0.25,
    "usage_native": 0.20,
    "adaptation_managed": 0.25,
    "usage_managed": 0.20,
    "control_native": 0.05,
    "control_managed": 0.05,
}
NATIVE_TARGET_LANE_WEIGHTS = {
    "adaptation": 0.45,
    "usage": 0.45,
    "control": 0.10,
}
GENERIC_FUNCTION_TOKENS = {
    "add",
    "begin",
    "clear",
    "clone",
    "compare",
    "create",
    "delete",
    "destroy",
    "empty",
    "end",
    "equals",
    "free",
    "fclose",
    "fgets",
    "fopen",
    "fread",
    "fwrite",
    "get",
    "hash",
    "hashcode",
    "init",
    "length",
    "malloc",
    "memcmp",
    "memcpy",
    "memmove",
    "memset",
    "new",
    "nullsub",
    "operator",
    "remove",
    "snprintf",
    "sprintf",
    "strcmp",
    "strcpy",
    "strlen",
    "strncmp",
    "set",
    "size",
    "sub",
    "tostring",
    "update",
}
MANAGED_GENERIC_METHOD_NAMES = {
    "clone",
    "compareto",
    "equals",
    "finalize",
    "getclass",
    "hashcode",
    "tostring",
}
MANAGED_GENERATED_METHOD_RE = re.compile(
    r"^(?:access\$\d+|component\d+|copy\$default|lambda\$.*|.*\$default)$",
    re.IGNORECASE,
)
MANAGED_ACCESSOR_METHOD_RE = re.compile(
    r"^(?:get|set|is|has)[A-Z_][A-Za-z0-9_$]*$"
)
ProgressCallback = Callable[[dict[str, Any]], None]


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value

def _signature_hashes(value: object) -> set[str]:
    if not isinstance(value, dict):
        return set()
    return {str(item) for item in value.get("hashes") or [] if item}


def _source_features(row: dict[str, Any]) -> dict[str, Any]:
    representation = str(row.get("representation") or "source_code_function")
    if representation != "source_code_function":
        return {
            "representation": representation,
            "semantic": set(
                row.get("semantic_tokens")
                or identifier_tokens(row.get("name") or row.get("function_name") or "")
            ),
            "calls": set(
                row.get("call_tokens")
                or identifier_tokens(row.get("call_targets") or [])
            ),
            "strings": set(
                row.get("string_tokens")
                or identifier_tokens(row.get("string_refs") or row.get("strings") or [])
            ),
            "capabilities": {
                str(value) for value in row.get("capabilities") or [] if value
            },
            "branches": Counter(
                {
                    str(key): int(value or 0)
                    for key, value in (row.get("branch_counts") or {}).items()
                }
            ),
            "cfg": Counter(
                {
                    str(key): int(value or 0)
                    for key, value in (row.get("cfg_counts") or {}).items()
                }
            ),
            "size": int(
                row.get("size_measure")
                or row.get("instruction_count")
                or row.get("size_bytes")
                or 0
            ),
            "instruction_hashes": _signature_hashes(
                row.get("instruction_signature")
            ),
            "source_shingles": _signature_hashes(
                row.get("token_shingle_signature")
            ),
            "structural_sha256": str(row.get("structural_sha256") or ""),
            "body_sha256": str(row.get("body_sha256") or ""),
        }
    calls = [
        str(item.get("name") or "")
        for item in row.get("top_calls") or []
        if isinstance(item, dict)
    ]
    return {
        "representation": "source_code_function",
        "semantic": set(
            identifier_tokens(
                [
                    row.get("function_name"),
                    Path(str(row.get("source_path") or "")).stem,
                    *(row.get("capabilities") or []),
                ]
            )
        ),
        "calls": set(identifier_tokens(calls)),
        "strings": set(identifier_tokens(row.get("strings") or [])),
        "capabilities": {str(value) for value in row.get("capabilities") or [] if value},
        "branches": Counter(
            {
                str(key): int(value or 0)
                for key, value in (row.get("branch_counts") or {}).items()
            }
        ),
        "cfg": Counter(
            {
                str(key): int(value or 0)
                for key, value in (row.get("cfg_counts") or {}).items()
            }
        ),
        "size": int(row.get("structure_token_count") or row.get("line_count") or 0),
        "instruction_hashes": set(),
        "source_shingles": _signature_hashes(row.get("token_shingle_signature")),
        "structural_sha256": str(row.get("structural_sha256") or ""),
        "body_sha256": str(row.get("body_sha256") or ""),
    }


def _commercial_features(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "representation": str(row.get("representation") or "unknown"),
        "semantic": set(row.get("semantic_tokens") or identifier_tokens(row.get("name") or "")),
        "calls": set(row.get("call_tokens") or identifier_tokens(row.get("call_targets") or [])),
        "strings": set(row.get("string_tokens") or identifier_tokens(row.get("string_refs") or [])),
        "capabilities": {str(value) for value in row.get("capabilities") or [] if value},
        "branches": Counter(
            {
                str(key): int(value or 0)
                for key, value in (row.get("branch_counts") or {}).items()
            }
        ),
        "cfg": Counter(
            {
                str(key): int(value or 0)
                for key, value in (row.get("cfg_counts") or {}).items()
            }
        ),
        "size": int(
            row.get("size_measure")
            or row.get("instruction_count")
            or row.get("line_count")
            or row.get("size_bytes")
            or 0
        ),
        "instruction_hashes": _signature_hashes(
            row.get("instruction_signature")
        ),
        "source_shingles": _signature_hashes(
            row.get("token_shingle_signature")
        ),
        "structural_sha256": str(row.get("structural_sha256") or ""),
        "body_sha256": str(row.get("body_sha256") or ""),
    }


def _representations_comparable(left: str, right: str) -> tuple[bool, bool, bool]:
    source = {"jadx_source_method", "source_code_function"}
    dex = {"dex_bytecode_method", "oss_compiled_dex_method"}
    native = {"ida_lightweight_inventory", "oss_compiled_binary_function"}
    return (
        left in source and right in source,
        left in dex and right in dex,
        left in native and right in native,
    )


def _score(
    left: dict[str, Any],
    right: dict[str, Any],
) -> tuple[float, dict[str, float], list[str]]:
    components = {
        "semantic": jaccard(left["semantic"], right["semantic"]),
        "calls": jaccard(left["calls"], right["calls"]),
        "strings": jaccard(left["strings"], right["strings"]),
        "capabilities": jaccard(left["capabilities"], right["capabilities"]),
        "branches": counter_cosine(left["branches"], right["branches"]),
        "cfg": counter_cosine(left["cfg"], right["cfg"]),
        "size": size_similarity(left["size"], right["size"]),
        "instruction": jaccard(
            left["instruction_hashes"], right["instruction_hashes"]
        ),
        "source_shingles": jaccard(
            left["source_shingles"], right["source_shingles"]
        ),
        "exact_body": float(
            bool(left["body_sha256"])
            and left["body_sha256"] == right["body_sha256"]
        ),
        "exact_structural": float(
            bool(left["structural_sha256"])
            and left["structural_sha256"] == right["structural_sha256"]
        ),
    }
    available_weights = {
        "semantic": 0.34,
        "calls": 0.22,
        "strings": 0.12,
        "capabilities": 0.14,
        "branches": 0.08,
        "cfg": 0.14,
        "size": 0.06,
        "instruction": 0.30,
        "source_shingles": 0.25,
        "exact_body": 0.45,
        "exact_structural": 0.25,
    }
    source_comparable, dex_comparable, native_comparable = _representations_comparable(
        left["representation"], right["representation"]
    )
    structural_comparable = source_comparable or dex_comparable or native_comparable
    usable = {
        key: weight
        for key, weight in available_weights.items()
        if (
            key in {"semantic", "calls", "strings", "capabilities"}
            and left[key]
            and right[key]
        )
        or (
            key == "branches"
            and structural_comparable
            and left["branches"]
            and right["branches"]
        )
        or (
            key == "cfg"
            and structural_comparable
            and left["cfg"]
            and right["cfg"]
        )
        or (
            key == "size"
            and structural_comparable
            and left["size"]
            and right["size"]
        )
        or (
            key == "instruction"
            and (dex_comparable or native_comparable)
            and left["instruction_hashes"]
            and right["instruction_hashes"]
        )
        or (
            key == "source_shingles"
            and source_comparable
            and left["source_shingles"]
            and right["source_shingles"]
        )
        or (
            key == "exact_body"
            and source_comparable
            and components["exact_body"] > 0
        )
        or (
            key == "exact_structural"
            and structural_comparable
            and components["exact_structural"] > 0
        )
    }
    denominator = sum(usable.values()) or 1.0
    score = sum(components[key] * weight for key, weight in usable.items()) / denominator
    return (
        score,
        {key: round(value, 6) for key, value in components.items()},
        sorted(usable),
    )


def _evidence_sufficiency(
    left: dict[str, Any],
    right: dict[str, Any],
    components: dict[str, float],
) -> dict[str, Any]:
    """Flag trivial exact matches without discarding them from the full index."""

    source_comparable, dex_comparable, native_comparable = _representations_comparable(
        left["representation"], right["representation"]
    )
    structurally_comparable = source_comparable or dex_comparable or native_comparable
    comparable_sizes = [
        int(value)
        for value in (left.get("size"), right.get("size"))
        if int(value or 0) > 0
    ]
    minimum_size = min(comparable_sizes) if structurally_comparable and comparable_sizes else None
    signal_thresholds = {
        "semantic": 0.50,
        "calls": 0.30,
        "strings": 0.20,
        "capabilities": 0.50,
        "instruction": 0.20,
        "source_shingles": 0.20,
        "exact_body": 1.0,
        "exact_structural": 1.0,
    }
    signals = sorted(
        key
        for key, threshold in signal_thresholds.items()
        if float(components.get(key) or 0) >= threshold
    )
    content_signals = set(signals).intersection(
        {"strings", "capabilities", "instruction", "source_shingles"}
    )
    trivial_exact_match = bool(
        structurally_comparable
        and minimum_size is not None
        and minimum_size <= 6
        and (
            components.get("exact_body", 0) > 0
            or components.get("exact_structural", 0) > 0
        )
        and not content_signals
    )
    if trivial_exact_match:
        return {
            "level": "low",
            "deep_comparison_eligible": False,
            "signal_count": len(signals),
            "signals": signals,
            "minimum_comparable_size": minimum_size,
            "reason": (
                "Exact or structural overlap is confined to a very small function "
                "without distinctive strings, capabilities, or instruction shingles."
            ),
        }
    high_information = bool(
        minimum_size is not None
        and minimum_size >= 20
        and len(signals) >= 3
        and content_signals
    )
    return {
        "level": "high" if high_information else "medium",
        "deep_comparison_eligible": True,
        "signal_count": len(signals),
        "signals": signals,
        "minimum_comparable_size": minimum_size,
        "reason": (
            "Multiple representation-compatible signals support deeper comparison."
            if high_information
            else "Candidate is retained for retrieval and may be enriched by deeper comparison."
        ),
    }


def _posting_tokens(features: dict[str, Any]) -> set[str]:
    tokens = features["semantic"] | features["calls"] | features["strings"]
    tokens |= {
        f"instruction:{value}" for value in features["instruction_hashes"]
    }
    tokens |= {
        f"source_shingle:{value}" for value in features["source_shingles"]
    }
    if features["body_sha256"]:
        tokens.add(f"body:{features['body_sha256']}")
    if features["structural_sha256"]:
        tokens.add(f"structural:{features['structural_sha256']}")
    return tokens


def _source_project_key(row: dict[str, Any]) -> str:
    return canonical_source_project(row)


def _representation_relation(left: str, right: str) -> str | None:
    source_comparable, dex_comparable, native_comparable = (
        _representations_comparable(left, right)
    )
    if source_comparable or dex_comparable or native_comparable:
        return "representation_compatible"
    source = {"jadx_source_method", "source_code_function"}
    compiled = {
        "dex_bytecode_method",
        "oss_compiled_dex_method",
        "ida_lightweight_inventory",
        "oss_compiled_binary_function",
    }
    if (left in source and right in compiled) or (
        right in source and left in compiled
    ):
        return "semantic_bridge"
    return None


def _logical_source_function_key(row: dict[str, Any]) -> tuple[str, ...]:
    representation = str(row.get("representation") or "source_code_function")
    if representation == "source_code_function":
        return (
            _source_project_key(row),
            str(row.get("commit_sha") or ""),
            str(row.get("source_path") or ""),
            str(row.get("start_line") or ""),
            str(row.get("function_name") or row.get("name") or ""),
        )
    name = str(row.get("function_name") or row.get("name") or "")
    source_path = str(row.get("source_path") or "")
    structural_hash = str(row.get("structural_sha256") or "")
    if source_path and name and not name.startswith(("sub_", "loc_", "nullsub_")):
        identity = (source_path, name)
    elif structural_hash:
        identity = ("structural", structural_hash)
    else:
        # Stripped functions cannot be safely merged across builds without a
        # representation-independent identity, so preserve them separately.
        identity = (
            "compiled",
            str(row.get("function_id") or ""),
        )
    return (
        _source_project_key(row),
        str(row.get("commit_sha") or ""),
        *identity,
    )


def _cross_representation_signal_count(components: dict[str, float]) -> int:
    return sum(
        float(components.get(channel) or 0) > 0
        for channel in ("semantic", "calls", "strings", "capabilities")
    )


def _retrieval_run_key(
    sources: list[dict[str, Any]],
    *,
    explicit_key: str | None,
    top_k: int,
    minimum_score: float,
    max_postings_per_token: int,
    max_candidates_per_commercial: int,
    project_top_k: int,
) -> str:
    digest = hashlib.sha256()
    digest.update(
        json.dumps(
            {
                "schema_version": RETRIEVAL_SCHEMA,
                "explicit_key": explicit_key,
                "top_k": top_k,
                "minimum_score": minimum_score,
                "max_postings_per_token": max_postings_per_token,
                "max_candidates_per_commercial": (
                    max_candidates_per_commercial
                ),
                "project_top_k": project_top_k,
                "source_count": len(sources),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    for row in sources:
        digest.update(
            "\0".join(
                (
                    str(row.get("function_id") or ""),
                    _source_project_key(row),
                    str(row.get("commit_sha") or ""),
                    str(row.get("source_path") or ""),
                    str(row.get("start_line") or ""),
                    str(row.get("representation") or "source_code_function"),
                )
            ).encode("utf-8", errors="ignore")
        )
    return digest.hexdigest()


def _write_candidate(handle: TextIO | None, row: dict[str, Any]) -> None:
    if handle is not None:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _retain_candidate(
    retained: list[dict[str, Any]],
    row: dict[str, Any],
    *,
    limit: int | None,
) -> None:
    if limit == 0:
        return
    retained.append(row)
    if limit is not None and len(retained) > limit * 2:
        retained.sort(
            key=lambda item: (
                -float(item.get("retrieval_score") or 0),
                str((item.get("commercial") or {}).get("function_id") or ""),
                int(item.get("rank") or 0),
            )
        )
        del retained[limit:]


def candidate_analysis_lane(row: dict[str, Any]) -> str:
    """Classify a retrieval row by the research claim it can support."""

    source = row.get("source") or {}
    return source_analysis_lane(source)


def _representation_group(row: dict[str, Any]) -> str:
    representation = str(
        (row.get("commercial") or {}).get("representation") or "unknown"
    )
    return "native" if representation == "ida_lightweight_inventory" else "managed"


def _generic_function_name(row: dict[str, Any]) -> bool:
    name = str((row.get("commercial") or {}).get("name") or "")
    tokens = set(identifier_tokens(name))
    if not tokens:
        return True
    if name.startswith((".", "sub_", "loc_", "nullsub_", "j_", "imp_")):
        return True
    return tokens.issubset(GENERIC_FUNCTION_TOKENS)


def _managed_method_name(row: dict[str, Any]) -> str:
    raw_name = str((row.get("commercial") or {}).get("name") or "").strip()
    if "->" in raw_name:
        raw_name = raw_name.rsplit("->", 1)[-1]
    elif "#" in raw_name:
        raw_name = raw_name.rsplit("#", 1)[-1]
    elif "::" in raw_name:
        raw_name = raw_name.rsplit("::", 1)[-1]
    raw_name = raw_name.split("(", 1)[0].strip()
    if "." in raw_name:
        raw_name = raw_name.rsplit(".", 1)[-1]
    return raw_name


def _managed_information_gate(
    row: dict[str, Any],
    profile: dict[str, Any],
) -> dict[str, Any]:
    commercial = row.get("commercial") or {}
    ownership = commercial.get("ownership") or {}
    ownership_category = str(ownership.get("category") or "unknown")
    method_name = _managed_method_name(row)
    normalized_name = method_name.casefold()
    components = row.get("components") or {}

    dependency_or_platform = ownership_category in {"third_party", "platform"}
    generic_method = bool(
        normalized_name in MANAGED_GENERIC_METHOD_NAMES
        or MANAGED_GENERATED_METHOD_RE.fullmatch(method_name)
        or MANAGED_ACCESSOR_METHOD_RE.fullmatch(method_name)
    )
    exact = bool(
        float(components.get("exact_body") or 0) >= 1.0
        or float(components.get("exact_structural") or 0) >= 1.0
    )
    strong_structure = bool(
        float(components.get("source_shingles") or 0) >= 0.50
        or float(components.get("instruction") or 0) >= 0.60
        or (
            float(components.get("source_shingles") or 0) >= 0.35
            and float(components.get("cfg") or 0) >= 0.80
        )
    )
    semantic_context = bool(
        float(components.get("strings") or 0) >= 0.50
        or float(components.get("capabilities") or 0) >= 0.75
        or float(components.get("calls") or 0) >= 0.65
    )
    distinctive_override = bool(
        (exact and (strong_structure or semantic_context))
        or (strong_structure and semantic_context)
        or (
            float(components.get("source_shingles") or 0) >= 0.70
            and float(components.get("cfg") or 0) >= 0.80
        )
    )
    distinctive_signals = set(profile.get("distinctive_signals") or [])
    high_information_signals = distinctive_signals.intersection(
        {
            "strings",
            "capabilities",
            "cfg",
            "instruction",
            "source_shingles",
            "exact_body",
            "exact_structural",
        }
    )

    exclusion_reason = None
    if dependency_or_platform:
        exclusion_reason = "commercial_dependency_or_platform"
    elif generic_method and not distinctive_override:
        exclusion_reason = "managed_low_information_generic_method"
    elif not high_information_signals and not distinctive_override:
        exclusion_reason = "managed_low_information_no_distinctive_structure"

    return {
        "eligible": exclusion_reason is None,
        "exclusion_reason": exclusion_reason,
        "method_name": method_name,
        "generic_method": generic_method,
        "dependency_or_platform": dependency_or_platform,
        "ownership_category": ownership_category,
        "distinctive_override": distinctive_override,
        "high_information_signals": sorted(high_information_signals),
    }


def _selection_evidence(row: dict[str, Any]) -> dict[str, Any]:
    components = row.get("components") or {}
    thresholds = {
        "semantic": 0.50,
        "calls": 0.30,
        "strings": 0.20,
        "capabilities": 0.50,
        "cfg": 0.60,
        "instruction": 0.20,
        "source_shingles": 0.20,
        "exact_body": 1.0,
        "exact_structural": 1.0,
    }
    signals = sorted(
        channel
        for channel, threshold in thresholds.items()
        if float(components.get(channel) or 0) >= threshold
    )
    distinctive_signals = set(signals).intersection(
        {
            "calls",
            "strings",
            "capabilities",
            "cfg",
            "instruction",
            "source_shingles",
            "exact_body",
            "exact_structural",
        }
    )
    generic_name = _generic_function_name(row)
    sufficiency = row.get("evidence_sufficiency") or {}
    explicitly_ineligible = sufficiency.get("deep_comparison_eligible") is False
    selection_score = float(row.get("retrieval_score") or 0)
    if generic_name and not distinctive_signals:
        selection_score = min(selection_score, 0.35)
    if len(signals) < 2 and not {
        "exact_body",
        "exact_structural",
    }.intersection(signals):
        selection_score = min(selection_score, 0.60)
    return {
        "signals": signals,
        "signal_count": len(signals),
        "distinctive_signals": sorted(distinctive_signals),
        "distinctive_signal_count": len(distinctive_signals),
        "generic_function_name": generic_name,
        "generic_or_runtime_noise": generic_name,
        "selection_score": round(selection_score, 6),
        "explicitly_ineligible": explicitly_ineligible,
    }


def annotate_candidate_for_selection(row: dict[str, Any]) -> dict[str, Any]:
    """Add selection semantics without changing the complete retrieval stream."""

    annotated = dict(row)
    lane = candidate_analysis_lane(row)
    group = _representation_group(row)
    profile = _selection_evidence(row)
    source = annotate_source_policy(row.get("source") or {})
    annotated["source"] = source
    commercial = row.get("commercial") or {}
    candidate_pair_id = str(
        row.get("candidate_pair_id")
        or stable_id(
            "reuse_candidate_pair",
            commercial.get("function_id"),
            source.get("function_id"),
            source.get("repository_full_name") or source.get("corpus_id"),
        )
    )
    role = source.get("effective_candidate_role") or source.get("candidate_role")
    ownership_class = str(source.get("ownership_class") or "unknown")
    missing_profile = not row.get("components") and not row.get(
        "evidence_sufficiency"
    )
    managed_gate = (
        _managed_information_gate(row, profile)
        if group == "managed"
        else {
            "eligible": True,
            "exclusion_reason": None,
        }
    )
    deep_eligible = not profile["explicitly_ineligible"]
    if ownership_class in {"test_example_or_demo", "test_or_example", "demo"}:
        deep_eligible = False
    elif lane == "control":
        deep_eligible = role == "method_control" and (
            missing_profile or profile["signal_count"] >= 1
        )
    elif lane == "adaptation":
        deep_eligible = deep_eligible and (
            missing_profile
            or (
                profile["signal_count"] >= 2
                and profile["distinctive_signal_count"] >= 1
                and (
                    not profile["generic_function_name"]
                    or profile["distinctive_signal_count"] >= 2
                    or bool(
                        {"exact_body", "exact_structural"}.intersection(
                            profile["signals"]
                        )
                    )
                )
            )
        )
    elif lane == "usage":
        deep_eligible = deep_eligible and (
            missing_profile
            or (
                profile["signal_count"] >= 1
                and (
                    not profile["generic_function_name"]
                    or profile["distinctive_signal_count"] >= 1
                )
            )
            or float((row.get("components") or {}).get("exact_body") or 0) > 0
        )
    if group == "managed" and not managed_gate["eligible"]:
        deep_eligible = False
    exclusion_reason = None
    if profile["explicitly_ineligible"]:
        exclusion_reason = "upstream_evidence_sufficiency_gate"
    elif ownership_class in {"test_example_or_demo", "test_or_example", "demo"}:
        exclusion_reason = "source_test_or_demo"
    elif group == "managed" and not managed_gate["eligible"]:
        exclusion_reason = managed_gate["exclusion_reason"]
    elif not deep_eligible:
        exclusion_reason = "insufficient_lane_evidence"
    profile["managed_information_gate"] = managed_gate
    profile["deep_comparison_exclusion_reason"] = exclusion_reason
    annotated.update(
        {
            "candidate_pair_id": candidate_pair_id,
            "analysis_lane": lane,
            "analysis_semantics": {
                "usage": (
                    "Evidence that an open-source or externally maintained implementation "
                    "may be bundled, linked, or invoked. It is not proprietary copying evidence."
                ),
                "adaptation": (
                    "A project-owned upstream candidate that may support modified, ported, "
                    "or reimplemented logic after representation-aware deep comparison."
                ),
                "control": (
                    "A method, dependency, sibling, test, or demo control retained for audit "
                    "and false-positive calibration."
                ),
            }[lane],
            "representation_group": group,
            "selection_score": profile["selection_score"],
            "selection_evidence": profile,
            "candidate_deep_comparison_eligible": bool(deep_eligible),
        }
    )
    return annotated


def _selection_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        -float(row.get("selection_score") or row.get("retrieval_score") or 0),
        -int((row.get("selection_evidence") or {}).get("signal_count") or 0),
        str(row.get("source_project") or ""),
        str((row.get("commercial") or {}).get("function_id") or ""),
        str((row.get("source") or {}).get("function_id") or ""),
    )


def _retain_selection_candidate(
    retained: list[dict[str, Any]],
    row: dict[str, Any],
    *,
    limit: int,
) -> None:
    if limit <= 0:
        return
    retained.append(row)
    if len(retained) > limit * 2:
        retained.sort(key=_selection_sort_key)
        del retained[limit:]


def _allocate_quotas(
    available: dict[str, int],
    weights: dict[str, float],
    limit: int,
) -> dict[str, int]:
    active = [key for key in weights if available.get(key, 0) > 0]
    quotas = {key: 0 for key in weights}
    remaining = max(0, min(limit, sum(available.values())))
    if not active or remaining == 0:
        return quotas
    if remaining >= len(active):
        for key in active:
            quotas[key] = 1
            remaining -= 1
    while remaining > 0:
        eligible = [key for key in active if quotas[key] < available[key]]
        if not eligible:
            break
        key = min(
            eligible,
            key=lambda item: (
                quotas[item] / max(weights[item], 0.000001),
                -weights[item],
                item,
            ),
        )
        quotas[key] += 1
        remaining -= 1
    return quotas


def _candidate_pair_key(row: dict[str, Any]) -> tuple[str, str]:
    return (
        str((row.get("commercial") or {}).get("function_id") or ""),
        str((row.get("source") or {}).get("function_id") or ""),
    )


def _take_diverse_candidates(
    rows: Iterable[dict[str, Any]],
    *,
    limit: int,
    selected_keys: set[tuple[str, str]],
    selected: list[dict[str, Any]],
    project_counts: Counter[str],
    library_counts: Counter[str],
    commercial_counts: Counter[str],
    project_cap: int,
    library_cap: int,
    commercial_cap: int,
    relax_diversity: bool = False,
) -> None:
    if limit <= 0:
        return
    added = 0
    for row in rows:
        pair_key = _candidate_pair_key(row)
        if pair_key in selected_keys:
            continue
        commercial = row.get("commercial") or {}
        project = str(row.get("source_project") or "unknown_project")
        library = str(commercial.get("library_sha256") or commercial.get("library") or "managed")
        function_id = str(commercial.get("function_id") or "")
        if not function_id:
            continue
        if commercial_counts[function_id] >= commercial_cap:
            continue
        if not relax_diversity and (
            project_counts[project] >= project_cap
            or library_counts[library] >= library_cap
        ):
            continue
        selected.append(row)
        selected_keys.add(pair_key)
        project_counts[project] += 1
        library_counts[library] += 1
        commercial_counts[function_id] += 1
        added += 1
        if added >= limit:
            break


def select_candidate_cohorts(
    candidates: Iterable[dict[str, Any]],
    *,
    review_limit: int,
    native_decompile_limit: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Build bounded, representation-aware review and native deep-comparison pools."""

    review_limit = max(0, review_limit)
    native_decompile_limit = max(0, native_decompile_limit)
    review_buckets: dict[str, list[dict[str, Any]]] = {
        key: [] for key in REVIEW_BUCKET_WEIGHTS
    }
    native_buckets: dict[str, list[dict[str, Any]]] = {
        lane: [] for lane in ANALYSIS_LANES
    }
    all_lane_counts: Counter[str] = Counter()
    representation_counts: Counter[str] = Counter()
    native_deep_eligible_counts: Counter[str] = Counter()
    managed_deep_eligible_counts: Counter[str] = Counter()
    managed_deep_exclusion_reason_counts: Counter[str] = Counter()
    row_count = 0
    review_bucket_capacity = max(1, review_limit)
    native_bucket_capacity = max(200, native_decompile_limit * 20)
    for raw_row in candidates:
        if not isinstance(raw_row, dict):
            continue
        row_count += 1
        row = annotate_candidate_for_selection(raw_row)
        lane = str(row["analysis_lane"])
        group = str(row["representation_group"])
        bucket = f"{lane}_{group}"
        all_lane_counts[lane] += 1
        representation_counts[group] += 1
        _retain_selection_candidate(
            review_buckets[bucket],
            row,
            limit=review_bucket_capacity,
        )
        if group == "native" and row["candidate_deep_comparison_eligible"]:
            native_deep_eligible_counts[lane] += 1
            _retain_selection_candidate(
                native_buckets[lane],
                row,
                limit=native_bucket_capacity,
            )
        elif group == "managed":
            if row["candidate_deep_comparison_eligible"]:
                managed_deep_eligible_counts[lane] += 1
            else:
                reason = str(
                    (row.get("selection_evidence") or {}).get(
                        "deep_comparison_exclusion_reason"
                    )
                    or "unspecified"
                )
                managed_deep_exclusion_reason_counts[reason] += 1

    for rows in review_buckets.values():
        rows.sort(key=_selection_sort_key)
    for rows in native_buckets.values():
        rows.sort(key=_selection_sort_key)

    review_available = {key: len(rows) for key, rows in review_buckets.items()}
    review_quotas = _allocate_quotas(
        review_available,
        REVIEW_BUCKET_WEIGHTS,
        review_limit,
    )
    review: list[dict[str, Any]] = []
    selected_keys: set[tuple[str, str]] = set()
    project_counts: Counter[str] = Counter()
    library_counts: Counter[str] = Counter()
    commercial_counts: Counter[str] = Counter()
    project_cap = max(8, math.ceil(max(1, review_limit) / 8))
    library_cap = max(8, math.ceil(max(1, review_limit) / 5))
    for bucket in REVIEW_BUCKET_WEIGHTS:
        desired = review_quotas[bucket]
        before = len(review)
        _take_diverse_candidates(
            review_buckets[bucket],
            limit=desired,
            selected_keys=selected_keys,
            selected=review,
            project_counts=project_counts,
            library_counts=library_counts,
            commercial_counts=commercial_counts,
            project_cap=project_cap,
            library_cap=library_cap,
            commercial_cap=3,
        )
        shortfall = desired - (len(review) - before)
        if shortfall > 0:
            _take_diverse_candidates(
                review_buckets[bucket],
                limit=shortfall,
                selected_keys=selected_keys,
                selected=review,
                project_counts=project_counts,
                library_counts=library_counts,
                commercial_counts=commercial_counts,
                project_cap=project_cap,
                library_cap=library_cap,
                commercial_cap=3,
                relax_diversity=True,
            )
    if len(review) < review_limit:
        spill = sorted(
            (row for rows in review_buckets.values() for row in rows),
            key=_selection_sort_key,
        )
        _take_diverse_candidates(
            spill,
            limit=review_limit - len(review),
            selected_keys=selected_keys,
            selected=review,
            project_counts=project_counts,
            library_counts=library_counts,
            commercial_counts=commercial_counts,
            project_cap=project_cap,
            library_cap=library_cap,
            commercial_cap=3,
            relax_diversity=True,
        )

    native_pool = sorted(
        (row for rows in native_buckets.values() for row in rows),
        key=_selection_sort_key,
    )
    review_lane_counts = Counter(str(row["analysis_lane"]) for row in review)
    review_bucket_counts = Counter(
        f"{row['analysis_lane']}_{row['representation_group']}" for row in review
    )
    summary = {
        "schema_version": SELECTION_SCHEMA,
        "status": "completed",
        "candidate_row_count": row_count,
        "candidate_lane_counts": dict(sorted(all_lane_counts.items())),
        "candidate_representation_counts": dict(
            sorted(representation_counts.items())
        ),
        "review_candidate_limit": review_limit,
        "review_candidate_count": len(review),
        "review_bucket_available_counts": dict(sorted(review_available.items())),
        "review_bucket_quotas": dict(sorted(review_quotas.items())),
        "review_bucket_counts": dict(sorted(review_bucket_counts.items())),
        "review_lane_counts": dict(sorted(review_lane_counts.items())),
        "review_project_count": len(project_counts),
        "review_library_count": len(library_counts),
        "native_deep_eligible_counts": dict(
            sorted(native_deep_eligible_counts.items())
        ),
        "native_deep_eligible_count": sum(native_deep_eligible_counts.values()),
        "managed_deep_eligible_counts": dict(
            sorted(managed_deep_eligible_counts.items())
        ),
        "managed_deep_eligible_count": sum(managed_deep_eligible_counts.values()),
        "managed_deep_exclusion_reason_counts": dict(
            sorted(managed_deep_exclusion_reason_counts.items())
        ),
        "native_deep_pool_count": len(native_pool),
        "native_decompile_limit": native_decompile_limit,
        "selection_starved": bool(
            sum(native_deep_eligible_counts.values()) > 0 and not native_pool
        ),
        "method_note": (
            "Review retention is stratified by claim lane and commercial representation. "
            "Usage evidence is separated from project-owned adaptation candidates and "
            "controls. Native deep candidates are selected independently of managed-code "
            "scores and remain bounded by project, library, and function diversity."
        ),
    }
    return summary, review, native_pool


def _retrieve_candidates_legacy(
    commercial_rows: Iterable[dict[str, Any]],
    source_rows: Iterable[dict[str, Any]],
    *,
    top_k: int = 10,
    minimum_score: float = 0.28,
    max_postings_per_token: int = 5000,
    max_candidates_per_commercial: int = 2000,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if top_k <= 0:
        raise ValueError("top_k must be positive")
    if not 0 <= minimum_score <= 1:
        raise ValueError("minimum_score must be between zero and one")
    if max_postings_per_token <= 0 or max_candidates_per_commercial <= 0:
        raise ValueError("retrieval posting and candidate limits must be positive")
    sources = [row for row in source_rows if isinstance(row, dict)]
    source_features = [_source_features(row) for row in sources]
    postings: dict[str, list[int]] = defaultdict(list)
    for index, features in enumerate(source_features):
        posting_tokens = features["semantic"] | features["calls"] | features["strings"]
        posting_tokens |= {f"instruction:{value}" for value in features["instruction_hashes"]}
        posting_tokens |= {
            f"source_shingle:{value}" for value in features["source_shingles"]
        }
        if features["body_sha256"]:
            posting_tokens.add(f"body:{features['body_sha256']}")
        if features["structural_sha256"]:
            posting_tokens.add(f"structural:{features['structural_sha256']}")
        for token in sorted(posting_tokens):
            postings[token].append(index)
    postings = {
        token: indexes
        for token, indexes in postings.items()
        if len(indexes) <= max_postings_per_token
    }

    output: list[dict[str, Any]] = []
    commercial_count = 0
    eligible_commercial_count = 0
    searchable_count = 0
    truncated_pool_count = 0
    largest_raw_pool = 0
    skipped_ownership_counts: Counter[str] = Counter()
    source_roles = Counter(str(row.get("candidate_role") or "unknown") for row in sources)
    for commercial in commercial_rows:
        if not isinstance(commercial, dict):
            continue
        commercial_count += 1
        ownership_category = str(
            (commercial.get("ownership") or {}).get("category") or "unknown"
        )
        if ownership_category in {"third_party", "platform"}:
            skipped_ownership_counts[ownership_category] += 1
            continue
        eligible_commercial_count += 1
        left = _commercial_features(commercial)
        informative_tokens = left["semantic"] | left["calls"] | left["strings"]
        retrieval_tokens = set(informative_tokens)
        retrieval_tokens |= {
            f"instruction:{value}" for value in left["instruction_hashes"]
        }
        retrieval_tokens |= {
            f"source_shingle:{value}" for value in left["source_shingles"]
        }
        if left["body_sha256"]:
            retrieval_tokens.add(f"body:{left['body_sha256']}")
        if left["structural_sha256"]:
            retrieval_tokens.add(f"structural:{left['structural_sha256']}")
        candidate_priorities: Counter[int] = Counter()
        for token in retrieval_tokens:
            token_postings = postings.get(token, [])
            if not token_postings:
                continue
            rarity_weight = 1.0 / len(token_postings)
            for source_index in token_postings:
                candidate_priorities[source_index] += rarity_weight
        if not candidate_priorities:
            continue
        searchable_count += 1
        largest_raw_pool = max(largest_raw_pool, len(candidate_priorities))
        if len(candidate_priorities) > max_candidates_per_commercial:
            truncated_pool_count += 1
        candidate_indexes = [
            source_index
            for source_index, _priority in sorted(
                candidate_priorities.items(),
                key=lambda item: (
                    -item[1],
                    str(sources[item[0]].get("corpus_id") or ""),
                    str(sources[item[0]].get("source_path") or ""),
                    int(sources[item[0]].get("start_line") or 0),
                ),
            )[:max_candidates_per_commercial]
        ]
        ranked: list[tuple[float, int, dict[str, float], list[str]]] = []
        for source_index in candidate_indexes:
            score, components, weighted_channels = _score(
                left,
                source_features[source_index],
            )
            distinctive_overlap = max(
                components["semantic"],
                components["calls"],
                components["strings"],
                components["capabilities"],
                components["cfg"],
                components["instruction"],
                components["source_shingles"],
                components["exact_body"],
                components["exact_structural"],
            )
            if distinctive_overlap > 0 and score >= minimum_score:
                ranked.append(
                    (score, source_index, components, weighted_channels)
                )
        ranked.sort(
            key=lambda item: (
                -item[0],
                str(sources[item[1]].get("corpus_id") or ""),
                str(sources[item[1]].get("source_path") or ""),
                int(sources[item[1]].get("start_line") or 0),
            )
        )
        for rank, (score, source_index, components, weighted_channels) in enumerate(
            ranked[:top_k],
            start=1,
        ):
            source = sources[source_index]
            right = source_features[source_index]
            commercial_function_id = str(
                commercial.get("function_id")
                or stable_id(
                    "commercial_function",
                    commercial.get("library_sha256"),
                    commercial.get("address"),
                    commercial.get("file"),
                    commercial.get("start_line"),
                    commercial.get("name")
                    or commercial.get("function_name")
                    or commercial.get("method_name"),
                )
            )
            source_function_id = str(
                source.get("function_id")
                or stable_id(
                    "oss_function",
                    source.get("corpus_id"),
                    source.get("repository_full_name"),
                    source.get("commit_sha"),
                    source.get("source_path"),
                    source.get("start_line"),
                    source.get("function_name") or source.get("name"),
                    source.get("build_variant"),
                    source.get("abi"),
                    source.get("address"),
                )
            )
            representation_pair = {
                "commercial": left["representation"],
                "source": right["representation"],
            }
            source_comparable, dex_comparable, native_comparable = (
                _representations_comparable(
                    left["representation"],
                    right["representation"],
                )
            )
            evidence_sufficiency = _evidence_sufficiency(
                left,
                right,
                components,
            )
            output.append(
                {
                    "schema_version": RETRIEVAL_SCHEMA,
                    "rank": rank,
                    "retrieval_score": round(score, 6),
                    "score_interpretation": (
                        "candidate retrieval priority, not a copying probability or final similarity score"
                    ),
                    "components": components,
                    "weighted_channels": weighted_channels,
                    "representation_pair": representation_pair,
                    "representation_compatibility": {
                        "source": source_comparable,
                        "dex": dex_comparable,
                        "native": native_comparable,
                        "structural_channels_allowed": (
                            source_comparable or dex_comparable or native_comparable
                        ),
                    },
                    "evidence_sufficiency": evidence_sufficiency,
                    "commercial": {
                        key: commercial.get(key)
                        for key in (
                            "function_id",
                            "representation",
                            "name",
                            "library",
                            "library_sha256",
                            "abi",
                            "address",
                            "file",
                            "start_line",
                            "ownership",
                            "capabilities",
                        )
                    }
                    | {
                        "function_id": commercial_function_id,
                        "representation": left["representation"],
                        "name": (
                            commercial.get("name")
                            or commercial.get("function_name")
                            or commercial.get("method_name")
                        ),
                    },
                    "source": {
                        key: source.get(key)
                        for key in (
                            "corpus_id",
                            "repository_full_name",
                            "commit_sha",
                            "source_path",
                            "start_line",
                            "end_line",
                            "function_name",
                            "name",
                            "language",
                            "candidate_role",
                            "ownership_class",
                            "capabilities",
                            "representation",
                            "function_id",
                            "library",
                            "library_sha256",
                            "binary_sha256",
                            "abi",
                            "address",
                            "build_variant",
                            "compiler",
                        )
                    }
                    | {
                        "function_id": source_function_id,
                        "representation": right["representation"],
                    },
                    "matched_tokens": sorted(
                        informative_tokens
                        & (
                            source_features[source_index]["semantic"]
                            | source_features[source_index]["calls"]
                            | source_features[source_index]["strings"]
                        )
                    )[:80],
                    "matched_fingerprints": {
                        "instruction_hashes": sorted(
                            left["instruction_hashes"]
                            & right["instruction_hashes"]
                        )[:80],
                        "source_shingle_hashes": sorted(
                            left["source_shingles"] & right["source_shingles"]
                        )[:80],
                        "body_sha256": (
                            left["body_sha256"]
                            if components["exact_body"] > 0
                            else None
                        ),
                        "structural_sha256": (
                            left["structural_sha256"]
                            if components["exact_structural"] > 0
                            else None
                        ),
                    },
                }
            )
    output.sort(
        key=lambda row: (
            -float(row.get("retrieval_score") or 0),
            str((row.get("commercial") or {}).get("function_id") or ""),
            int(row.get("rank") or 0),
        )
    )
    sufficiency_counts = Counter(
        str((row.get("evidence_sufficiency") or {}).get("level") or "unknown")
        for row in output
    )
    summary = {
        "schema_version": RETRIEVAL_SCHEMA,
        "status": "completed",
        "commercial_function_count": commercial_count,
        "eligible_commercial_function_count": eligible_commercial_count,
        "searchable_commercial_function_count": searchable_count,
        "source_function_count": len(sources),
        "source_candidate_role_counts": dict(sorted(source_roles.items())),
        "candidate_pair_count": len(output),
        "evidence_sufficiency_counts": dict(sorted(sufficiency_counts.items())),
        "deep_comparison_eligible_candidate_count": sum(
            (row.get("evidence_sufficiency") or {}).get(
                "deep_comparison_eligible"
            )
            is not False
            for row in output
        ),
        "commercial_function_with_candidate_count": len(
            {
                str((row.get("commercial") or {}).get("function_id") or "")
                for row in output
            }
        ),
        "top_k": top_k,
        "minimum_score": minimum_score,
        "max_postings_per_token": max_postings_per_token,
        "max_candidates_per_commercial": max_candidates_per_commercial,
        "truncated_candidate_pool_function_count": truncated_pool_count,
        "largest_raw_candidate_pool": largest_raw_pool,
        "skipped_commercial_ownership_counts": dict(
            sorted(skipped_ownership_counts.items())
        ),
        "method_note": (
            "Retrieval uses explainable semantic, call, string, capability, branch, "
            "control-flow, size, exact-body, source-shingle, and "
            "representation-compatible opcode "
            "signals. Known third-party and platform commercial functions "
            "remain indexed but are excluded from proprietary reuse retrieval. "
            "Candidate pairs require later decompilation and attribution before any "
            "implementation-similarity conclusion."
        ),
    }
    return summary, output


def retrieve_candidates(
    commercial_rows: Iterable[dict[str, Any]],
    source_rows: Iterable[dict[str, Any]],
    *,
    top_k: int = 10,
    minimum_score: float = 0.28,
    max_postings_per_token: int = 5000,
    max_candidates_per_commercial: int = 200,
    project_top_k: int = 12,
    output_path: Path | None = None,
    summary_path: Path | None = None,
    checkpoint_path: Path | None = None,
    resume_key: str | None = None,
    checkpoint_interval: int = 10_000,
    retained_candidate_limit: int | None = None,
    progress_callback: ProgressCallback | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Retrieve bounded, explainable candidates with resumable streaming output."""

    if top_k <= 0:
        raise ValueError("top_k must be positive")
    if not 0 <= minimum_score <= 1:
        raise ValueError("minimum_score must be between zero and one")
    if min(
        max_postings_per_token,
        max_candidates_per_commercial,
        project_top_k,
        checkpoint_interval,
    ) <= 0:
        raise ValueError("retrieval limits must be positive")
    if retained_candidate_limit is not None and retained_candidate_limit < 0:
        raise ValueError("retained_candidate_limit must be non-negative when set")

    sources = [row for row in source_rows if isinstance(row, dict)]
    source_features = [_source_features(row) for row in sources]
    source_projects = [_source_project_key(row) for row in sources]
    source_roles = Counter(
        str(row.get("candidate_role") or "unknown") for row in sources
    )
    postings: dict[str, list[int]] = defaultdict(list)
    for source_index, features in enumerate(source_features):
        for token in sorted(_posting_tokens(features)):
            postings[token].append(source_index)
    postings = {
        token: indexes
        for token, indexes in postings.items()
        if len(indexes) <= max_postings_per_token
    }
    run_key = _retrieval_run_key(
        sources,
        explicit_key=resume_key,
        top_k=top_k,
        minimum_score=minimum_score,
        max_postings_per_token=max_postings_per_token,
        max_candidates_per_commercial=max_candidates_per_commercial,
        project_top_k=project_top_k,
    )

    if output_path is not None and summary_path is not None:
        try:
            existing_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            existing_summary = {}
        if (
            isinstance(existing_summary, dict)
            and existing_summary.get("status") == "completed"
            and existing_summary.get("retrieval_run_key") == run_key
            and output_path.is_file()
        ):
            if retained_candidate_limit == 0:
                return {**existing_summary, "cache_status": "reused"}, []
            retained: list[dict[str, Any]] = []
            for row in iter_jsonl(output_path):
                _retain_candidate(
                    retained,
                    row,
                    limit=retained_candidate_limit,
                )
            retained.sort(
                key=lambda row: (
                    -float(row.get("retrieval_score") or 0),
                    str((row.get("commercial") or {}).get("function_id") or ""),
                    int(row.get("rank") or 0),
                )
            )
            if retained_candidate_limit is not None:
                retained = retained[:retained_candidate_limit]
            return {**existing_summary, "cache_status": "reused"}, retained

    state: dict[str, Any] = {
        "commercial_count": 0,
        "eligible_count": 0,
        "searchable_count": 0,
        "with_candidate_count": 0,
        "candidate_pair_count": 0,
        "deep_eligible_count": 0,
        "truncated_pool_count": 0,
        "largest_raw_pool": 0,
        "insufficient_bridge_count": 0,
        "deduplicated_variant_count": 0,
        "skipped_ownership": Counter(),
        "sufficiency": Counter(),
        "relations": Counter(),
        "representations": Counter(),
    }
    part_path = (
        output_path.with_suffix(output_path.suffix + ".part")
        if output_path is not None
        else None
    )
    if checkpoint_path is None and output_path is not None:
        checkpoint_path = output_path.with_suffix(
            output_path.suffix + ".checkpoint.json"
        )

    resumed = False
    resume_at = 0
    checkpoint: dict[str, Any] = {}
    if checkpoint_path is not None:
        try:
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        except Exception:
            checkpoint = {}
    if (
        checkpoint.get("retrieval_run_key") == run_key
        and part_path is not None
        and part_path.is_file()
    ):
        saved = checkpoint.get("counters") or {}
        resume_at = int(saved.get("commercial_function_count") or 0)
        state.update(
            {
                "commercial_count": resume_at,
                "eligible_count": int(
                    saved.get("eligible_commercial_function_count") or 0
                ),
                "searchable_count": int(
                    saved.get("searchable_commercial_function_count") or 0
                ),
                "with_candidate_count": int(
                    saved.get("commercial_function_with_candidate_count") or 0
                ),
                "candidate_pair_count": int(
                    saved.get("candidate_pair_count") or 0
                ),
                "deep_eligible_count": int(
                    saved.get("deep_comparison_eligible_candidate_count") or 0
                ),
                "truncated_pool_count": int(
                    saved.get("truncated_candidate_pool_function_count") or 0
                ),
                "largest_raw_pool": int(
                    saved.get("largest_raw_candidate_pool") or 0
                ),
                "insufficient_bridge_count": int(
                    saved.get("insufficient_bridge_signal_count") or 0
                ),
                "deduplicated_variant_count": int(
                    saved.get("deduplicated_source_variant_count") or 0
                ),
                "skipped_ownership": Counter(
                    saved.get("skipped_commercial_ownership_counts") or {}
                ),
                "sufficiency": Counter(
                    saved.get("evidence_sufficiency_counts") or {}
                ),
                "relations": Counter(
                    saved.get("representation_relation_counts") or {}
                ),
                "representations": Counter(
                    saved.get("commercial_representation_counts") or {}
                ),
            }
        )
        resumed = True
    elif part_path is not None:
        part_path.unlink(missing_ok=True)
        if checkpoint_path is not None:
            checkpoint_path.unlink(missing_ok=True)

    output: list[dict[str, Any]] = []
    if resumed and part_path is not None:
        for row in iter_jsonl(part_path):
            _retain_candidate(output, row, limit=retained_candidate_limit)
    output_handle: TextIO | None = None
    if part_path is not None:
        part_path.parent.mkdir(parents=True, exist_ok=True)
        output_handle = part_path.open("a" if resumed else "w", encoding="utf-8")

    def counters_payload() -> dict[str, Any]:
        return {
            "commercial_function_count": state["commercial_count"],
            "eligible_commercial_function_count": state["eligible_count"],
            "searchable_commercial_function_count": state["searchable_count"],
            "commercial_function_with_candidate_count": state[
                "with_candidate_count"
            ],
            "candidate_pair_count": state["candidate_pair_count"],
            "deep_comparison_eligible_candidate_count": state[
                "deep_eligible_count"
            ],
            "truncated_candidate_pool_function_count": state[
                "truncated_pool_count"
            ],
            "largest_raw_candidate_pool": state["largest_raw_pool"],
            "insufficient_bridge_signal_count": state[
                "insufficient_bridge_count"
            ],
            "deduplicated_source_variant_count": state[
                "deduplicated_variant_count"
            ],
            "skipped_commercial_ownership_counts": dict(
                sorted(state["skipped_ownership"].items())
            ),
            "evidence_sufficiency_counts": dict(
                sorted(state["sufficiency"].items())
            ),
            "representation_relation_counts": dict(
                sorted(state["relations"].items())
            ),
            "commercial_representation_counts": dict(
                sorted(state["representations"].items())
            ),
        }

    def save_checkpoint(status: str) -> None:
        if checkpoint_path is None:
            return
        if output_handle is not None:
            output_handle.flush()
        safe_write_json(
            checkpoint_path,
            {
                "schema_version": RETRIEVAL_SCHEMA,
                "status": status,
                "retrieval_run_key": run_key,
                "candidate_output_part": (
                    str(part_path) if part_path is not None else None
                ),
                "counters": counters_payload(),
            },
        )

    def build_summary(status: str) -> dict[str, Any]:
        return {
            "schema_version": RETRIEVAL_SCHEMA,
            "status": status,
            "retrieval_run_key": run_key,
            "cache_status": "resumed" if resumed else "computed",
            **counters_payload(),
            "source_function_count": len(sources),
            "source_project_count": len(set(source_projects)),
            "source_candidate_role_counts": dict(sorted(source_roles.items())),
            "top_k": top_k,
            "project_top_k": project_top_k,
            "minimum_score": minimum_score,
            "max_postings_per_token": max_postings_per_token,
            "max_candidates_per_commercial": max_candidates_per_commercial,
            "candidate_output_path": (
                str(output_path) if output_path is not None else None
            ),
            "method_note": (
                "Retrieval shortlists OSS projects before function scoring. "
                "Structural channels are restricted to representation-compatible "
                "pairs; source-to-compiled semantic bridges require at least two "
                "independent semantic channels. Build variants of the same logical "
                "OSS function are deduplicated before top-k selection. Known "
                "third-party and platform commercial functions stay indexed but "
                "are excluded from proprietary reuse retrieval. Scores are "
                "retrieval priorities, not copying probabilities."
            ),
        }

    stream_position = 0
    try:
        for commercial in commercial_rows:
            if not isinstance(commercial, dict):
                continue
            stream_position += 1
            if stream_position <= resume_at:
                continue
            state["commercial_count"] += 1
            try:
                ownership_category = str(
                    (commercial.get("ownership") or {}).get("category")
                    or "unknown"
                )
                if ownership_category in {"third_party", "platform"}:
                    state["skipped_ownership"][ownership_category] += 1
                    continue
                state["eligible_count"] += 1
                left = _commercial_features(commercial)
                state["representations"][left["representation"]] += 1
                matched_postings = [
                    (token, postings[token])
                    for token in _posting_tokens(left)
                    if token in postings
                ]
                if not matched_postings:
                    continue

                project_priorities: Counter[str] = Counter()
                for _token, token_postings in matched_postings:
                    rarity_weight = 1.0 / len(token_postings)
                    for project in {
                        source_projects[source_index]
                        for source_index in token_postings
                    }:
                        project_priorities[project] += rarity_weight
                selected_projects = {
                    project
                    for project, _priority in sorted(
                        project_priorities.items(),
                        key=lambda item: (-item[1], item[0]),
                    )[:project_top_k]
                }

                candidate_priorities: Counter[int] = Counter()
                for _token, token_postings in matched_postings:
                    rarity_weight = 1.0 / len(token_postings)
                    for source_index in token_postings:
                        if source_projects[source_index] not in selected_projects:
                            continue
                        relation = _representation_relation(
                            left["representation"],
                            source_features[source_index]["representation"],
                        )
                        if relation is not None:
                            candidate_priorities[source_index] += rarity_weight
                if not candidate_priorities:
                    continue
                state["searchable_count"] += 1
                state["largest_raw_pool"] = max(
                    state["largest_raw_pool"], len(candidate_priorities)
                )
                if len(candidate_priorities) > max_candidates_per_commercial:
                    state["truncated_pool_count"] += 1
                candidate_indexes = [
                    source_index
                    for source_index, _priority in sorted(
                        candidate_priorities.items(),
                        key=lambda item: (
                            -item[1],
                            source_projects[item[0]],
                            str(sources[item[0]].get("source_path") or ""),
                            int(sources[item[0]].get("start_line") or 0),
                        ),
                    )[:max_candidates_per_commercial]
                ]

                ranked: list[tuple[float, int, dict[str, float], list[str], str]] = []
                for source_index in candidate_indexes:
                    right = source_features[source_index]
                    relation = _representation_relation(
                        left["representation"], right["representation"]
                    )
                    if relation is None:
                        continue
                    score, components, weighted_channels = _score(left, right)
                    if (
                        relation == "semantic_bridge"
                        and _cross_representation_signal_count(components) < 2
                    ):
                        state["insufficient_bridge_count"] += 1
                        continue
                    distinctive_overlap = max(
                        components["semantic"],
                        components["calls"],
                        components["strings"],
                        components["capabilities"],
                        components["cfg"],
                        components["instruction"],
                        components["source_shingles"],
                        components["exact_body"],
                        components["exact_structural"],
                    )
                    if distinctive_overlap > 0 and score >= minimum_score:
                        ranked.append(
                            (
                                score,
                                source_index,
                                components,
                                weighted_channels,
                                relation,
                            )
                        )
                ranked.sort(
                    key=lambda item: (
                        -item[0],
                        source_projects[item[1]],
                        str(sources[item[1]].get("source_path") or ""),
                        int(sources[item[1]].get("start_line") or 0),
                    )
                )
                deduplicated = []
                seen_source_functions: set[tuple[str, ...]] = set()
                for item in ranked:
                    logical_key = _logical_source_function_key(sources[item[1]])
                    if logical_key in seen_source_functions:
                        state["deduplicated_variant_count"] += 1
                        continue
                    seen_source_functions.add(logical_key)
                    deduplicated.append(item)
                    if len(deduplicated) >= top_k:
                        break

                emitted = 0
                for rank, item in enumerate(deduplicated, start=1):
                    score, source_index, components, weighted_channels, relation = item
                    candidate = _candidate_record(
                        commercial,
                        left,
                        sources[source_index],
                        source_features[source_index],
                        score=score,
                        components=components,
                        weighted_channels=weighted_channels,
                        relation=relation,
                        rank=rank,
                    )
                    _write_candidate(output_handle, candidate)
                    _retain_candidate(
                        output,
                        candidate,
                        limit=retained_candidate_limit,
                    )
                    state["candidate_pair_count"] += 1
                    state["relations"][relation] += 1
                    sufficiency = candidate["evidence_sufficiency"]
                    state["sufficiency"][
                        str(sufficiency.get("level") or "unknown")
                    ] += 1
                    if sufficiency.get("deep_comparison_eligible") is not False:
                        state["deep_eligible_count"] += 1
                    emitted += 1
                if emitted:
                    state["with_candidate_count"] += 1
            finally:
                if state["commercial_count"] % checkpoint_interval == 0:
                    save_checkpoint("running")
                    if progress_callback is not None:
                        progress_callback(
                            {
                                "event": "reuse_retrieval_checkpoint",
                                "commercial_function_count": state[
                                    "commercial_count"
                                ],
                                "candidate_pair_count": state[
                                    "candidate_pair_count"
                                ],
                            }
                        )
    except KeyboardInterrupt:
        save_checkpoint("interrupted")
        interrupted_summary = build_summary("interrupted")
        if summary_path is not None:
            safe_write_json(summary_path, interrupted_summary)
        raise
    except Exception:
        save_checkpoint("failed")
        failed_summary = build_summary("failed")
        if summary_path is not None:
            safe_write_json(summary_path, failed_summary)
        raise
    finally:
        if output_handle is not None:
            output_handle.close()

    if part_path is not None and output_path is not None:
        os.replace(part_path, output_path)
    if checkpoint_path is not None:
        checkpoint_path.unlink(missing_ok=True)
    output.sort(
        key=lambda row: (
            -float(row.get("retrieval_score") or 0),
            str((row.get("commercial") or {}).get("function_id") or ""),
            int(row.get("rank") or 0),
        )
    )
    if retained_candidate_limit is not None:
        del output[retained_candidate_limit:]
    summary = build_summary("completed")
    if summary_path is not None:
        safe_write_json(summary_path, summary)
    return summary, output


def _candidate_record(
    commercial: dict[str, Any],
    left: dict[str, Any],
    source: dict[str, Any],
    right: dict[str, Any],
    *,
    score: float,
    components: dict[str, float],
    weighted_channels: list[str],
    relation: str,
    rank: int,
) -> dict[str, Any]:
    source = annotate_source_policy(source)
    commercial_function_id = str(
        commercial.get("function_id")
        or stable_id(
            "commercial_function",
            commercial.get("library_sha256"),
            commercial.get("address"),
            commercial.get("file"),
            commercial.get("start_line"),
            commercial.get("name")
            or commercial.get("function_name")
            or commercial.get("method_name"),
        )
    )
    source_function_id = str(
        source.get("function_id")
        or stable_id(
            "oss_function",
            source.get("corpus_id"),
            source.get("repository_full_name"),
            source.get("commit_sha"),
            source.get("source_path"),
            source.get("start_line"),
            source.get("function_name") or source.get("name"),
            source.get("build_variant"),
            source.get("abi"),
            source.get("address"),
        )
    )
    source_comparable, dex_comparable, native_comparable = (
        _representations_comparable(
            left["representation"], right["representation"]
        )
    )
    evidence_sufficiency = _evidence_sufficiency(left, right, components)
    informative_tokens = left["semantic"] | left["calls"] | left["strings"]
    return {
        "schema_version": RETRIEVAL_SCHEMA,
        "rank": rank,
        "retrieval_score": round(score, 6),
        "score_interpretation": (
            "candidate retrieval priority, not a copying probability or final similarity score"
        ),
        "retrieval_mode": relation,
        "source_project": _source_project_key(source),
        "components": components,
        "weighted_channels": weighted_channels,
        "representation_pair": {
            "commercial": left["representation"],
            "source": right["representation"],
        },
        "representation_compatibility": {
            "source": source_comparable,
            "dex": dex_comparable,
            "native": native_comparable,
            "structural_channels_allowed": (
                source_comparable or dex_comparable or native_comparable
            ),
        },
        "evidence_sufficiency": evidence_sufficiency,
        "commercial": {
            key: commercial.get(key)
            for key in (
                "function_id",
                "representation",
                "name",
                "library",
                "library_sha256",
                "abi",
                "address",
                "file",
                "start_line",
                "ownership",
                "capabilities",
            )
        }
        | {
            "function_id": commercial_function_id,
            "representation": left["representation"],
            "name": (
                commercial.get("name")
                or commercial.get("function_name")
                or commercial.get("method_name")
            ),
        },
        "source": {
            key: source.get(key)
            for key in (
                "corpus_id",
                "repository_full_name",
                "commit_sha",
                "source_path",
                "start_line",
                "end_line",
                "function_name",
                "name",
                "language",
                "candidate_role",
                "ownership_class",
                "capabilities",
                "representation",
                "function_id",
                "library",
                "library_sha256",
                "binary_sha256",
                "abi",
                "address",
                "build_variant",
                "compiler",
                "carrier_project",
                "canonical_upstream_project",
                "canonical_component",
                "source_origin_class",
                "source_origin_confidence",
                "source_origin_rule",
                "declared_candidate_role",
                "effective_candidate_role",
                "candidate_role_resolution",
            )
        }
        | {
            "function_id": source_function_id,
            "representation": right["representation"],
        },
        "matched_tokens": sorted(
            informative_tokens
            & (right["semantic"] | right["calls"] | right["strings"])
        )[:80],
        "matched_fingerprints": {
            "instruction_hashes": sorted(
                left["instruction_hashes"] & right["instruction_hashes"]
            )[:80],
            "source_shingle_hashes": sorted(
                left["source_shingles"] & right["source_shingles"]
            )[:80],
            "body_sha256": (
                left["body_sha256"] if components["exact_body"] > 0 else None
            ),
            "structural_sha256": (
                left["structural_sha256"]
                if components["exact_structural"] > 0
                else None
            ),
        },
    }


def native_decompile_targets(
    candidates: Iterable[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    limit = max(0, limit)
    if limit == 0:
        return []
    rows_by_lane: dict[str, list[dict[str, Any]]] = {
        lane: [] for lane in ANALYSIS_LANES
    }
    for raw_row in candidates:
        row = (
            raw_row
            if raw_row.get("analysis_lane") in ANALYSIS_LANES
            else annotate_candidate_for_selection(raw_row)
        )
        commercial = row.get("commercial") or {}
        if commercial.get("representation") != "ida_lightweight_inventory":
            continue
        ownership = commercial.get("ownership") or {}
        if ownership.get("category") in {"third_party", "platform"}:
            continue
        source = row.get("source") or {}
        role = source.get("effective_candidate_role") or source.get(
            "candidate_role"
        )
        lane = str(row.get("analysis_lane") or "control")
        if lane == "control" and role != "method_control":
            continue
        if lane in PRIMARY_ANALYSIS_LANES and role not in {
            None,
            "upstream_candidate",
        }:
            continue
        if row.get("candidate_deep_comparison_eligible") is False:
            continue
        function_id = str(commercial.get("function_id") or "")
        library = str(commercial.get("library") or "")
        address = str(commercial.get("address") or "")
        if not function_id or not library or not address:
            continue
        rows_by_lane[lane].append(row)

    for rows in rows_by_lane.values():
        rows.sort(key=_selection_sort_key)
    quotas = _allocate_quotas(
        {lane: len(rows) for lane, rows in rows_by_lane.items()},
        NATIVE_TARGET_LANE_WEIGHTS,
        limit,
    )
    selected_rows: list[dict[str, Any]] = []
    selected_keys: set[tuple[str, str]] = set()
    project_counts: Counter[str] = Counter()
    library_counts: Counter[str] = Counter()
    commercial_counts: Counter[str] = Counter()
    project_cap = max(4, math.ceil(limit / 4))
    library_cap = max(4, math.ceil(limit / 4))
    for lane in ANALYSIS_LANES:
        desired = quotas[lane]
        before = len(selected_rows)
        _take_diverse_candidates(
            rows_by_lane[lane],
            limit=desired,
            selected_keys=selected_keys,
            selected=selected_rows,
            project_counts=project_counts,
            library_counts=library_counts,
            commercial_counts=commercial_counts,
            project_cap=project_cap,
            library_cap=library_cap,
            commercial_cap=1,
        )
        shortfall = desired - (len(selected_rows) - before)
        if shortfall > 0:
            _take_diverse_candidates(
                rows_by_lane[lane],
                limit=shortfall,
                selected_keys=selected_keys,
                selected=selected_rows,
                project_counts=project_counts,
                library_counts=library_counts,
                commercial_counts=commercial_counts,
                project_cap=project_cap,
                library_cap=library_cap,
                commercial_cap=1,
                relax_diversity=True,
            )
    if len(selected_rows) < limit:
        spill = sorted(
            (row for rows in rows_by_lane.values() for row in rows),
            key=_selection_sort_key,
        )
        _take_diverse_candidates(
            spill,
            limit=limit - len(selected_rows),
            selected_keys=selected_keys,
            selected=selected_rows,
            project_counts=project_counts,
            library_counts=library_counts,
            commercial_counts=commercial_counts,
            project_cap=project_cap,
            library_cap=library_cap,
            commercial_cap=1,
            relax_diversity=True,
        )

    targets: list[dict[str, Any]] = []
    for row in selected_rows:
        commercial = row.get("commercial") or {}
        source = row.get("source") or {}
        lane = str(row.get("analysis_lane") or "control")
        function_id = str(commercial.get("function_id") or "")
        candidate_pair_id = stable_id(
            "reuse_candidate_pair",
            function_id,
            source.get("function_id"),
            source.get("repository_full_name") or source.get("corpus_id"),
        )
        selection_score = float(
            row.get("selection_score") or row.get("retrieval_score") or 0
        )
        targets.append(
            {
                "library": str(commercial.get("library") or ""),
                "library_sha256": commercial.get("library_sha256"),
                "abi": commercial.get("abi"),
                "ownership": commercial.get("ownership") or {},
                "kind": "reuse_candidate",
                "analysis_lane": lane,
                "candidate_pair_id": candidate_pair_id,
                "commercial_function_id": function_id,
                "source_function_id": source.get("function_id"),
                "name": commercial.get("name") or function_id,
                "address": str(commercial.get("address") or ""),
                "score": 2000 + int(selection_score * 1000),
                "capabilities": commercial.get("capabilities") or [],
                "reasons": [
                    "open_source_candidate_retrieval",
                    f"analysis_lane:{lane}",
                    f"selection_score:{selection_score:.6f}",
                    f"retrieval_score:{row.get('retrieval_score')}",
                    f"source:{source.get('repository_full_name') or source.get('corpus_id')}",
                ],
                "reuse_candidate": {
                    "candidate_pair_id": candidate_pair_id,
                    "commercial_function_id": function_id,
                    "source_function_id": source.get("function_id"),
                    "analysis_lane": lane,
                    "analysis_semantics": row.get("analysis_semantics"),
                    "selection_score": selection_score,
                    "selection_evidence": row.get("selection_evidence") or {},
                    "retrieval_score": row.get("retrieval_score"),
                    "components": row.get("components") or {},
                    "weighted_channels": row.get("weighted_channels") or [],
                    "commercial": commercial,
                    "source": source,
                    "source_project": row.get("source_project")
                    or source.get("repository_full_name")
                    or source.get("corpus_id"),
                },
            }
        )
    return targets
