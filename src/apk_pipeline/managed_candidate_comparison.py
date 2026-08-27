"""Bounded deep review for managed-code open-source candidates.

Managed Java/Kotlin and DEX functions already have source- or bytecode-level
fingerprints, so they do not need Hex-Rays. This pass applies stricter,
claim-aware gates to a diverse subset of the retained retrieval candidates and
collapses duplicate observations from the same source family.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable

from .code_ownership import classify_code_ownership
from .function_fingerprint import stable_id
from .source_provenance import canonical_source_project
from .utils import safe_write_json


MANAGED_COMPARISON_SCHEMA = "2026-08-26.managed-deep-comparison.v2"
VALID_LANES = {"usage", "adaptation", "control"}
LANE_WEIGHTS = {"adaptation": 0.45, "usage": 0.45, "control": 0.10}
LOW_INFORMATION_METHOD_RE = re.compile(
    r"^(?:hashCode|toString|equals|clone|finalize|getClass|compareTo|"
    r"access\$\d+|component\d+|copy\$default|lambda\$.*|.*\$default)$",
    re.IGNORECASE,
)


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def _lane(row: dict[str, Any]) -> str:
    value = str(row.get("analysis_lane") or "control")
    return value if value in VALID_LANES else "control"


def _project(row: dict[str, Any]) -> str:
    source = row.get("source") or {}
    return canonical_source_project(source)


def _source_family(row: dict[str, Any]) -> str:
    source = row.get("source") or {}
    return stable_id(
        "managed_source_family",
        _project(row),
        source.get("commit_sha"),
        source.get("source_path"),
        source.get("function_name") or source.get("name"),
        source.get("body_sha256"),
        source.get("structural_sha256"),
    )


def _commercial_class(row: dict[str, Any]) -> str:
    commercial = row.get("commercial") or {}
    file_path = str(commercial.get("file") or "").replace("\\", "/")
    if file_path and not file_path.endswith(("classes.dex", "classes.jar")):
        return file_path
    name = str(commercial.get("name") or "")
    if "->" in name:
        return name.split("->", 1)[0]
    if "#" in name:
        return name.rsplit("#", 1)[0]
    if "::" in name:
        return name.rsplit("::", 1)[0]
    return file_path or "unknown_managed_class"


def _commercial_method(row: dict[str, Any]) -> str:
    name = str((row.get("commercial") or {}).get("name") or "").strip()
    for separator in ("->", "#", "::"):
        if separator in name:
            name = name.rsplit(separator, 1)[-1]
            break
    name = name.split("(", 1)[0].strip()
    return name.rsplit(".", 1)[-1]


def _managed_package_from_source_path(file_path: str) -> str | None:
    normalized = file_path.replace("\\", "/")
    marker = "/sources/"
    if marker in normalized:
        normalized = normalized.split(marker, 1)[1]
    elif normalized.startswith("sources/"):
        normalized = normalized[len("sources/") :]
    else:
        return None
    parent = Path(normalized).parent
    parts = [part for part in parent.parts if part not in {"", "."}]
    if not parts or any(not part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def _effective_ownership_category(row: dict[str, Any]) -> str:
    commercial = row.get("commercial") or {}
    ownership_category = str(
        (commercial.get("ownership") or {}).get("category") or "unknown"
    )
    if ownership_category != "unknown":
        return ownership_category

    # Compatibility for completed workspaces created before the managed SDK
    # registry existed. This only promotes an unknown row when its source path
    # independently matches an audited component namespace.
    file_path = str(commercial.get("file") or "")
    package = _managed_package_from_source_path(file_path)
    if package:
        inferred = classify_code_ownership(package, file_path)
        if inferred.attribution_kind == "managed_component_registry":
            return inferred.category
    return ownership_category


def _selection_exclusion_reason(row: dict[str, Any]) -> str | None:
    if row.get("candidate_deep_comparison_eligible") is False:
        return str(
            (row.get("selection_evidence") or {}).get(
                "deep_comparison_exclusion_reason"
            )
            or "upstream_selection_gate"
        )
    ownership_category = _effective_ownership_category(row)
    if ownership_category in {"third_party", "platform"}:
        return "commercial_dependency_or_platform"

    managed_gate = (row.get("selection_evidence") or {}).get(
        "managed_information_gate"
    )
    if isinstance(managed_gate, dict) and managed_gate.get("eligible") is False:
        return str(managed_gate.get("exclusion_reason") or "managed_information_gate")

    # Defensive compatibility for review files produced before the managed gate
    # was added. New runs carry the richer managed_information_gate telemetry.
    if LOW_INFORMATION_METHOD_RE.fullmatch(_commercial_method(row)):
        components = row.get("components") or {}
        strong_structure = bool(
            float(components.get("source_shingles") or 0) >= 0.50
            or float(components.get("instruction") or 0) >= 0.60
        )
        semantic_context = bool(
            float(components.get("strings") or 0) >= 0.50
            or float(components.get("capabilities") or 0) >= 0.75
            or float(components.get("calls") or 0) >= 0.65
        )
        if not (strong_structure and semantic_context):
            return "managed_low_information_generic_method"
    return None


def _sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    evidence = row.get("selection_evidence") or {}
    return (
        -float(row.get("selection_score") or row.get("retrieval_score") or 0),
        -int(evidence.get("distinctive_signal_count") or 0),
        -int(evidence.get("signal_count") or 0),
        _project(row),
        str((row.get("commercial") or {}).get("function_id") or ""),
        str((row.get("source") or {}).get("function_id") or ""),
    )


def _select_bounded(
    candidates: Iterable[dict[str, Any]],
    *,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exclusion_counts: Counter[str] = Counter()
    managed_candidate_count = 0
    for row in candidates:
        if not isinstance(row, dict):
            continue
        if str(row.get("representation_group") or "") != "managed":
            continue
        managed_candidate_count += 1
        exclusion_reason = _selection_exclusion_reason(row)
        if exclusion_reason is not None:
            exclusion_counts[exclusion_reason] += 1
            continue
        buckets[_lane(row)].append(row)
    for rows in buckets.values():
        rows.sort(key=_sort_key)

    limit = max(0, limit)
    quotas = {
        lane: int(limit * weight) for lane, weight in LANE_WEIGHTS.items()
    }
    quotas["adaptation"] += limit - sum(quotas.values())
    selected: list[dict[str, Any]] = []
    keys: set[tuple[str, str]] = set()
    project_counts: Counter[str] = Counter()
    commercial_counts: Counter[str] = Counter()
    commercial_class_counts: Counter[str] = Counter()
    source_family_counts: Counter[str] = Counter()
    project_cap = max(8, math.ceil(max(1, limit) * 0.15))
    commercial_class_cap = max(6, math.ceil(max(1, limit) * 0.03))
    source_family_cap = max(4, math.ceil(max(1, limit) * 0.02))
    commercial_function_cap = 2

    def take(rows: Iterable[dict[str, Any]], count: int) -> None:
        for row in rows:
            if count <= 0:
                return
            commercial_id = str(
                (row.get("commercial") or {}).get("function_id") or ""
            )
            pair_id = str(row.get("candidate_pair_id") or "")
            key = (pair_id, _source_family(row))
            project = _project(row)
            commercial_class = _commercial_class(row)
            source_family = _source_family(row)
            if key in keys or commercial_counts[commercial_id] >= commercial_function_cap:
                continue
            if (
                project_counts[project] >= project_cap
                or commercial_class_counts[commercial_class]
                >= commercial_class_cap
                or source_family_counts[source_family] >= source_family_cap
            ):
                continue
            selected.append(row)
            keys.add(key)
            project_counts[project] += 1
            commercial_counts[commercial_id] += 1
            commercial_class_counts[commercial_class] += 1
            source_family_counts[source_family] += 1
            count -= 1

    for lane in ("adaptation", "usage", "control"):
        take(buckets.get(lane, []), quotas[lane])
    if len(selected) < limit:
        spill = sorted(
            (row for rows in buckets.values() for row in rows), key=_sort_key
        )
        take(spill, limit - len(selected))
    telemetry = {
        "managed_candidate_count": managed_candidate_count,
        "eligible_candidate_count": sum(len(rows) for rows in buckets.values()),
        "excluded_candidate_count": sum(exclusion_counts.values()),
        "exclusion_reason_counts": dict(sorted(exclusion_counts.items())),
        "comparison_budget_unused_count": max(0, limit - len(selected)),
        "source_project_cap": project_cap,
        "commercial_class_cap": commercial_class_cap,
        "source_family_cap": source_family_cap,
        "commercial_function_cap": commercial_function_cap,
        "selected_source_project_counts": dict(sorted(project_counts.items())),
        "selected_commercial_class_count": len(commercial_class_counts),
        "selected_source_family_count": len(source_family_counts),
        "selection_boundary": (
            "Hard ownership and information gates are never relaxed. Diversity "
            "caps may leave comparison budget unused rather than filling it with "
            "dependency, generic-method, or repeated-family noise."
        ),
    }
    return selected, telemetry


def _signals(components: dict[str, Any]) -> list[str]:
    thresholds = {
        "calls": 0.45,
        "strings": 0.35,
        "capabilities": 0.60,
        "cfg": 0.75,
        "instruction": 0.40,
        "source_shingles": 0.35,
        "exact_body": 1.0,
        "exact_structural": 1.0,
    }
    return sorted(
        name
        for name, threshold in thresholds.items()
        if float(components.get(name) or 0) >= threshold
    )


def _assessment(row: dict[str, Any]) -> tuple[str, list[str], dict[str, bool]]:
    components = row.get("components") or {}
    signals = _signals(components)
    signal_set = set(signals)
    exact = bool(signal_set.intersection({"exact_body", "exact_structural"}))
    structural = bool(
        signal_set.intersection({"source_shingles", "instruction", "cfg"})
    )
    corroborated = len(
        signal_set.intersection({"calls", "strings", "capabilities"})
    ) >= 1
    lane = _lane(row)
    usage_ready = bool(
        lane == "usage"
        and (exact or (structural and corroborated and len(signals) >= 2))
    )
    adaptation_ready = bool(
        lane == "adaptation"
        and (
            "exact_body" in signal_set
            or (
                structural
                and corroborated
                and len(signals) >= 3
                and float(components.get("source_shingles") or 0) >= 0.35
            )
        )
    )
    if adaptation_ready:
        relationship = "open_source_implementation_match_candidate"
    elif usage_ready:
        relationship = "open_source_or_external_usage_candidate"
    elif lane == "control":
        relationship = "control_observation"
    else:
        relationship = "insufficient_managed_deep_evidence"
    return relationship, signals, {
        "usage_review": usage_ready,
        "adaptation_review": adaptation_ready,
        "copying_conclusion": False,
    }


def compare_managed_candidates(
    candidates: Iterable[dict[str, Any]],
    output_path: Path,
    summary_path: Path,
    *,
    limit: int = 600,
) -> dict[str, Any]:
    selected, selection_telemetry = _select_bounded(candidates, limit=limit)
    rows: list[dict[str, Any]] = []
    relationship_counts: Counter[str] = Counter()
    lane_counts: Counter[str] = Counter()
    for candidate in selected:
        commercial = candidate.get("commercial") or {}
        source = candidate.get("source") or {}
        relationship, signals, claim = _assessment(candidate)
        relationship_counts[relationship] += 1
        lane_counts[_lane(candidate)] += 1
        rows.append(
            {
                "schema_version": MANAGED_COMPARISON_SCHEMA,
                "comparison_id": stable_id(
                    "managed_deep_comparison",
                    candidate.get("candidate_pair_id"),
                    _source_family(candidate),
                ),
                "candidate_pair_id": candidate.get("candidate_pair_id"),
                "analysis_lane": _lane(candidate),
                "relationship_assessment": relationship,
                "deep_comparison_score": candidate.get("selection_score")
                or candidate.get("retrieval_score"),
                "retrieval_score": candidate.get("retrieval_score"),
                "components": candidate.get("components") or {},
                "independent_signals": signals,
                "independent_signal_count": len(signals),
                "commercial": commercial,
                "source": source,
                "source_family": _source_family(candidate),
                "source_project": _project(candidate),
                "claim_eligibility": claim,
                "conclusion_boundary": (
                    "Managed-code deep comparison ranks source- and bytecode-level "
                    "evidence for review. It does not establish copying, direction, "
                    "intent, or license noncompliance."
                ),
            }
        )
    rows.sort(
        key=lambda row: (
            not bool(
                (row.get("claim_eligibility") or {}).get("adaptation_review")
            ),
            not bool((row.get("claim_eligibility") or {}).get("usage_review")),
            -float(row.get("deep_comparison_score") or 0),
            str(row.get("comparison_id") or ""),
        )
    )
    _write_jsonl(output_path, rows)
    summary = {
        "schema_version": MANAGED_COMPARISON_SCHEMA,
        "status": "completed",
        "comparison_limit": max(0, limit),
        "comparison_count": len(rows),
        "selection": selection_telemetry,
        "analysis_lane_counts": dict(sorted(lane_counts.items())),
        "relationship_counts": dict(sorted(relationship_counts.items())),
        "usage_review_ready_count": sum(
            bool((row.get("claim_eligibility") or {}).get("usage_review"))
            for row in rows
        ),
        "adaptation_review_ready_count": sum(
            bool((row.get("claim_eligibility") or {}).get("adaptation_review"))
            for row in rows
        ),
        "review_ready_project_count": len(
            {
                str(row.get("source_project") or "")
                for row in rows
                if (row.get("claim_eligibility") or {}).get("usage_review")
                or (row.get("claim_eligibility") or {}).get("adaptation_review")
            }
        ),
        "copying_conclusion_supported": False,
        "comparison_path": str(output_path),
        "conclusion_boundary": (
            "This bounded pass reviews retained managed-code candidates only. A zero "
            "result is valid for the searched corpus but is not proof that no reuse "
            "exists outside that corpus."
        ),
    }
    safe_write_json(summary_path, summary)
    return summary
