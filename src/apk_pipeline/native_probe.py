"""Native-only deep probe runner for focused follow-up analysis."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import time
from typing import Any

from .capability_taxonomy import capability_names
from .evidence import unit_id, write_jsonl
from .native_decompiler import build_decompile_plan, run_targeted_decompile
from .phase3_native import (
    _build_native_callgraph,
    _collect_function_features,
    _collect_string_xrefs,
)
from .phase5_evidence import run_phase5_evidence
from .profiles import NativeProbeProfile, load_native_probe_profile
from .utils import ensure_dir, safe_name, safe_write_json


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _library_name(library_path: str) -> str:
    return Path(str(library_path)).name


def _matches_any(text: str, patterns: tuple[str, ...]) -> list[str]:
    lowered = text.lower()
    return [pattern for pattern in patterns if pattern.lower() in lowered]


def _priority_library_score(library_name: str, profile: NativeProbeProfile) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    lowered = library_name.lower()
    for item in profile.priority_libraries:
        if item.lower() == lowered:
            score += 80
            reasons.append(f"profile_priority_library:{item}")
        elif item.lower().replace(".so", "") in lowered:
            score += 45
            reasons.append(f"profile_priority_library_fuzzy:{item}")
    for item in profile.deprioritize_libraries:
        if item.lower() in lowered:
            score -= 100
            reasons.append(f"profile_deprioritized_library:{item}")
    return score, reasons


def _function_seed_score(
    library: dict[str, Any],
    function: dict[str, Any],
    profile: NativeProbeProfile,
) -> tuple[int, list[str]]:
    library_name = str(library.get("name") or _library_name(str(library.get("path") or "")))
    name = str(function.get("name") or "")
    kind = str(function.get("kind") or "")
    capabilities = set(str(item) for item in function.get("capabilities") or [])
    score = int(function.get("score") or 0)
    reasons: list[str] = list(function.get("reasons") or [])

    lib_score, lib_reasons = _priority_library_score(library_name, profile)
    score += lib_score
    reasons.extend(lib_reasons)

    seed_hits = _matches_any(name, profile.seed_name_patterns)
    if seed_hits:
        score += 18 + 4 * min(len(seed_hits), 5)
        reasons.append(f"profile_seed:{','.join(seed_hits[:6])}")

    generic_hits = _matches_any(name, profile.generic_helper_patterns)
    if generic_hits:
        score -= 35
        reasons.append(f"profile_generic_helper:{','.join(generic_hits[:6])}")

    capability_hits = sorted(capabilities.intersection(profile.capability_priorities))
    if capability_hits:
        score += 10 + 3 * len(capability_hits)
        reasons.append(f"profile_capability:{','.join(capability_hits[:6])}")

    if kind == "jni_symbol":
        score += 12
        reasons.append("profile_jni_entry")
    elif kind == "exported_symbol":
        score += 4
        reasons.append("profile_exported_symbol")
    elif kind == "string":
        score -= 20
        reasons.append("profile_string_not_direct_function")

    if name.startswith("PDE") or "PDFOCR" in name or "OCR" in name:
        score += 8
    if "Java_" in name and "adobe" in name.lower():
        score += 10
        reasons.append("profile_adobe_jni_symbol")

    return score, sorted(set(reasons))[:20]


def build_profile_seed_targets(
    function_index: dict[str, Any],
    profile: NativeProbeProfile,
    *,
    max_targets: int,
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for library in function_index.get("libraries") or []:
        library_path = str(library.get("path") or "")
        if not library_path:
            continue
        library_name = str(library.get("name") or _library_name(library_path))
        lib_score, _lib_reasons = _priority_library_score(library_name, profile)
        if lib_score < -50:
            continue
        for function in library.get("functions") or []:
            if not isinstance(function, dict):
                continue
            name = str(function.get("name") or "")
            if not name or function.get("kind") == "string":
                continue
            key = (library_path, name)
            if key in seen:
                continue
            seen.add(key)
            score, reasons = _function_seed_score(library, function, profile)
            has_seed_signal = any(
                reason.startswith("profile_seed:")
                or reason.startswith("profile_capability:")
                or reason in {"profile_adobe_jni_symbol", "profile_jni_entry"}
                for reason in reasons
            )
            has_generic_signal = any(reason.startswith("profile_generic_helper:") for reason in reasons)
            if has_generic_signal and not has_seed_signal:
                continue
            if score < 35:
                continue
            if not has_seed_signal and score < 90:
                continue
            targets.append(
                {
                    "library": library_path,
                    "kind": "profile_seed",
                    "original_kind": function.get("kind"),
                    "name": name,
                    "score": score,
                    "capabilities": capability_names(function.get("capabilities") or []),
                    "reasons": reasons,
                    "profile": profile.name,
                    "library_name": library_name,
                    "source": "native_function_index",
                }
            )

    targets.sort(
        key=lambda item: (
            -int(item.get("score") or 0),
            str(item.get("library_name") or ""),
            str(item.get("name") or ""),
        )
    )
    return targets[:max_targets]


CALL_HEX_RE = re.compile(r"(?:bl|call)?\s*(0x[0-9a-fA-F]+)")
CALL_SYMBOL_RE = re.compile(r"\b((?:fcn|sym|sub)\.[A-Za-z0-9_.$:@+\-]+)")


def _normalize_call_target(value: str) -> str | None:
    text = str(value or "")
    match = CALL_HEX_RE.search(text)
    if match:
        return match.group(1)
    match = CALL_SYMBOL_RE.search(text)
    if match:
        return match.group(1)
    if text.startswith("fcn.") or text.startswith("sym."):
        return text
    return None


def build_expanded_callee_targets(
    decompile_result: dict[str, Any],
    *,
    max_targets: int,
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for result in decompile_result.get("results") or []:
        if not result.get("success"):
            continue
        target = result.get("target") or {}
        library = str(target.get("library") or "")
        features = result.get("function_features") or {}
        if not library:
            continue
        for raw_call in features.get("call_targets") or []:
            name = _normalize_call_target(str(raw_call))
            if not name:
                continue
            key = (library, name)
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                {
                    "library": library,
                    "kind": "internal_callee",
                    "name": name,
                    "score": int(target.get("score") or 0) + 6,
                    "capabilities": target.get("capabilities") or [],
                    "reasons": [
                        "callgraph_expansion",
                        f"caller:{target.get('name')}",
                    ],
                    "profile": target.get("profile"),
                    "source": "native_probe_callgraph_expansion",
                    "caller": target.get("name"),
                }
            )
            if len(targets) >= max_targets:
                return targets
    return targets


def classify_probe_outcome(result: dict[str, Any]) -> dict[str, Any]:
    target = result.get("target") or {}
    features = result.get("function_features") or {}
    if not result.get("success"):
        error = str(result.get("error") or result.get("stderr_tail") or "")
        if "timeout" in error.lower() or "timed out" in error.lower():
            return {
                "outcome": "timeout",
                "outcome_class": "tool_limit",
                "research_value": "unknown",
            }
        if result.get("error") == "library_not_found":
            return {
                "outcome": "library_not_found",
                "outcome_class": "input_error",
                "research_value": "none",
            }
        return {
            "outcome": "decompiler_failed",
            "outcome_class": "tool_or_target_error",
            "research_value": "unknown",
        }

    instructions = int(features.get("instruction_count") or 0)
    blocks = int(features.get("basic_block_count") or 0)
    name = str(target.get("name") or "")
    if instructions == 0:
        return {
            "outcome": "empty_feature",
            "outcome_class": "technical_success_semantic_empty",
            "research_value": "none",
        }
    if instructions <= 5 or name.startswith("PDE"):
        return {
            "outcome": "wrapper_or_import_thunk",
            "outcome_class": "technical_success_semantic_low",
            "research_value": "workflow_only",
        }
    if blocks >= 3 and instructions >= 20:
        return {
            "outcome": "semantic_success",
            "outcome_class": "usable_function_structure",
            "research_value": "function_structure",
        }
    return {
        "outcome": "technical_success",
        "outcome_class": "partial_function_structure",
        "research_value": "limited_function_structure",
    }


def build_probe_review_units(
    decompile_result: dict[str, Any],
    *,
    probe_name: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in decompile_result.get("results") or []:
        target = result.get("target") or {}
        features = result.get("function_features") or {}
        outcome = classify_probe_outcome(result)
        rows.append(
            {
                "unit_id": unit_id("native_probe", probe_name, target.get("library"), target.get("name")),
                "phase": "phase3_native_probe",
                "kind": "native_probe_target",
                "probe": probe_name,
                "library": target.get("library"),
                "library_name": target.get("library_name") or _library_name(str(target.get("library") or "")),
                "name": target.get("name"),
                "target_kind": target.get("kind"),
                "original_kind": target.get("original_kind"),
                "score": target.get("score"),
                "capabilities": target.get("capabilities") or [],
                "reasons": target.get("reasons") or [],
                "success": result.get("success"),
                "tool": result.get("tool"),
                "output_path": result.get("output_path"),
                "error": result.get("error"),
                "outcome": outcome["outcome"],
                "outcome_class": outcome["outcome_class"],
                "research_value": outcome["research_value"],
                "feature_hash": features.get("feature_hash"),
                "pseudocode_fingerprint": features.get("pseudocode_fingerprint"),
                "instruction_count": features.get("instruction_count"),
                "basic_block_count": features.get("basic_block_count"),
                "cfg_edge_count": features.get("cfg_edge_count"),
                "call_targets": features.get("call_targets") or [],
                "string_refs": features.get("string_refs") or [],
            }
        )
    rows.sort(
        key=lambda item: (
            str(item.get("outcome_class") or ""),
            -int(item.get("score") or 0),
            str(item.get("library_name") or ""),
            str(item.get("name") or ""),
        )
    )
    return rows


def _merge_decompile_results(
    first: dict[str, Any],
    second: dict[str, Any] | None,
) -> dict[str, Any]:
    if not second:
        return first
    merged = dict(first)
    merged["status"] = "completed"
    merged["probe_rounds"] = [first, second]
    merged["results"] = list(first.get("results") or []) + list(second.get("results") or [])
    merged["attempted_targets"] = int(first.get("attempted_targets") or 0) + int(second.get("attempted_targets") or 0)
    return merged


def run_native_deep_probe(
    workspace: Path,
    *,
    profile_name: str = "adobe_acrobat_deep",
    native_decompiler: str = "auto",
    max_seed_targets: int | None = None,
    max_decompile_targets: int | None = None,
    max_libraries: int | None = None,
    timeout_per_function: int | None = None,
    timeout_per_app: int | None = None,
    expansion_rounds: int | None = None,
    max_expanded_targets: int | None = None,
    refresh_phase5: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    profile = load_native_probe_profile(profile_name)
    limits = profile.default_limits
    max_seed_targets = max_seed_targets or limits.get("max_seed_targets", 80)
    max_decompile_targets = max_decompile_targets or limits.get("max_decompile_targets", 48)
    max_libraries = max_libraries or limits.get("max_libraries", 8)
    timeout_per_function = timeout_per_function or limits.get("timeout_per_function", 120)
    timeout_per_app = timeout_per_app or limits.get("timeout_per_app", 7200)
    expansion_rounds = limits.get("expansion_rounds", 1) if expansion_rounds is None else expansion_rounds
    max_expanded_targets = max_expanded_targets or limits.get("max_expanded_targets", 24)

    output_dir = ensure_dir(workspace / "phase3_native" / "probes" / safe_name(profile.name))
    summary_path = output_dir / "native_probe_summary.json"
    if summary_path.exists() and not force:
        return _load_json(summary_path)

    function_index_path = workspace / "phase3_native" / "native_function_index.json"
    function_index = _load_json(function_index_path)
    if not function_index:
        raise FileNotFoundError(f"Missing native function index: {function_index_path}")

    seed_targets = build_profile_seed_targets(
        function_index,
        profile,
        max_targets=max_seed_targets,
    )
    safe_write_json(output_dir / "native_probe_targets.json", {"profile": profile.raw, "targets": seed_targets})

    plan = build_decompile_plan(
        seed_targets,
        decompiler=native_decompiler,
        max_targets=max_decompile_targets,
        max_libraries=max_libraries,
        target_capabilities=profile.capability_priorities,
    )
    safe_write_json(output_dir / "native_probe_decompile_plan.json", plan)

    start = time.monotonic()
    first_result = run_targeted_decompile(
        seed_targets,
        output_dir / "decompiled_targets",
        decompiler=native_decompiler,
        timeout_per_function=timeout_per_function,
        timeout_per_app=timeout_per_app,
        max_targets=max_decompile_targets,
        max_libraries=max_libraries,
        target_capabilities=profile.capability_priorities,
    )

    expanded_targets: list[dict[str, Any]] = []
    second_result: dict[str, Any] | None = None
    if expansion_rounds > 0 and first_result.get("results"):
        expanded_targets = build_expanded_callee_targets(first_result, max_targets=max_expanded_targets)
        safe_write_json(output_dir / "native_probe_expanded_targets.json", {"targets": expanded_targets})
        remaining_budget = max(60, timeout_per_app - int(time.monotonic() - start))
        if expanded_targets and remaining_budget > 60:
            second_result = run_targeted_decompile(
                expanded_targets,
                output_dir / "decompiled_expanded_targets",
                decompiler=native_decompiler,
                timeout_per_function=timeout_per_function,
                timeout_per_app=remaining_budget,
                max_targets=max_expanded_targets,
                max_libraries=max_libraries,
                target_capabilities=profile.capability_priorities,
            )

    merged_result = _merge_decompile_results(first_result, second_result)
    safe_write_json(output_dir / "native_probe_decompilation.json", merged_result)

    function_features = _collect_function_features(merged_result)
    write_jsonl(output_dir / "native_probe_function_features.jsonl", function_features)
    string_xrefs = _collect_string_xrefs(merged_result)
    safe_write_json(output_dir / "native_probe_string_xrefs.json", string_xrefs)
    callgraph = _build_native_callgraph(merged_result)
    safe_write_json(output_dir / "native_probe_callgraph.json", callgraph)
    review_units = build_probe_review_units(merged_result, probe_name=profile.name)
    write_jsonl(output_dir / "native_probe_review_units.jsonl", review_units)

    outcome_counts = Counter(str(unit.get("outcome") or "unknown") for unit in review_units)
    research_value_counts = Counter(str(unit.get("research_value") or "unknown") for unit in review_units)
    summary = {
        "schema_version": "2026-07-07.native-probe-summary.v1",
        "profile": profile.raw,
        "workspace": str(workspace),
        "function_index_path": str(function_index_path),
        "seed_target_count": len(seed_targets),
        "expanded_target_count": len(expanded_targets),
        "attempted_targets": merged_result.get("attempted_targets"),
        "successful_decompilations": sum(1 for item in merged_result.get("results") or [] if item.get("success")),
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "research_value_counts": dict(sorted(research_value_counts.items())),
        "function_feature_count": len(function_features),
        "string_xref_function_count": len(string_xrefs),
        "callgraph_node_count": callgraph.get("node_count"),
        "callgraph_edge_count": callgraph.get("edge_count"),
        "paths": {
            "targets": str(output_dir / "native_probe_targets.json"),
            "plan": str(output_dir / "native_probe_decompile_plan.json"),
            "decompilation": str(output_dir / "native_probe_decompilation.json"),
            "function_features": str(output_dir / "native_probe_function_features.jsonl"),
            "string_xrefs": str(output_dir / "native_probe_string_xrefs.json"),
            "callgraph": str(output_dir / "native_probe_callgraph.json"),
            "review_units": str(output_dir / "native_probe_review_units.jsonl"),
        },
        "phase5_refreshed": False,
    }
    safe_write_json(summary_path, summary)

    if refresh_phase5:
        result = run_phase5_evidence(workspace, force=True)
        summary["phase5_refreshed"] = result.success
        summary["phase5_details"] = result.details
        safe_write_json(summary_path, summary)

    return summary
