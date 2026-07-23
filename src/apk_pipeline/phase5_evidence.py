"""Phase 5: compact research evidence packet for downstream review."""

from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

from .capability_taxonomy import CAPABILITY_PATTERNS, capability_names
from .evidence import unit_id, write_jsonl
from .models import PhaseResult
from .run_context import (
    build_phase_cache_spec,
    cached_phase_result,
    load_valid_phase_cache,
    write_phase_cache,
)
from .utils import ensure_dir, safe_write_json, safe_write_text


PHASE_SCHEMA = "2026-07-23.phase5.v6"
SIMILARITY_UNIT_LIMIT = 250


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _validate_json_source(path: Path, expected_type: type) -> dict[str, Any]:
    record: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "valid": False,
        "expected_type": expected_type.__name__,
    }
    if not path.is_file():
        record["issue"] = "missing"
        return record
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        record["issue"] = "invalid_json"
        record["error"] = repr(exc)
        return record
    if not isinstance(payload, expected_type):
        record["issue"] = "unexpected_type"
        record["actual_type"] = type(payload).__name__
        return record
    record["valid"] = True
    return record


def _phase5_dependency_state(
    workspace: Path,
    *,
    upstream_results: list[PhaseResult] | None,
    require_resources: bool,
) -> dict[str, Any]:
    required_sources: list[tuple[str, Path, type]] = [
        (
            "split_inventory",
            workspace / "phase0_split_inventory" / "split_inventory.json",
            dict,
        ),
        (
            "manifest",
            workspace / "phase1_manifest" / "manifest_summary.json",
            dict,
        ),
        (
            "code_index",
            workspace / "phase2_jadx" / "code_index.json",
            dict,
        ),
        (
            "java_evidence_units",
            workspace / "phase2_jadx" / "java_evidence_units.json",
            list,
        ),
        (
            "native_analysis",
            workspace / "phase3_native" / "native_analysis.json",
            dict,
        ),
        (
            "native_evidence_units",
            workspace / "phase3_native" / "native_evidence_units.json",
            list,
        ),
    ]
    if require_resources:
        required_sources.extend(
            [
                (
                    "resource_inventory",
                    workspace / "phase4_resources" / "resource_inventory.json",
                    dict,
                ),
                (
                    "model_evidence_units",
                    workspace / "phase4_resources" / "model_evidence_units.json",
                    list,
                ),
                (
                    "resource_evidence_units",
                    workspace / "phase4_resources" / "resource_evidence_units.json",
                    list,
                ),
            ]
        )

    source_checks = [
        {
            "name": name,
            **_validate_json_source(path, expected_type),
        }
        for name, path, expected_type in required_sources
    ]
    required_phase_names = [
        "phase0_split_inventory",
        "phase1_manifest",
        "phase2_jadx",
        "phase3_native",
    ]
    if require_resources:
        required_phase_names.append("phase4_resources")
    upstream_status = {
        result.name: result.status
        for result in (upstream_results or [])
        if result.name in required_phase_names
    }
    if upstream_results is None:
        phase_dirs = {
            "phase0_split_inventory": "phase0_split_inventory",
            "phase1_manifest": "phase1_manifest",
            "phase2_jadx": "phase2_jadx",
            "phase3_native": "phase3_native",
            "phase4_resources": "phase4_resources",
        }
        for phase_name, directory in phase_dirs.items():
            cache_path = workspace / directory / "cache_manifest.json"
            if not cache_path.exists():
                continue
            try:
                cache_payload = json.loads(cache_path.read_text(encoding="utf-8"))
                status = ((cache_payload.get("result") or {}).get("status"))
                if status:
                    upstream_status[phase_name] = str(status)
            except Exception:
                upstream_status[phase_name] = "failed"
        for phase_name in required_phase_names:
            upstream_status.setdefault(phase_name, "unknown")
    non_success_upstream = {
        name: status
        for name, status in upstream_status.items()
        if status != "success"
    }
    missing = [item["name"] for item in source_checks if item.get("issue") == "missing"]
    invalid = [
        item["name"]
        for item in source_checks
        if not item.get("valid") and item.get("issue") != "missing"
    ]
    valid_count = sum(1 for item in source_checks if item.get("valid"))
    complete = not missing and not invalid and not non_success_upstream
    return {
        "status": "complete" if complete else "incomplete",
        "complete": complete,
        "required_source_count": len(source_checks),
        "valid_source_count": valid_count,
        "missing_sources": missing,
        "invalid_sources": invalid,
        "upstream_status": upstream_status,
        "non_success_upstream": non_success_upstream,
        "sources": source_checks,
    }


def _capability_label(name: str) -> str:
    for pattern in CAPABILITY_PATTERNS:
        if pattern.name == name:
            return pattern.label
    return name


def _counter_from_dict(payload: dict[str, Any] | None) -> Counter[str]:
    counter: Counter[str] = Counter()
    for key, value in (payload or {}).items():
        try:
            counter[str(key)] += int(value)
        except Exception:
            counter[str(key)] += 1
    return counter


def _collect_capabilities(
    code_index: dict[str, Any],
    native_analysis: dict[str, Any],
    resource_inventory: dict[str, Any],
    split_inventory: dict[str, Any],
) -> dict[str, int]:
    counter: Counter[str] = Counter()
    java_counts = (
        code_index.get("comparison_capability_counts")
        if "comparison_capability_counts" in code_index
        else code_index.get("capability_counts")
    )
    counter.update(_counter_from_dict(java_counts))
    native_counts = (
        native_analysis.get("comparison_capability_counts")
        if "comparison_capability_counts" in native_analysis
        else native_analysis.get("capability_counts")
    )
    counter.update(_counter_from_dict(native_counts))
    counter.update(_counter_from_dict(resource_inventory.get("aggregate_capability_counts")))
    for split in split_inventory.get("splits") or []:
        counter.update(split.get("capabilities") or [])
    return dict(sorted(counter.items()))


def _capability_counts_by_phase(
    code_index: dict[str, Any],
    native_analysis: dict[str, Any],
    resource_inventory: dict[str, Any],
    split_inventory: dict[str, Any],
) -> dict[str, dict[str, int]]:
    split_counts: Counter[str] = Counter()
    for split in split_inventory.get("splits") or []:
        split_counts.update(split.get("capabilities") or [])
    java_counts = (
        code_index.get("comparison_capability_counts")
        if "comparison_capability_counts" in code_index
        else code_index.get("capability_counts")
    )
    native_counts = (
        native_analysis.get("comparison_capability_counts")
        if "comparison_capability_counts" in native_analysis
        else native_analysis.get("capability_counts")
    )
    return {
        "phase0_split_inventory": dict(sorted(split_counts.items())),
        "phase2_java_kotlin": dict(
            sorted(_counter_from_dict(java_counts).items())
        ),
        "phase3_native": dict(
            sorted(_counter_from_dict(native_counts).items())
        ),
        "phase4_resources_models": dict(
            sorted(
                _counter_from_dict(
                    resource_inventory.get("aggregate_capability_counts")
                ).items()
            )
        ),
    }


def _extract_code_snippets(
    code_index: dict[str, Any],
    max_per_capability: int = 12,
    *,
    ownership_categories: set[str] | None = None,
    source_types: set[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    def row_source_type(row: dict[str, Any]) -> str:
        return str(
            row.get("source_type")
            or Path(str(row.get("file") or "")).suffix.lstrip(".")
        ).lower()

    snippets: dict[str, list[dict[str, Any]]] = {}
    for capability, rows in (code_index.get("snippets_by_capability") or {}).items():
        selected = [
            row
            for row in rows
            if (
                ownership_categories is None
                or str(row.get("ownership") or "unknown") in ownership_categories
            )
            and (
                source_types is None
                or not row_source_type(row)
                or row_source_type(row) in source_types
            )
        ]
        snippets[capability] = selected[:max_per_capability]
    return snippets


def _extract_models(resource_inventory: dict[str, Any], max_models: int = 40) -> list[dict[str, Any]]:
    models: list[dict[str, Any]] = []
    for record in resource_inventory.get("records") or []:
        if record.get("kind") != "model":
            continue
        metadata = record.get("model_metadata") or {}
        models.append(
            {
                "apk": record.get("apk"),
                "path": record.get("path"),
                "size_bytes": record.get("size_bytes"),
                "sha256": record.get("sha256"),
                "format": metadata.get("format"),
                "tflite_magic_present": metadata.get("tflite_magic_present"),
                "tflite_magic_offsets": metadata.get("tflite_magic_offsets") or [],
                "embedded_tflite_magic_present": metadata.get("embedded_tflite_magic_present"),
                "likely_wrapped_or_encrypted": metadata.get("likely_wrapped_or_encrypted"),
                "entropy_first_mb": metadata.get("entropy_first_mb"),
                "operator_hints": metadata.get("operator_hints") or [],
                "capabilities": capability_names((metadata.get("capabilities") or {}).keys()),
                "strings_sample": (metadata.get("strings_sample") or [])[:20],
            }
        )
    return models[:max_models]


def _extract_native_targets(
    native_targets: dict[str, Any],
    max_targets: int = 50,
    *,
    ownership_categories: set[str] | None = None,
) -> list[dict[str, Any]]:
    targets = [
        target
        for target in (native_targets.get("targets") or [])
        if ownership_categories is None
        or str((target.get("ownership") or {}).get("category") or "unknown")
        in ownership_categories
    ]
    return targets[:max_targets]


def _extract_native_deep_summary(workspace: Path) -> dict[str, Any]:
    return {
        "toolchain": _load_json(workspace / "phase3_native" / "native_toolchain.json"),
        "decompile_plan": _load_json(workspace / "phase3_native" / "native_decompile_plan.json"),
        "deep_summary": _load_json(workspace / "phase3_native" / "native_deep_summary.json"),
        "function_features": _load_jsonl(workspace / "phase3_native" / "native_function_features.jsonl")[:100],
        "string_xrefs": _load_list(workspace / "phase3_native" / "native_string_xrefs.json")[:100],
        "callgraph": _load_json(workspace / "phase3_native" / "native_callgraph.json"),
        "ida_target_manifest": _load_json(
            workspace / "phase3_native" / "ida_target_manifest.json"
        ),
        "manual_ida_import": _load_json(
            workspace / "phase3_native" / "manual_ida" / "import_summary.json"
        ),
        "ida_handoff": _load_json(
            workspace
            / "phase3_native"
            / "ida_handoff"
            / "ida_handoff_manifest.json"
        ),
    }


def _collect_native_probe_summaries(workspace: Path) -> list[dict[str, Any]]:
    probe_root = workspace / "phase3_native" / "probes"
    summaries: list[dict[str, Any]] = []
    if not probe_root.exists():
        return summaries
    for summary_path in sorted(probe_root.glob("*/native_probe_summary.json")):
        summary = _load_json(summary_path)
        if not summary:
            continue
        enriched = dict(summary)
        enriched.setdefault("summary_path", str(summary_path))
        summaries.append(enriched)
    return summaries


def _extract_urls(code_index: dict[str, Any], native_analysis: dict[str, Any]) -> dict[str, list[str]]:
    code_urls = list((code_index.get("urls") or {}).keys())[:100]
    native_urls: list[str] = []
    for record in native_analysis.get("libraries") or []:
        native_urls.extend(record.get("urls") or [])
    return {
        "code_urls": sorted(set(code_urls))[:100],
        "native_urls": sorted(set(native_urls))[:100],
    }


def _collect_evidence_units(workspace: Path) -> list[dict[str, Any]]:
    sources = [
        workspace / "phase2_jadx" / "java_evidence_units.json",
        workspace / "phase3_native" / "native_evidence_units.json",
        workspace / "phase3_native" / "manual_ida" / "evidence_units.json",
        workspace / "phase4_resources" / "model_evidence_units.json",
        workspace / "phase4_resources" / "resource_evidence_units.json",
    ]
    units: list[dict[str, Any]] = []
    for source in sources:
        for row in _load_list(source):
            enriched = dict(row)
            enriched.setdefault("source_file", str(source))
            enriched.setdefault("unit_id", unit_id(source.name, len(units), row.get("kind"), row.get("file") or row.get("path")))
            units.append(enriched)
    probe_root = workspace / "phase3_native" / "probes"
    if probe_root.exists():
        for source in sorted(probe_root.glob("*/native_probe_review_units.jsonl")):
            for row in _load_jsonl(source):
                enriched = dict(row)
                enriched.setdefault("source_file", str(source))
                enriched.setdefault("unit_id", unit_id(source.name, len(units), row.get("library"), row.get("name")))
                units.append(enriched)
    units.sort(
        key=lambda item: (
            -float(item.get("confidence") or 0),
            item.get("phase") or "",
            item.get("kind") or "",
            item.get("unit_id") or "",
        )
    )
    return units


def _lib_stems(values: list[str]) -> set[str]:
    stems: set[str] = set()
    for value in values:
        text = str(value or "")
        name = Path(text).name
        if name.startswith("lib") and name.endswith(".so"):
            stems.add(name[3:-3])
        elif name.endswith(".so"):
            stems.add(name[:-3])
        else:
            stems.add(name)
    return {item for item in stems if item}


def _jni_prefix(package: str | None, class_name: str | None, method: str) -> str:
    package_part = str(package or "").replace(".", "_")
    class_part = str(class_name or "").replace(".", "_").replace("$", "_")
    base = "_".join(part for part in [package_part, class_part, method] if part)
    return f"Java_{base}" if base else method


def _build_java_native_bridge_map(
    code_index: dict[str, Any],
    native_analysis: dict[str, Any],
    evidence_units: list[dict[str, Any]],
) -> dict[str, Any]:
    native_libraries: dict[str, list[dict[str, Any]]] = defaultdict(list)
    native_targets: list[dict[str, Any]] = []
    for unit in evidence_units:
        if unit.get("kind") == "native_library":
            for stem in _lib_stems([str(unit.get("name") or ""), str(unit.get("library") or "")]):
                native_libraries[stem].append(unit)
        elif unit.get("kind") in {"native_target", "manual_ida_function"}:
            native_targets.append(unit)

    symbol_rows: list[dict[str, Any]] = []
    for library in native_analysis.get("libraries") or []:
        symbol_records = [
            item
            for item in library.get("symbol_records") or []
            if isinstance(item, dict)
        ]
        if not symbol_records:
            names: list[Any] = []
            names.extend(library.get("jni_symbols") or [])
            names.extend(library.get("exported_symbols") or [])
            symbol_records = [{"name": name} for name in names]
        for symbol_record in symbol_records:
            symbol_rows.append(
                {
                    "library": library.get("extracted_path") or library.get("entry"),
                    "library_name": library.get("name"),
                    "library_sha256": library.get("sha256"),
                    "abi": library.get("abi"),
                    "symbol": str(symbol_record.get("name") or ""),
                    "address": symbol_record.get("address"),
                }
            )

    mappings: list[dict[str, Any]] = []
    for record in code_index.get("files") or []:
        native_methods = record.get("native_methods") or []
        load_libraries = record.get("load_libraries") or []
        if not native_methods and not load_libraries:
            continue
        loaded_stems = _lib_stems([str(item) for item in load_libraries])
        loaded_libraries = []
        for stem in sorted(loaded_stems):
            loaded_libraries.extend(native_libraries.get(stem) or [])

        for method in native_methods or [None]:
            expected = _jni_prefix(record.get("package"), record.get("class_name"), str(method or ""))
            candidate_symbols = []
            for row in symbol_rows:
                row_stems = _lib_stems([str(row.get("library_name") or ""), str(row.get("library") or "")])
                if loaded_stems and not loaded_stems.intersection(row_stems):
                    continue
                symbol = str(row.get("symbol") or "")
                if method and (expected in symbol or symbol.endswith(f"_{method}") or f"_{method}__" in symbol):
                    candidate_symbols.append(row)
                elif not method and loaded_stems.intersection(row_stems):
                    candidate_symbols.append(row)
                if len(candidate_symbols) >= 40:
                    break

            candidate_targets = []
            for target in native_targets:
                target_stems = _lib_stems([str(target.get("library") or "")])
                if loaded_stems and not loaded_stems.intersection(target_stems):
                    continue
                name = str(target.get("name") or target.get("symbol") or "")
                if method and not (
                    expected in name or name.endswith(f"_{method}") or f"_{method}__" in name
                ):
                    continue
                candidate_targets.append(
                    {
                        "unit_id": target.get("unit_id"),
                        "library": target.get("library"),
                        "name": target.get("name") or target.get("symbol"),
                        "address": target.get("address"),
                        "abi": target.get("abi"),
                        "score": target.get("score"),
                        "feature_hash": target.get("feature_hash"),
                        "pseudocode_path": target.get("pseudocode_path"),
                        "evidence_source": target.get("evidence_source"),
                        "identity_verification": target.get(
                            "identity_verification"
                        ),
                        "semantic_role": target.get("semantic_role"),
                        "decompiled": target.get("decompiled"),
                        "algorithm_recovered": target.get(
                            "algorithm_recovered"
                        ),
                        "algorithm_body_candidate": target.get(
                            "algorithm_body_candidate"
                        ),
                    }
                )
                if len(candidate_targets) >= 40:
                    break

            mappings.append(
                {
                    "java_file": record.get("file"),
                    "package": record.get("package"),
                    "class_name": record.get("class_name"),
                    "native_method": method,
                    "expected_jni_prefix": expected if method else None,
                    "load_libraries": load_libraries,
                    "matched_native_libraries": [
                        {
                            "unit_id": item.get("unit_id"),
                            "name": item.get("name"),
                            "library": item.get("library"),
                            "abi": item.get("abi"),
                        }
                        for item in loaded_libraries[:40]
                    ],
                    "candidate_symbols": candidate_symbols,
                    "candidate_native_targets": candidate_targets,
                    "confidence": "candidate" if candidate_symbols or candidate_targets else "library_only",
                }
            )

    return {
        "schema_version": "2026-07-23.java-native-bridge-map.v2",
        "mapping_count": len(mappings),
        "mappings": mappings,
        "notes": [
            "JNI matching is conservative and may miss obfuscated, dynamically registered, or overloaded methods.",
            "Use candidate_symbols and candidate_native_targets as review links, not final attribution claims.",
        ],
    }


def _build_evidence_graph(units: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
    app_id = unit_id("app", manifest.get("package"), manifest.get("version_code"), manifest.get("version_name"))
    nodes: list[dict[str, Any]] = [
        {
            "id": app_id,
            "kind": "app",
            "label": manifest.get("package") or manifest.get("app_name") or "app",
        }
    ]
    edges: list[dict[str, Any]] = []
    native_libraries: dict[str, str] = {}

    for unit in units:
        uid = str(unit.get("unit_id"))
        nodes.append(
            {
                "id": uid,
                "kind": unit.get("kind"),
                "phase": unit.get("phase"),
                "label": unit.get("normalized_signature") or unit.get("name") or unit.get("path") or unit.get("file") or uid,
                "capabilities": unit.get("capabilities") or [],
                "confidence": unit.get("confidence"),
            }
        )
        edges.append({"source": app_id, "target": uid, "type": "contains"})
        if unit.get("kind") == "native_library":
            for key in [unit.get("name"), Path(str(unit.get("library") or "")).name]:
                if key:
                    native_libraries[str(key)] = uid

    for unit in units:
        if unit.get("kind") == "native_bridge":
            for library in unit.get("native_libraries") or []:
                candidates = [str(library), f"lib{library}.so", f"{library}.so"]
                for candidate in candidates:
                    target = native_libraries.get(candidate)
                    if target:
                        edges.append({"source": unit["unit_id"], "target": target, "type": "loads_native_library"})
                        break
        if unit.get("kind") in {"native_target", "manual_ida_function"}:
            target_library = native_libraries.get(Path(str(unit.get("library") or "")).name)
            if target_library:
                edges.append(
                    {
                        "source": target_library,
                        "target": unit["unit_id"],
                        "type": (
                            "has_manual_ida_function"
                            if unit.get("kind") == "manual_ida_function"
                            else "has_native_target"
                        ),
                    }
                )

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


def _build_similarity_packet(
    manifest: dict[str, Any],
    split_inventory: dict[str, Any],
    capability_counts: dict[str, int],
    evidence_units: list[dict[str, Any]],
    graph_path: Path,
    *,
    native_deep_summary: dict[str, Any] | None = None,
    native_probe_summaries: list[dict[str, Any]] | None = None,
    bridge_map_path: Path | None = None,
) -> dict[str, Any]:
    kind_counts: Counter[str] = Counter(str(unit.get("kind") or "unknown") for unit in evidence_units)

    def is_java_kotlin_unit(unit: dict[str, Any]) -> bool:
        source_type = str(
            unit.get("source_type")
            or Path(str(unit.get("file") or "")).suffix.lstrip(".")
        ).lower()
        if source_type:
            return source_type in {"java", "kt"}
        return unit.get("kind") != "resource_source"

    def is_dependency_unit(unit: dict[str, Any]) -> bool:
        return (
            unit.get("phase") in {"phase2_jadx", "phase3_native"}
            and str((unit.get("ownership") or {}).get("category") or "unknown")
            in {"third_party", "platform"}
        )

    dependency_java_units = [
        unit
        for unit in evidence_units
        if unit.get("phase") == "phase2_jadx"
        and is_java_kotlin_unit(unit)
        and is_dependency_unit(unit)
    ]
    dependency_native_units = [
        unit
        for unit in evidence_units
        if unit.get("phase") == "phase3_native" and is_dependency_unit(unit)
    ]
    comparison_units = [
        unit
        for unit in evidence_units
        if not is_dependency_unit(unit)
        and not (
            unit.get("phase") == "phase2_jadx"
            and not is_java_kotlin_unit(unit)
        )
    ]

    buckets: dict[tuple[str, str, str], deque[dict[str, Any]]] = {}
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for unit in comparison_units:
        capabilities = sorted(str(value) for value in (unit.get("capabilities") or []))
        key = (
            str(unit.get("phase") or "unknown"),
            str(unit.get("kind") or "unknown"),
            capabilities[0] if capabilities else "<none>",
        )
        grouped[key].append(unit)
    for key, units in grouped.items():
        buckets[key] = deque(
            sorted(
                units,
                key=lambda unit: (
                    -float(unit.get("confidence") or 0),
                    -float(unit.get("score") or 0),
                    str(unit.get("unit_id") or ""),
                ),
            )
        )
    selected_units: list[dict[str, Any]] = []
    active_keys = sorted(buckets)
    while len(selected_units) < SIMILARITY_UNIT_LIMIT and active_keys:
        next_keys: list[tuple[str, str, str]] = []
        for key in active_keys:
            bucket = buckets[key]
            if bucket and len(selected_units) < SIMILARITY_UNIT_LIMIT:
                selected_units.append(bucket.popleft())
            if bucket:
                next_keys.append(key)
        active_keys = next_keys

    high_value = [
        {
            "unit_id": unit.get("unit_id"),
            "kind": unit.get("kind"),
            "phase": unit.get("phase"),
            "source_type": unit.get("source_type"),
            "label": unit.get("normalized_signature") or unit.get("name") or unit.get("path") or unit.get("file"),
            "file": unit.get("file"),
            "path": unit.get("path"),
            "line": unit.get("line"),
            "apk": unit.get("apk"),
            "entry": unit.get("entry"),
            "split": unit.get("split"),
            "package": unit.get("package"),
            "ownership": unit.get("ownership"),
            "class_name": unit.get("class_name"),
            "method_names": unit.get("method_names"),
            "native_methods": unit.get("native_methods"),
            "native_libraries": unit.get("native_libraries"),
            "library": unit.get("library"),
            "library_name": unit.get("library_name"),
            "library_sha256": unit.get("library_sha256"),
            "abi": unit.get("abi"),
            "address": unit.get("address"),
            "symbol": unit.get("symbol"),
            "target_kind": unit.get("target_kind"),
            "name": unit.get("name") or unit.get("symbol"),
            "model_path": unit.get("model_path") or unit.get("path"),
            "sha256": unit.get("sha256"),
            "size_bytes": unit.get("size_bytes"),
            "capabilities": unit.get("capabilities") or [],
            "confidence": unit.get("confidence"),
            "score": unit.get("score"),
            "reasons": unit.get("reasons"),
            "feature_hash": unit.get("feature_hash"),
            "pseudocode_path": unit.get("pseudocode_path"),
            "pseudocode_excerpt": unit.get("pseudocode_excerpt"),
            "pseudocode_fingerprint": unit.get("pseudocode_fingerprint"),
            "evidence_source": unit.get("evidence_source"),
            "identity_verification": unit.get("identity_verification"),
            "decompiled": unit.get("decompiled"),
            "algorithm_recovered": unit.get("algorithm_recovered"),
            "algorithm_body_candidate": unit.get("algorithm_body_candidate"),
            "semantic_role": unit.get("semantic_role"),
            "semantic_confidence": unit.get("semantic_confidence"),
            "semantic_reasons": unit.get("semantic_reasons"),
            "instruction_count": unit.get("instruction_count"),
            "basic_block_count": unit.get("basic_block_count"),
            "cfg_edge_count": unit.get("cfg_edge_count"),
            "call_targets": unit.get("call_targets"),
            "string_refs": unit.get("string_refs"),
            "token_fingerprint": unit.get("token_fingerprint"),
            "token_shingle_signature": unit.get("token_shingle_signature"),
            "graph_fingerprint": unit.get("graph_fingerprint"),
            "subgraph_count": unit.get("subgraph_count"),
            "operator_count": unit.get("operator_count"),
            "tensor_count": unit.get("tensor_count"),
            "operator_counts": unit.get("operator_counts"),
            "source_file": unit.get("source_file"),
        }
        for unit in selected_units
    ]
    available_by_phase_kind = Counter(
        (
            str(unit.get("phase") or "unknown"),
            str(unit.get("kind") or "unknown"),
        )
        for unit in comparison_units
    )
    selected_by_phase_kind = Counter(
        (
            str(unit.get("phase") or "unknown"),
            str(unit.get("kind") or "unknown"),
        )
        for unit in selected_units
    )
    return {
        "schema_version": "2026-07-23.similarity-preparation.v1",
        "app": {
            "package": manifest.get("package"),
            "app_name": manifest.get("app_name"),
            "version_name": manifest.get("version_name"),
            "version_code": manifest.get("version_code"),
        },
        "input": {
            "apk_count": split_inventory.get("apk_count"),
            "split_types": ((split_inventory.get("summary") or {}).get("split_types") or []),
        },
        "capability_counts": capability_counts,
        "evidence_unit_count": len(evidence_units),
        "comparison_evidence_unit_count": len(comparison_units),
        "excluded_dependency_java_unit_count": len(dependency_java_units),
        "excluded_dependency_native_unit_count": len(dependency_native_units),
        "excluded_dependency_unit_count": (
            len(dependency_java_units) + len(dependency_native_units)
        ),
        "evidence_units_by_kind": dict(sorted(kind_counts.items())),
        "high_value_selection": {
            "limit": SIMILARITY_UNIT_LIMIT,
            "available_count": len(comparison_units),
            "selected_count": len(selected_units),
            "excluded_count": max(0, len(comparison_units) - len(selected_units)),
            "selection_rule": (
                "round_robin_by_phase_kind_and_primary_capability_then_"
                "confidence_score_and_unit_id"
            ),
            "complete_evidence_path": str(
                graph_path.parent / "evidence_units.jsonl"
            ),
            "available_by_phase_kind": {
                f"{phase}:{kind}": count
                for (phase, kind), count in sorted(available_by_phase_kind.items())
            },
            "selected_by_phase_kind": {
                f"{phase}:{kind}": count
                for (phase, kind), count in sorted(selected_by_phase_kind.items())
            },
        },
        "high_value_units": high_value,
        "native_deep": {
            "decompiler_status": ((native_deep_summary or {}).get("deep_summary") or {}).get("decompiler_status"),
            "attempted_targets": ((native_deep_summary or {}).get("deep_summary") or {}).get("attempted_targets"),
            "successful_decompilations": ((native_deep_summary or {}).get("deep_summary") or {}).get(
                "successful_decompilations"
            ),
            "selected_decompiler": ((native_deep_summary or {}).get("toolchain") or {}).get("selected_decompiler"),
            "decompile_plan_status": ((native_deep_summary or {}).get("decompile_plan") or {}).get("status"),
            "function_feature_count": len((native_deep_summary or {}).get("function_features") or []),
            "string_xref_function_count": len((native_deep_summary or {}).get("string_xrefs") or []),
            "callgraph_node_count": ((native_deep_summary or {}).get("callgraph") or {}).get("node_count"),
            "callgraph_edge_count": ((native_deep_summary or {}).get("callgraph") or {}).get("edge_count"),
            "ida_candidate_count": (
                (native_deep_summary or {}).get("ida_target_manifest") or {}
            ).get("candidate_count"),
            "ida_review_queue_count": (
                (native_deep_summary or {}).get("ida_target_manifest") or {}
            ).get("review_queue_count"),
            "manual_ida_import": (
                native_deep_summary or {}
            ).get("manual_ida_import") or {},
            "ida_handoff": (native_deep_summary or {}).get("ida_handoff") or {},
        },
        "native_probes": native_probe_summaries or [],
        "graph_path": str(graph_path),
        "java_native_bridge_map_path": str(bridge_map_path) if bridge_map_path else None,
        "notes": [
            "This packet is intended for downstream review and similarity preparation.",
            "Hashes identify exact artifacts; token_fingerprint is exact normalized identity and token_shingle_signature is comparison-ready, but neither is a final similarity score.",
            "Native pseudocode and function features appear when auto/deep native analysis selects targets and an automated adapter is available.",
            "Manual IDA evidence re-verifies the current binary SHA-256 and matches submitted task metadata; it remains distinct from automated radare2/rizin evidence.",
            "decompiled=true records pseudocode production; algorithm_body_candidate is heuristic and algorithm_recovered remains false until research review.",
            "Java capability counts exclude code classified as third-party or platform by default; dependency signals are reported separately.",
            "Capability counts are kept by phase because Java files, native string occurrences, model resources, and split tags are different measurement units.",
        ],
    }


def _render_markdown(packet: dict[str, Any]) -> str:
    manifest = packet.get("manifest") or {}
    capabilities = packet.get("capability_counts") or {}
    lines: list[str] = []

    lines.append("# Mobile App Research Evidence Packet")
    lines.append("")
    completeness = packet.get("completeness") or {}
    lines.append("## Evidence Completeness")
    lines.append(f"- Status: {completeness.get('status') or 'unknown'}")
    if completeness.get("missing_sources"):
        lines.append(f"- Missing sources: {', '.join(completeness['missing_sources'])}")
    if completeness.get("invalid_sources"):
        lines.append(f"- Invalid sources: {', '.join(completeness['invalid_sources'])}")
    if completeness.get("non_success_upstream"):
        lines.append(
            f"- Non-success upstream phases: {completeness.get('non_success_upstream')}"
        )
    lines.append("")
    lines.append("## App Identity")
    lines.append(f"- App name: {manifest.get('app_name') or 'unknown'}")
    lines.append(f"- Package: {manifest.get('package') or 'unknown'}")
    lines.append(f"- Version: {manifest.get('version_name') or 'unknown'} ({manifest.get('version_code') or 'unknown'})")
    sdk = manifest.get("sdk") or {}
    lines.append(f"- SDK: min={sdk.get('min_sdk')}, target={sdk.get('target_sdk')}")
    lines.append("")

    java_attribution = packet.get("java_code_attribution") or {}
    native_attribution = packet.get("native_code_attribution") or {}
    lines.append("## Code Ownership Attribution")
    ownership_counts = (
        java_attribution.get("ownership_code_file_counts")
        or java_attribution.get("ownership_file_counts")
        or {}
    )
    if ownership_counts:
        lines.append("- Java/Kotlin:")
        for ownership, count in sorted(ownership_counts.items()):
            lines.append(f"  - {ownership}: {count} indexed files")
        lines.append(
            "- Similarity-facing Java evidence includes first-party and unknown code; "
            "third-party and platform code is reported separately."
        )
    else:
        lines.append("- Java/Kotlin ownership attribution was unavailable.")
    native_ownership_counts = (
        native_attribution.get("ownership_library_counts") or {}
    )
    if native_ownership_counts:
        lines.append("- Native libraries:")
        for ownership, count in sorted(native_ownership_counts.items()):
            lines.append(f"  - {ownership}: {count} libraries")
    else:
        lines.append("- Native ownership attribution was unavailable.")
    dependency_counts = (
        java_attribution.get("excluded_dependency_capability_counts") or {}
    )
    if dependency_counts:
        lines.append(
            "- Dependency-only capability signals: "
            + ", ".join(
                f"{name}={count}"
                for name, count in sorted(dependency_counts.items())
            )
        )
    lines.append("")

    lines.append("## Input Structure")
    split_summary = (packet.get("split_inventory") or {}).get("summary") or {}
    lines.append(f"- APK count: {(packet.get('split_inventory') or {}).get('apk_count', 0)}")
    lines.append(f"- Split types: {', '.join(split_summary.get('split_types') or []) or 'none'}")
    lines.append(f"- Native APK count: {split_summary.get('native_apk_count', 0)}")
    lines.append(f"- Model APK count: {split_summary.get('model_apk_count', 0)}")
    lines.append("")

    lines.append("## Capability Signals")
    if capabilities:
        for capability in capability_names(capabilities.keys()):
            lines.append(f"- {_capability_label(capability)} (`{capability}`): {capabilities[capability]}")
    else:
        lines.append("- No capability-specific evidence was indexed.")
    lines.append("")

    evidence_summary = packet.get("evidence_units_summary") or {}
    lines.append("## Structured Evidence Units")
    if evidence_summary.get("total"):
        lines.append(f"- Total units: {evidence_summary.get('total')}")
        for kind, count in sorted((evidence_summary.get("by_kind") or {}).items()):
            lines.append(f"- {kind}: {count}")
        lines.append(f"- JSONL: {evidence_summary.get('jsonl_path')}")
        lines.append(f"- Similarity-ready packet: {evidence_summary.get('similarity_packet_path')}")
    else:
        lines.append("- No structured evidence units were available.")
    lines.append("")

    permissions = manifest.get("permissions") or []
    dangerous_permissions = manifest.get("dangerous_permissions") or []
    lines.append("## Permissions")
    lines.append(f"- Total permissions: {len(permissions)}")
    lines.append(f"- Sensitive permissions: {', '.join(dangerous_permissions) if dangerous_permissions else 'none detected'}")
    lines.append("")

    models = packet.get("models") or []
    lines.append("## Local Models and High-Value Assets")
    if models:
        for model in models[:25]:
            hints = ", ".join(model.get("operator_hints") or [])
            caps = ", ".join(model.get("capabilities") or [])
            lines.append(
                f"- `{model.get('path')}` ({model.get('format')}, {model.get('size_bytes')} bytes)"
                f"; capabilities={caps or 'unknown'}; hints={hints or 'none'}"
            )
    else:
        lines.append("- No model files were identified.")
    lines.append("")

    native_targets = packet.get("native_targets") or []
    lines.append("## Native Targets")
    if native_targets:
        for target in native_targets[:30]:
            caps = ", ".join(target.get("capabilities") or [])
            reasons = ", ".join(target.get("reasons") or [])
            lines.append(
                f"- `{target.get('name')}` in `{target.get('library')}` "
                f"(abi={target.get('abi') or 'unknown'}, address={target.get('address') or 'unknown'}, "
                f"score={target.get('score')}, kind={target.get('kind')}, "
                f"capabilities={caps or 'unknown'}, reasons={reasons})"
            )
    else:
        lines.append("- No high-value native targets were selected.")
    lines.append("")

    native_deep = packet.get("native_deep") or {}
    deep_summary = native_deep.get("deep_summary") or {}
    toolchain = native_deep.get("toolchain") or {}
    decompile_plan = native_deep.get("decompile_plan") or {}
    lines.append("## Native Deep Evidence")
    lines.append(f"- Selected decompiler: {toolchain.get('selected_decompiler') or 'none'}")
    lines.append(f"- Decompile plan status: {decompile_plan.get('status') or 'unknown'}")
    lines.append(f"- Decompiler status: {deep_summary.get('decompiler_status') or 'unknown'}")
    lines.append(f"- Attempted targets: {deep_summary.get('attempted_targets') or 0}")
    lines.append(f"- Successful decompilations: {deep_summary.get('successful_decompilations') or 0}")
    lines.append(f"- Function feature rows: {len(native_deep.get('function_features') or [])}")
    callgraph = native_deep.get("callgraph") or {}
    lines.append(f"- Callgraph: {callgraph.get('node_count') or 0} nodes, {callgraph.get('edge_count') or 0} edges")
    if (decompile_plan.get("status") or "") == "tool_missing":
        lines.append("- Native pseudocode was not generated because no automated native decompiler was available.")
    lines.append("")

    manual_ida = packet.get("manual_ida") or {}
    ida_manifest = manual_ida.get("target_manifest") or {}
    ida_import = manual_ida.get("import") or {}
    lines.append("## Manual IDA Classroom Evidence")
    lines.append(
        f"- Candidate inventory: {ida_manifest.get('candidate_count') or 0}; "
        f"priority review queue: {ida_manifest.get('review_queue_count') or 0}"
    )
    lines.append(
        f"- Import status: {ida_import.get('status') or 'no_results'}; "
        f"accepted={ida_import.get('accepted_count') or 0}; "
        f"rejected={ida_import.get('rejected_count') or 0}"
    )
    role_counts = ida_import.get("semantic_role_counts") or {}
    lines.append(f"- Semantic roles: {role_counts or {}}")
    lines.append(
        "- A verified IDA pseudocode export is recorded as decompiled; only a "
        "separate substantive-body classification can mark algorithm_recovered=true."
    )
    lines.append(
        "- Manual IDA evidence is stored separately from automated radare2/rizin evidence."
    )
    lines.append("")

    native_probes = packet.get("native_probes") or []
    lines.append("## Native Deep Probes")
    if native_probes:
        for probe in native_probes:
            profile = probe.get("profile") or {}
            paths = probe.get("paths") or {}
            lines.append(f"- Profile: `{profile.get('name') or 'unknown'}`")
            lines.append(f"  - Seed targets: {probe.get('seed_target_count', 0)}")
            lines.append(f"  - Expanded targets: {probe.get('expanded_target_count', 0)}")
            lines.append(f"  - Attempted targets: {probe.get('attempted_targets', 0)}")
            lines.append(f"  - Successful decompilations: {probe.get('successful_decompilations', 0)}")
            lines.append(f"  - Function features: {probe.get('function_feature_count', 0)}")
            lines.append(f"  - Outcome counts: {probe.get('outcome_counts') or {}}")
            if paths.get("review_units"):
                lines.append(f"  - Review units: {paths.get('review_units')}")
    else:
        lines.append("- No native deep probe outputs were found.")
    lines.append("")

    snippets_by_capability = packet.get("code_snippets") or {}
    lines.append("## Code Evidence")
    if snippets_by_capability:
        for capability in capability_names(snippets_by_capability.keys()):
            lines.append(f"### {_capability_label(capability)}")
            for snippet in snippets_by_capability[capability][:10]:
                text = str(snippet.get("text") or "").replace("\n", " ")
                lines.append(f"- `{snippet.get('file')}:{snippet.get('line')}` {text}")
    else:
        lines.append("- No code snippets were indexed.")
    lines.append("")

    urls = packet.get("urls") or {}
    lines.append("## Network and Cloud Clues")
    code_urls = urls.get("code_urls") or []
    native_urls = urls.get("native_urls") or []
    if code_urls or native_urls:
        for url in (code_urls + native_urls)[:80]:
            lines.append(f"- {url}")
    else:
        lines.append("- No explicit URLs were indexed.")
    lines.append("")

    lines.append("## Review Notes")
    lines.append("- Treat obfuscated names, native binaries, and dynamic downloads as uncertainty sources.")
    lines.append("- This packet is evidence for research triage; it is not a legal or security determination.")
    lines.append("- Similarity scoring against open-source projects is intentionally out of scope for this pipeline stage.")
    lines.append("")
    return "\n".join(lines)


def _render_prompt(packet_path: Path) -> str:
    return "\n".join(
        [
            "Use the attached evidence packet to assess the app's local/offline capabilities.",
            "",
            "Tasks:",
            "1. Identify which capabilities appear to run locally on-device.",
            "2. Separate local implementation evidence from cloud/service/dependency evidence.",
            "3. Flag native libraries, model files, and resource files that deserve manual follow-up.",
            "4. Review manual IDA evidence separately from automated native evidence.",
            "5. Distinguish pseudocode produced from substantive algorithm recovered.",
            "6. State what cannot be concluded from the available decompiled evidence.",
            "7. Do not perform open-source similarity scoring unless separate comparison material is provided.",
            "",
            f"Evidence packet: {packet_path}",
        ]
    )


def run_phase5_evidence(
    workspace: Path,
    *,
    force: bool = False,
    run_context: dict[str, Any] | None = None,
    upstream_results: list[PhaseResult] | None = None,
    require_resources: bool | None = None,
) -> PhaseResult:
    if run_context is None:
        run_context = _load_json(workspace / "run_context.json") or None
    if require_resources is None:
        require_resources = bool(
            ((run_context or {}).get("config") or {}).get(
                "resource_scan",
                (workspace / "phase4_resources").exists(),
            )
        )
    output_dir = ensure_dir(workspace / "phase5_evidence")
    packet_json_path = output_dir / "review_packet.json"
    packet_md_path = output_dir / "review_packet.md"
    prompt_path = output_dir / "review_prompt.md"
    evidence_jsonl_path = output_dir / "evidence_units.jsonl"
    graph_path = output_dir / "evidence_graph.json"
    similarity_packet_path = output_dir / "similarity_preparation_packet.json"
    similarity_compatibility_path = output_dir / "similarity_ready_packet.json"
    bridge_map_path = output_dir / "java_native_bridge_map.json"
    cache_path = output_dir / "cache_manifest.json"

    output_paths = [
        packet_json_path,
        packet_md_path,
        prompt_path,
        evidence_jsonl_path,
        graph_path,
        similarity_packet_path,
        similarity_compatibility_path,
        bridge_map_path,
    ]
    upstream_paths = [
        workspace / "phase0_split_inventory" / "split_inventory.json",
        workspace / "phase0_split_inventory" / "cache_manifest.json",
        workspace / "phase1_manifest" / "manifest_summary.json",
        workspace / "phase1_manifest" / "cache_manifest.json",
        workspace / "phase2_jadx" / "code_index.json",
        workspace / "phase2_jadx" / "java_evidence_units.json",
        workspace / "phase2_jadx" / "cache_manifest.json",
        workspace / "phase3_native" / "native_analysis.json",
        workspace / "phase3_native" / "native_evidence_units.json",
        workspace / "phase3_native" / "ida_target_manifest.json",
        workspace / "phase3_native" / "manual_ida" / "import_summary.json",
        workspace / "phase3_native" / "manual_ida" / "evidence_units.json",
        workspace / "phase3_native" / "cache_manifest.json",
    ]
    if require_resources:
        upstream_paths.extend(
            [
                workspace / "phase4_resources" / "resource_inventory.json",
                workspace / "phase4_resources" / "model_evidence_units.json",
                workspace / "phase4_resources" / "resource_evidence_units.json",
                workspace / "phase4_resources" / "cache_manifest.json",
            ]
        )
    upstream_status = {
        result.name: result.status
        for result in (upstream_results or [])
        if result.name != "phase5_evidence"
    }
    cache_spec = build_phase_cache_spec(
        phase="phase5_evidence",
        phase_schema=PHASE_SCHEMA,
        phase_config={
            "require_resources": require_resources,
            "upstream_status": upstream_status,
        },
        upstream_paths=upstream_paths,
        run_context=run_context,
    )
    if not force:
        cached = load_valid_phase_cache(cache_path, cache_spec, output_paths)
        if cached:
            return cached_phase_result("phase5_evidence", output_paths, cached)

    dependency_state = _phase5_dependency_state(
        workspace,
        upstream_results=upstream_results,
        require_resources=require_resources,
    )

    split_inventory = _load_json(workspace / "phase0_split_inventory" / "split_inventory.json")
    manifest = _load_json(workspace / "phase1_manifest" / "manifest_summary.json")
    code_index = _load_json(workspace / "phase2_jadx" / "code_index.json")
    native_analysis = _load_json(workspace / "phase3_native" / "native_analysis.json")
    native_targets = _load_json(workspace / "phase3_native" / "native_targets.json")
    resource_inventory = _load_json(workspace / "phase4_resources" / "resource_inventory.json")
    capability_counts = _collect_capabilities(
        code_index,
        native_analysis,
        resource_inventory,
        split_inventory,
    )
    capability_counts_by_phase = _capability_counts_by_phase(
        code_index,
        native_analysis,
        resource_inventory,
        split_inventory,
    )
    evidence_units = _collect_evidence_units(workspace)
    evidence_kind_counts = Counter(str(unit.get("kind") or "unknown") for unit in evidence_units)
    evidence_graph = _build_evidence_graph(evidence_units, manifest)
    native_deep_summary = _extract_native_deep_summary(workspace)
    native_probe_summaries = _collect_native_probe_summaries(workspace)
    bridge_map = _build_java_native_bridge_map(code_index, native_analysis, evidence_units)
    similarity_packet = _build_similarity_packet(
        manifest,
        split_inventory,
        capability_counts,
        evidence_units,
        graph_path,
        native_deep_summary=native_deep_summary,
        native_probe_summaries=native_probe_summaries,
        bridge_map_path=bridge_map_path,
    )
    java_code_attribution = {
        "app_package": code_index.get("app_package"),
        "ownership_file_counts": code_index.get("ownership_file_counts") or {},
        "ownership_code_file_counts": (
            code_index.get("ownership_code_file_counts") or {}
        ),
        "ownership_policy": code_index.get("ownership_policy") or {},
        "comparison_capability_counts": (
            code_index.get("comparison_capability_counts")
            if "comparison_capability_counts" in code_index
            else code_index.get("capability_counts") or {}
        ),
        "excluded_dependency_capability_counts": (
            code_index.get("excluded_dependency_capability_counts") or {}
        ),
        "non_code_capability_counts": (
            code_index.get("non_code_capability_counts") or {}
        ),
        "capability_metrics": code_index.get("capability_metrics") or {},
        "comparison_capability_metrics": (
            code_index.get("comparison_capability_metrics") or {}
        ),
        "index_coverage": code_index.get("index_coverage"),
        "files_truncated": code_index.get("files_truncated"),
        "files_excluded_count": code_index.get("files_excluded_count"),
    }
    similarity_packet["java_code_attribution"] = java_code_attribution
    native_code_attribution = {
        "ownership_library_counts": (
            native_analysis.get("ownership_library_counts") or {}
        ),
        "ownership_policy": native_analysis.get("ownership_policy") or {},
        "comparison_capability_counts": (
            native_analysis.get("comparison_capability_counts")
            if "comparison_capability_counts" in native_analysis
            else native_analysis.get("capability_counts") or {}
        ),
        "excluded_dependency_capability_counts": (
            native_analysis.get("excluded_dependency_capability_counts") or {}
        ),
    }
    similarity_packet["native_code_attribution"] = native_code_attribution
    similarity_packet["capability_counts_by_phase"] = capability_counts_by_phase
    similarity_packet["capability_count_interpretation"] = (
        "discovery counts with phase-specific denominators; do not compare or sum "
        "them as a homogeneous similarity metric"
    )
    similarity_packet["completeness"] = dependency_state

    packet = {
        "completeness": dependency_state,
        "manifest": manifest,
        "split_inventory": split_inventory,
        "capability_counts": capability_counts,
        "capability_counts_by_phase": capability_counts_by_phase,
        "java_code_attribution": java_code_attribution,
        "native_code_attribution": native_code_attribution,
        "models": _extract_models(resource_inventory),
        "native_targets": _extract_native_targets(
            native_targets,
            ownership_categories={"first_party", "unknown"},
        ),
        "dependency_native_targets": _extract_native_targets(
            native_targets,
            max_targets=20,
            ownership_categories={"third_party", "platform"},
        ),
        "native_deep": native_deep_summary,
        "manual_ida": {
            "target_manifest": {
                "schema_version": (
                    native_deep_summary.get("ida_target_manifest") or {}
                ).get("schema_version"),
                "candidate_count": (
                    native_deep_summary.get("ida_target_manifest") or {}
                ).get("candidate_count"),
                "review_queue_count": (
                    native_deep_summary.get("ida_target_manifest") or {}
                ).get("review_queue_count"),
                "all_candidates_retained": (
                    native_deep_summary.get("ida_target_manifest") or {}
                ).get("all_candidates_retained"),
            },
            "import": native_deep_summary.get("manual_ida_import") or {},
        },
        "native_probes": native_probe_summaries,
        "java_native_bridge_map": {
            "mapping_count": bridge_map.get("mapping_count"),
            "path": str(bridge_map_path),
        },
        "code_snippets": _extract_code_snippets(
            code_index,
            ownership_categories={"first_party", "unknown"},
            source_types={"java", "kt"},
        ),
        "dependency_code_snippets": _extract_code_snippets(
            code_index,
            max_per_capability=4,
            ownership_categories={"third_party", "platform"},
            source_types={"java", "kt"},
        ),
        "urls": _extract_urls(code_index, native_analysis),
        "evidence_units_summary": {
            "total": len(evidence_units),
            "by_kind": dict(sorted(evidence_kind_counts.items())),
            "jsonl_path": str(evidence_jsonl_path),
            "graph_path": str(graph_path),
            "similarity_packet_path": str(similarity_packet_path),
            "legacy_similarity_packet_alias": str(similarity_compatibility_path),
        },
        "source_files": {
            "split_inventory": str(workspace / "phase0_split_inventory" / "split_inventory.json"),
            "manifest": str(workspace / "phase1_manifest" / "manifest_summary.json"),
            "code_index": str(workspace / "phase2_jadx" / "code_index.json"),
            "java_evidence_units": str(workspace / "phase2_jadx" / "java_evidence_units.json"),
            "native_analysis": str(workspace / "phase3_native" / "native_analysis.json"),
            "native_targets": str(workspace / "phase3_native" / "native_targets.json"),
            "native_toolchain": str(workspace / "phase3_native" / "native_toolchain.json"),
            "native_decompile_plan": str(workspace / "phase3_native" / "native_decompile_plan.json"),
            "native_decompilation": str(workspace / "phase3_native" / "native_decompilation.json"),
            "native_function_features": str(workspace / "phase3_native" / "native_function_features.jsonl"),
            "native_string_xrefs": str(workspace / "phase3_native" / "native_string_xrefs.json"),
            "native_callgraph": str(workspace / "phase3_native" / "native_callgraph.json"),
            "native_deep_summary": str(workspace / "phase3_native" / "native_deep_summary.json"),
            "native_evidence_units": str(workspace / "phase3_native" / "native_evidence_units.json"),
            "ida_target_manifest": str(
                workspace / "phase3_native" / "ida_target_manifest.json"
            ),
            "ida_handoff_zip": str(
                workspace / "phase3_native" / "ida_handoff.zip"
            ),
            "ida_handoff_manifest": str(
                workspace
                / "phase3_native"
                / "ida_handoff"
                / "ida_handoff_manifest.json"
            ),
            "manual_ida_import": str(
                workspace
                / "phase3_native"
                / "manual_ida"
                / "import_summary.json"
            ),
            "manual_ida_evidence_units": str(
                workspace
                / "phase3_native"
                / "manual_ida"
                / "evidence_units.json"
            ),
            "resource_inventory": str(workspace / "phase4_resources" / "resource_inventory.json"),
            "model_evidence_units": str(workspace / "phase4_resources" / "model_evidence_units.json"),
            "resource_evidence_units": str(workspace / "phase4_resources" / "resource_evidence_units.json"),
            "native_probes": str(workspace / "phase3_native" / "probes"),
        },
    }

    write_jsonl(evidence_jsonl_path, evidence_units)
    safe_write_json(graph_path, evidence_graph)
    safe_write_json(bridge_map_path, bridge_map)
    safe_write_json(similarity_packet_path, similarity_packet)
    safe_write_json(similarity_compatibility_path, similarity_packet)
    safe_write_json(packet_json_path, packet)
    safe_write_text(packet_md_path, _render_markdown(packet))
    safe_write_text(prompt_path, _render_prompt(packet_md_path))

    if dependency_state["complete"]:
        status = "success"
    elif dependency_state["valid_source_count"] == 0:
        status = "failed"
    else:
        status = "partial"
    warnings = []
    if not dependency_state["complete"]:
        warnings.append(
            "Evidence packet is incomplete; inspect the completeness section before review."
        )
    packet_capability_counts = packet.get("capability_counts")
    packet_capability_names = (
        [str(name) for name in packet_capability_counts]
        if isinstance(packet_capability_counts, dict)
        else []
    )
    result = PhaseResult(
        name="phase5_evidence",
        success=status == "success",
        status=status,
        output_paths=output_paths,
        details={
            "capabilities": capability_names(packet_capability_names),
            "model_count": len(packet["models"]),
            "native_target_count": len(packet["native_targets"]),
            "native_probe_count": len(native_probe_summaries),
            "evidence_unit_count": len(evidence_units),
            "java_native_bridge_mapping_count": bridge_map.get("mapping_count"),
            "similarity_packet": str(similarity_packet_path),
            "packet_md": str(packet_md_path),
            "prompt": str(prompt_path),
            "completeness": dependency_state["status"],
            "missing_source_count": len(dependency_state["missing_sources"]),
            "invalid_source_count": len(dependency_state["invalid_sources"]),
        },
        error=(
            "No valid required evidence sources were available."
            if status == "failed"
            else None
        ),
        warnings=warnings,
    )
    write_phase_cache(cache_path, cache_spec, output_paths, result)
    return result
