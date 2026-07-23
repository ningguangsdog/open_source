"""Task packaging and verified import for manual IDA Classroom analysis."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .capability_taxonomy import capability_names, classify_text
from .evidence import token_fingerprint, unit_id
from .native_semantics import abi_analysis_role, classify_native_semantics
from .utils import (
    atomic_text_writer,
    ensure_dir,
    reset_dir,
    safe_read_text,
    safe_name,
    safe_write_json,
    safe_write_text,
    sha256_file,
)


IDA_TASK_SCHEMA = "2026-07-23.ida-task-manifest.v2"
IDA_RESULT_SCHEMA = "2026-07-23.ida-manual-result.v2"
IDA_IMPORT_SCHEMA = "2026-07-23.ida-import.v2"
CALLABLE_KINDS = {
    "jni_symbol",
    "exported_symbol",
    "profile_seed",
    "internal_callee",
    "address",
}
MODEL_MARKERS = (
    "tflite",
    "tensorflow",
    "onnx",
    "mediapipe",
    "model",
    "tensor",
    "interpreter",
)


def normalize_address(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return hex(value) if value >= 0 else None
    text = str(value).strip().lower()
    try:
        if text.startswith("0x"):
            parsed = int(text, 16)
        elif re.fullmatch(r"[0-9a-f]+", text) and re.search(r"[a-f]", text):
            parsed = int(text, 16)
        else:
            parsed = int(text, 10)
    except ValueError:
        return None
    return hex(parsed) if parsed >= 0 else None


def _lib_stems(values: Iterable[str]) -> set[str]:
    stems: set[str] = set()
    for value in values:
        name = Path(str(value or "")).name
        lowered = name.lower()
        if lowered.startswith("lib") and lowered.endswith(".so"):
            stems.add(lowered[3:-3])
        elif lowered.endswith(".so"):
            stems.add(lowered[:-3])
        elif lowered:
            stems.add(lowered)
    return stems


def _expected_jni_prefix(
    package: str | None,
    class_name: str | None,
    method: str,
) -> str:
    package_part = str(package or "").replace(".", "_")
    class_part = str(class_name or "").replace(".", "_").replace("$", "_")
    base = "_".join(part for part in (package_part, class_part, method) if part)
    return f"Java_{base}" if base else method


def build_java_native_hints(
    code_index: dict[str, Any],
    library_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build conservative Java-to-native links before target ranking."""

    libraries_by_stem: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for library in library_records:
        for stem in _lib_stems(
            [
                str(library.get("name") or ""),
                str(library.get("entry") or ""),
                str(library.get("extracted_path") or ""),
            ]
        ):
            libraries_by_stem[stem].append(library)

    hints: list[dict[str, Any]] = []
    for record in code_index.get("files") or []:
        if not isinstance(record, dict):
            continue
        native_methods = [
            str(item)
            for item in record.get("native_methods") or []
            if str(item).strip()
        ]
        loaded_stems = _lib_stems(
            str(item) for item in record.get("load_libraries") or []
        )
        candidate_libraries: list[dict[str, Any]] = []
        for stem in sorted(loaded_stems):
            candidate_libraries.extend(libraries_by_stem.get(stem) or [])
        if not candidate_libraries and native_methods:
            candidate_libraries = library_records
        if not native_methods and not loaded_stems:
            continue

        for library in candidate_libraries:
            if loaded_stems:
                hints.append(
                    {
                        "library": library.get("extracted_path"),
                        "library_name": library.get("name"),
                        "library_sha256": library.get("sha256"),
                        "abi": library.get("abi"),
                        "symbol": None,
                        "address": None,
                        "java_file": record.get("file"),
                        "java_package": record.get("package"),
                        "java_class": record.get("class_name"),
                        "java_method": None,
                        "expected_jni_prefix": None,
                        "loaded_libraries": sorted(loaded_stems),
                        "match_type": "load_library",
                    }
                )
            symbol_records = library.get("symbol_records") or []
            for method in native_methods:
                expected = _expected_jni_prefix(
                    record.get("package"),
                    record.get("class_name"),
                    method,
                )
                matches: list[dict[str, Any]] = []
                for symbol_record in symbol_records:
                    symbol = str(symbol_record.get("name") or "")
                    if not (
                        expected in symbol
                        or symbol.endswith(f"_{method}")
                        or f"_{method}__" in symbol
                    ):
                        continue
                    matches.append(symbol_record)
                if not matches:
                    continue

                for matched in matches:
                    hints.append(
                        {
                            "library": library.get("extracted_path"),
                            "library_name": library.get("name"),
                            "library_sha256": library.get("sha256"),
                            "abi": library.get("abi"),
                            "symbol": matched.get("name"),
                            "address": normalize_address(matched.get("address")),
                            "java_file": record.get("file"),
                            "java_package": record.get("package"),
                            "java_class": record.get("class_name"),
                            "java_method": method,
                            "expected_jni_prefix": expected,
                            "loaded_libraries": sorted(loaded_stems),
                            "match_type": "jni_symbol",
                        }
                    )

    deduped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for hint in hints:
        key = (
            hint.get("library_sha256"),
            hint.get("abi"),
            hint.get("symbol"),
            hint.get("address"),
            hint.get("java_file"),
            hint.get("java_method"),
        )
        deduped[key] = hint
    return sorted(
        deduped.values(),
        key=lambda item: (
            str(item.get("library_name") or ""),
            str(item.get("abi") or ""),
            str(item.get("symbol") or ""),
            str(item.get("java_file") or ""),
            str(item.get("java_method") or ""),
        ),
    )


def _target_key(
    library: str | None,
    symbol: str | None,
    address: Any,
) -> tuple[str, str, str]:
    return (
        str(library or ""),
        str(symbol or ""),
        str(normalize_address(address) or ""),
    )


def _callgraph_degree(callgraph: dict[str, Any]) -> Counter[tuple[str, str]]:
    nodes = {
        str(node.get("id")): node
        for node in callgraph.get("nodes") or []
        if isinstance(node, dict)
    }
    degree: Counter[tuple[str, str]] = Counter()
    for edge in callgraph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        for node_id in (edge.get("source"), edge.get("target")):
            node = nodes.get(str(node_id))
            if not node:
                continue
            degree[
                (
                    str(node.get("library") or ""),
                    str(node.get("name") or ""),
                )
            ] += 1
    return degree


def build_ida_task_manifest(
    library_records: list[dict[str, Any]],
    function_index: dict[str, Any],
    selected_targets: list[dict[str, Any]],
    *,
    code_index: dict[str, Any] | None = None,
    automated_callgraph: dict[str, Any] | None = None,
    review_limit: int = 120,
) -> dict[str, Any]:
    """Create a complete, deterministic IDA review manifest."""

    code_index = code_index or {}
    automated_callgraph = automated_callgraph or {}
    java_hints = build_java_native_hints(code_index, library_records)
    hints_by_target: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    hints_by_library: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for hint in java_hints:
        hints_by_target[
            _target_key(
                hint.get("library"),
                hint.get("symbol"),
                hint.get("address"),
            )
        ].append(hint)
        hints_by_library[str(hint.get("library") or "")].append(hint)

    selected_by_target = {
        _target_key(
            target.get("library"),
            target.get("name"),
            target.get("address"),
        ): target
        for target in selected_targets
    }
    selected_by_symbol = {
        (str(target.get("library") or ""), str(target.get("name") or "")): target
        for target in selected_targets
    }
    degree = _callgraph_degree(automated_callgraph)
    arm64_available = any(
        str(record.get("abi") or "").lower() == "arm64-v8a"
        for record in library_records
    )
    records_by_path = {
        str(record.get("extracted_path") or record.get("entry") or ""): record
        for record in library_records
    }

    candidates: list[dict[str, Any]] = []
    library_summaries: list[dict[str, Any]] = []
    indexed_by_path = {
        str(item.get("path") or ""): item
        for item in function_index.get("libraries") or []
        if isinstance(item, dict)
    }
    for library_path, library in sorted(records_by_path.items()):
        abi = str(library.get("abi") or "")
        analysis_role = abi_analysis_role(
            abi,
            arm64_available=arm64_available,
        )
        indexed_library = indexed_by_path.get(library_path) or {}
        functions = [
            item
            for item in indexed_library.get("functions") or []
            if isinstance(item, dict) and item.get("kind") in CALLABLE_KINDS
        ]
        model_dependency = (
            "local_ml" in (indexed_library.get("capabilities") or [])
            or any(
                marker in " ".join(
                    str(item.get("value") or "").lower()
                    for item in library.get("interesting_strings") or []
                    if isinstance(item, dict)
                )
                for marker in MODEL_MARKERS
            )
        )
        library_candidate_count = 0
        for function in functions:
            symbol = str(function.get("name") or "")
            address = normalize_address(function.get("address"))
            key = _target_key(library_path, symbol, address)
            selected = (
                selected_by_target.get(key)
                or selected_by_symbol.get((library_path, symbol))
                or {}
            )
            associated_java = hints_by_target.get(key) or [
                hint
                for hint in hints_by_library.get(library_path) or []
                if hint.get("symbol") in {None, symbol}
            ]
            semantic_prior = classify_native_semantics(symbol)
            centrality = degree[(library_path, symbol)]
            raw_base_score = (
                selected.get("score")
                if selected
                else function.get("score")
            )
            try:
                base_score = int(raw_base_score or 0)
            except (TypeError, ValueError):
                base_score = 0
            components = {
                "base_native_score": base_score,
                "java_jni_bridge_bonus": min(24, 12 * len(associated_java)),
                "arm64_priority_bonus": (
                    16
                    if analysis_role == "primary_production"
                    else 6
                    if analysis_role == "secondary_production"
                    else 0
                ),
                "model_dependency_bonus": 10 if model_dependency else 0,
                "callgraph_centrality_bonus": min(16, centrality * 2),
                "wrapper_penalty": (
                    -18 if semantic_prior.get("role") == "wrapper" else 0
                ),
            }
            priority_score = sum(components.values())
            candidate = {
                "task_id": unit_id(
                    "ida_task",
                    library.get("sha256"),
                    abi,
                    address,
                    symbol,
                ),
                "task_type": "function",
                "library": library_path,
                "workspace_relative_path": library.get("workspace_relative_path"),
                "library_name": library.get("name"),
                "library_sha256": library.get("sha256"),
                "abi": abi,
                "abi_analysis_role": analysis_role,
                "symbol": symbol,
                "address": address,
                "size_bytes": function.get("size_bytes"),
                "symbol_source": function.get("symbol_source"),
                "target_kind": function.get("kind"),
                "priority_score": priority_score,
                "score_components": components,
                "capabilities": capability_names(
                    set(function.get("capabilities") or []).union(
                        selected.get("capabilities") or []
                    )
                ),
                "selection_reasons": sorted(
                    set(function.get("reasons") or []).union(
                        selected.get("reasons") or []
                    )
                ),
                "selected_by_automated_ranking": bool(selected),
                "associated_java_methods": associated_java,
                "model_dependency_signal": model_dependency,
                "automated_callgraph_degree": centrality,
                "semantic_role_prior": semantic_prior,
                "review_status": "pending",
            }
            candidates.append(candidate)
            library_candidate_count += 1

        discovery_components = {
            "library_discovery_required": 1,
            "arm64_priority_bonus": (
                16
                if analysis_role == "primary_production"
                else 6
                if analysis_role == "secondary_production"
                else 0
            ),
            "model_dependency_bonus": 10 if model_dependency else 0,
            "java_bridge_bonus": min(
                20,
                4 * len(hints_by_library.get(library_path) or []),
            ),
        }
        candidates.append(
            {
                "task_id": unit_id(
                    "ida_library_discovery",
                    library.get("sha256"),
                    abi,
                ),
                "task_type": "library_discovery",
                "library": library_path,
                "workspace_relative_path": library.get(
                    "workspace_relative_path"
                ),
                "library_name": library.get("name"),
                "library_sha256": library.get("sha256"),
                "abi": abi,
                "abi_analysis_role": analysis_role,
                "symbol": None,
                "address": None,
                "priority_score": sum(discovery_components.values()),
                "score_components": discovery_components,
                "capabilities": indexed_library.get("capabilities") or [],
                "selection_reasons": [
                    (
                        "no_callable_exported_symbols"
                        if not functions
                        else "discover_internal_implementations_beyond_exported_wrappers"
                    )
                ],
                "selected_by_automated_ranking": False,
                "associated_java_methods": hints_by_library.get(library_path)
                or [],
                "model_dependency_signal": model_dependency,
                "semantic_role_prior": {
                    "role": "uncertain",
                    "confidence": "low",
                    "reasons": ["library_level_discovery_required"],
                },
                "review_status": "pending",
            }
        )
        library_candidate_count += 1

        library_summaries.append(
            {
                "library": library_path,
                "workspace_relative_path": library.get("workspace_relative_path"),
                "library_name": library.get("name"),
                "library_sha256": library.get("sha256"),
                "abi": abi,
                "abi_analysis_role": analysis_role,
                "size_bytes": library.get("size_bytes"),
                "ownership": library.get("ownership") or {},
                "model_dependency_signal": model_dependency,
                "candidate_count": library_candidate_count,
                "java_bridge_hint_count": len(
                    hints_by_library.get(library_path) or []
                ),
            }
        )

    candidates.sort(
        key=lambda item: (
            -int(item.get("priority_score") or 0),
            0
            if item.get("abi_analysis_role") == "primary_production"
            else 1,
            str(item.get("library_name") or ""),
            str(item.get("address") or ""),
            str(item.get("symbol") or ""),
        )
    )
    review_limit = max(1, review_limit)
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        bucket_key = (
            str(candidate.get("library_sha256") or ""),
            str(candidate.get("abi") or ""),
        )
        buckets[bucket_key].append(candidate)
    ordered_bucket_keys = sorted(
        buckets,
        key=lambda key: (
            -int(buckets[key][0].get("priority_score") or 0),
            key,
        ),
    )
    diversified: list[dict[str, Any]] = []
    while ordered_bucket_keys and len(diversified) < review_limit:
        remaining_keys: list[tuple[str, str]] = []
        for review_bucket_key in ordered_bucket_keys:
            bucket = buckets[review_bucket_key]
            if bucket and len(diversified) < review_limit:
                diversified.append(bucket.pop(0))
            if bucket:
                remaining_keys.append(review_bucket_key)
        ordered_bucket_keys = remaining_keys

    review_queue = [
        {
            "rank": index,
            "task_id": candidate["task_id"],
            "task_type": candidate.get("task_type"),
            "library": candidate.get("library"),
            "workspace_relative_path": candidate.get("workspace_relative_path"),
            "library_name": candidate.get("library_name"),
            "library_sha256": candidate.get("library_sha256"),
            "abi": candidate.get("abi"),
            "symbol": candidate.get("symbol"),
            "address": candidate.get("address"),
            "priority_score": candidate.get("priority_score"),
            "capabilities": candidate.get("capabilities") or [],
            "selection_reasons": candidate.get("selection_reasons") or [],
            "associated_java_methods": candidate.get("associated_java_methods")
            or [],
            "semantic_role_prior": candidate.get("semantic_role_prior"),
        }
        for index, candidate in enumerate(diversified, start=1)
    ]
    return {
        "schema_version": IDA_TASK_SCHEMA,
        "policy": {
            "primary_abi": "arm64-v8a",
            "x86_role": "cross_validation",
            "automated_native_evidence": (
                "radare2/rizin outputs remain separate from manual IDA evidence"
            ),
            "decompiled_definition": (
                "decompiled means pseudocode was produced; it does not imply that "
                "a core algorithm was recovered"
            ),
            "review_queue_selection": (
                "round_robin_across_library_sha256_and_abi_after_priority_sort"
            ),
        },
        "library_count": len(library_summaries),
        "candidate_count": len(candidates),
        "review_queue_count": len(review_queue),
        "review_queue_limit": review_limit,
        "all_candidates_retained": True,
        "java_native_hint_count": len(java_hints),
        "libraries": library_summaries,
        "review_queue": review_queue,
        "candidates": candidates,
    }


def prepare_manual_ida_workspace(manual_root: Path) -> dict[str, Path]:
    results_dir = ensure_dir(manual_root / "results")
    template_path = manual_root / "result_template.json"
    readme_path = manual_root / "README.txt"
    safe_write_json(
        template_path,
        {
            "schema_version": IDA_RESULT_SCHEMA,
            "task_id": "<copy from ida_target_manifest.json>",
            "library_sha256": "<copy from ida_target_manifest.json>",
            "library_name": "<library file name>",
            "abi": "arm64-v8a",
            "address": "0x0",
            "symbol": "<IDA function name>",
            "ida_version": "<IDA version>",
            "pseudocode_file": "<matching .c or .txt file>",
        },
    )
    safe_write_text(
        readme_path,
        "\n".join(
            [
                "Manual IDA import contract",
                "",
                "1. Select a task from ../ida_target_manifest.json.",
                "2. Save pseudocode as UTF-8 text under this results directory.",
                "3. Save one JSON metadata file per function using result_template.json.",
                "4. Keep the exact task ID, library SHA-256, ABI, address, symbol, and IDA version.",
                "5. Run: python scripts/import_ida_results.py --workspace <workspace> --refresh-phase5",
                "",
                "A produced pseudocode file is recorded as decompiled. Semantic role is",
                "classified separately and may remain uncertain.",
                "",
            ]
        ),
    )
    return {
        "root": manual_root,
        "results_dir": results_dir,
        "template": template_path,
        "readme": readme_path,
        "import_summary": manual_root / "import_summary.json",
        "evidence_units": manual_root / "evidence_units.json",
    }


def export_ida_handoff(
    workspace: Path,
    task_manifest: dict[str, Any],
    *,
    max_libraries: int = 12,
) -> dict[str, Any]:
    """Package a portable, bounded set of ranked libraries for manual IDA review."""

    if max_libraries < 1:
        raise ValueError("max_libraries must be positive")
    phase3_dir = workspace / "phase3_native"
    handoff_dir = reset_dir(phase3_dir / "ida_handoff")
    binaries_dir = ensure_dir(handoff_dir / "binaries")
    candidates_by_task = {
        str(item.get("task_id") or ""): item
        for item in task_manifest.get("candidates") or []
        if isinstance(item, dict)
    }
    selected_libraries: list[dict[str, Any]] = []
    selected_keys: set[tuple[str, str]] = set()
    attempted_keys: set[tuple[str, str]] = set()
    skipped_libraries: list[dict[str, Any]] = []
    selected_tasks: list[dict[str, Any]] = []

    for queued in task_manifest.get("review_queue") or []:
        if not isinstance(queued, dict):
            continue
        candidate = candidates_by_task.get(str(queued.get("task_id") or ""))
        if not candidate:
            continue
        key = (
            str(candidate.get("library_sha256") or "").lower(),
            str(candidate.get("abi") or ""),
        )
        if key not in selected_keys:
            if key in attempted_keys:
                continue
            if len(selected_keys) >= max_libraries:
                continue
            attempted_keys.add(key)
            try:
                source_path = _resolve_library_binary(workspace, candidate)
                actual_sha = sha256_file(source_path).lower()
                if actual_sha != key[0]:
                    raise ValueError(
                        f"hash mismatch: {actual_sha} != {key[0]}"
                    )
                destination_name = "__".join(
                    (
                        f"{len(selected_keys) + 1:02d}",
                        safe_name(key[1] or "unknown_abi"),
                        safe_name(
                            Path(
                                str(
                                    candidate.get("library_name")
                                    or source_path.name
                                )
                            ).stem
                        ),
                        actual_sha[:12],
                    )
                ) + ".so"
                destination = binaries_dir / destination_name
                shutil.copy2(source_path, destination)
            except (OSError, ValueError) as exc:
                skipped_libraries.append(
                    {
                        "library_name": candidate.get("library_name"),
                        "abi": key[1],
                        "library_sha256": key[0],
                        "workspace_relative_path": candidate.get(
                            "workspace_relative_path"
                        ),
                        "error": str(exc),
                    }
                )
                continue
            selected_keys.add(key)
            binary_record = {
                "library_rank": len(selected_keys),
                "library_name": candidate.get("library_name"),
                "abi": key[1],
                "library_sha256": actual_sha,
                "source_workspace_relative_path": candidate.get(
                    "workspace_relative_path"
                ),
                "handoff_path": str(destination.relative_to(handoff_dir)),
                "size_bytes": destination.stat().st_size,
            }
            selected_libraries.append(binary_record)
        if key in selected_keys:
            selected_tasks.append(dict(queued))

    handoff_manifest = {
        "schema_version": "2026-07-23.ida-handoff.v2",
        "source_task_schema": task_manifest.get("schema_version"),
        "status": (
            "partial"
            if skipped_libraries and selected_libraries
            else "failed"
            if skipped_libraries
            else "success"
            if selected_libraries
            else "empty"
        ),
        "selection_policy": (
            "first ranked unique library-and-ABI pairs from the diversified review queue"
        ),
        "max_libraries": max_libraries,
        "selected_library_count": len(selected_libraries),
        "excluded_library_count": max(
            0,
            int(task_manifest.get("library_count") or 0) - len(selected_libraries),
        ),
        "selected_task_count": len(selected_tasks),
        "skipped_library_count": len(skipped_libraries),
        "skipped_libraries": skipped_libraries,
        "libraries": selected_libraries,
        "review_queue": selected_tasks,
    }
    safe_write_json(handoff_dir / "ida_handoff_manifest.json", handoff_manifest)
    safe_write_json(handoff_dir / "ida_target_manifest.json", task_manifest)
    with atomic_text_writer(handoff_dir / "review_queue.csv") as fh:
        fieldnames = [
            "rank",
            "task_id",
            "task_type",
            "library_name",
            "abi",
            "library_sha256",
            "symbol",
            "address",
            "priority_score",
            "capabilities",
            "selection_reasons",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for task in selected_tasks:
            writer.writerow(
                {
                    **{field: task.get(field) for field in fieldnames},
                    "capabilities": ",".join(task.get("capabilities") or []),
                    "selection_reasons": ",".join(
                        task.get("selection_reasons") or []
                    ),
                }
            )
    safe_write_text(
        handoff_dir / "README.txt",
        "\n".join(
            [
                "IDA Classroom handoff",
                "",
                "1. Open binaries in library_rank order.",
                "2. Use review_queue.csv to inspect the ranked functions for each binary.",
                "3. Press F5 in IDA to decompile a selected function.",
                "4. Export pseudocode as UTF-8 text and fill the manual_ida result template.",
                "5. Keep task_id, ABI, address, symbol, and library SHA-256 unchanged.",
                "",
                "This package is a bounded review set. The complete native inventory remains",
                "in phase3_native/native_analysis.json and ida_target_manifest.json.",
                "",
            ]
        ),
    )

    zip_path = phase3_dir / "ida_handoff.zip"
    fd, temp_name = tempfile.mkstemp(
        prefix=".ida_handoff.",
        suffix=".zip",
        dir=str(phase3_dir),
    )
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for path in sorted(item for item in handoff_dir.rglob("*") if item.is_file()):
                archive.write(path, path.relative_to(handoff_dir).as_posix())
        os.replace(temp_path, zip_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    handoff_manifest["zip_path"] = str(zip_path)
    handoff_manifest["zip_size_bytes"] = zip_path.stat().st_size
    safe_write_json(handoff_dir / "ida_handoff_manifest.json", handoff_manifest)
    return handoff_manifest


def _load_result_rows(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
        rows = payload["results"]
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        raise ValueError("IDA result JSON must be an object, a list, or contain results[].")
    if not all(isinstance(item, dict) for item in rows):
        raise ValueError("Every IDA result must be a JSON object.")
    return rows


def _safe_result_text(
    row: dict[str, Any],
    *,
    metadata_path: Path,
    manual_root: Path,
    source_root: Path,
) -> tuple[str, str | None]:
    inline = row.get("pseudocode")
    if inline is not None:
        text = str(inline)
        if len(text.encode("utf-8")) > 5_000_000:
            raise ValueError("Inline pseudocode exceeds the 5 MB import limit.")
        return text, None
    relative = row.get("pseudocode_file")
    if not relative:
        raise ValueError("Missing pseudocode or pseudocode_file.")
    candidate = Path(str(relative))
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        from_metadata = (metadata_path.parent / candidate).resolve()
        from_root = (manual_root / candidate).resolve()
        resolved = from_metadata if from_metadata.exists() else from_root
    allowed_roots = (manual_root.resolve(), source_root.resolve())
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        raise ValueError("pseudocode_file escapes the approved IDA result directories.")
    if not resolved.is_file():
        raise FileNotFoundError(f"Pseudocode file not found: {resolved}")
    if resolved.stat().st_size > 5_000_000:
        raise ValueError("Pseudocode file exceeds the 5 MB import limit.")
    return resolved.read_text(encoding="utf-8", errors="ignore"), str(resolved)


def _candidate_indexes(
    task_manifest: dict[str, Any],
) -> tuple[
    dict[tuple[str, str, str, str], dict[str, Any]],
    dict[tuple[str, str, str], list[dict[str, Any]]],
    dict[tuple[str, str, str], list[dict[str, Any]]],
]:
    exact: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    by_symbol: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    by_address: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate in task_manifest.get("candidates") or []:
        if not isinstance(candidate, dict):
            continue
        sha = str(candidate.get("library_sha256") or "").lower()
        abi = str(candidate.get("abi") or "")
        symbol = str(candidate.get("symbol") or "")
        address = str(normalize_address(candidate.get("address")) or "")
        exact[(sha, abi, symbol, address)] = candidate
        if symbol:
            by_symbol[(sha, abi, symbol)].append(candidate)
        if address:
            by_address[(sha, abi, address)].append(candidate)
    return exact, by_symbol, by_address


def _resolve_library_binary(
    workspace: Path,
    library: dict[str, Any],
) -> Path:
    candidates: list[Path] = []
    workspace_root = workspace.resolve()
    relative = library.get("workspace_relative_path")
    if relative:
        for root in (workspace_root, workspace_root / "phase3_native"):
            relative_candidate = (root / str(relative)).resolve()
            if (
                relative_candidate == workspace_root
                or workspace_root in relative_candidate.parents
            ):
                candidates.append(relative_candidate)
    for field in ("library", "extracted_path"):
        value = library.get(field)
        if not value:
            continue
        candidate = Path(str(value)).expanduser()
        if not candidate.is_absolute():
            candidate = workspace_root / candidate
        candidates.append(candidate.resolve())
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "The extracted library is missing at every recorded path; "
        "rerun Phase 3 or restore the complete workspace."
    )


def import_manual_ida_results(
    workspace: Path,
    *,
    results_dir: Path | None = None,
    task_manifest: dict[str, Any] | None = None,
    library_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate IDA outputs against the exact extracted library and task identity."""

    phase3_dir = workspace / "phase3_native"
    manual_root = phase3_dir / "manual_ida"
    paths = prepare_manual_ida_workspace(manual_root)
    source_dir = (results_dir or paths["results_dir"]).expanduser().resolve()
    task_manifest_path = phase3_dir / "ida_target_manifest.json"
    native_analysis_path = phase3_dir / "native_analysis.json"
    if task_manifest is None:
        task_manifest = (
            json.loads(task_manifest_path.read_text(encoding="utf-8"))
            if task_manifest_path.exists()
            else {}
        )
    if library_records is None:
        native_analysis = (
            json.loads(native_analysis_path.read_text(encoding="utf-8"))
            if native_analysis_path.exists()
            else {}
        )
        library_records = [
            item
            for item in native_analysis.get("libraries") or []
            if isinstance(item, dict)
        ]
    if task_manifest.get("schema_version") != IDA_TASK_SCHEMA:
        raise ValueError(
            "A current ida_target_manifest.json is required before importing IDA results."
        )
    libraries_by_sha: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in library_records:
        sha = str(record.get("sha256") or "").lower()
        if sha:
            libraries_by_sha[sha].append(record)
    exact, by_symbol, by_address = _candidate_indexes(task_manifest)
    metadata_paths = sorted(source_dir.rglob("*.json")) if source_dir.exists() else []
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen_targets: set[tuple[str, str, str]] = set()

    for metadata_path in metadata_paths:
        metadata_resolved = metadata_path.resolve()
        if metadata_resolved != source_dir and source_dir not in metadata_resolved.parents:
            rejected.append(
                {
                    "metadata_path": str(metadata_path),
                    "error": "invalid_path:metadata_file_escapes_results_directory",
                }
            )
            continue
        try:
            metadata_size = metadata_path.stat().st_size
        except OSError as exc:
            rejected.append(
                {
                    "metadata_path": str(metadata_path),
                    "error": f"invalid_path:{type(exc).__name__}:{exc}",
                }
            )
            continue
        if metadata_size > 10_000_000:
            rejected.append(
                {
                    "metadata_path": str(metadata_path),
                    "error": "invalid_json:metadata_file_exceeds_10_mb",
                }
            )
            continue
        try:
            rows = _load_result_rows(metadata_path)
        except Exception as exc:
            rejected.append(
                {
                    "metadata_path": str(metadata_path),
                    "error": f"invalid_json:{type(exc).__name__}:{exc}",
                }
            )
            continue
        for row_index, row in enumerate(rows):
            try:
                schema = str(row.get("schema_version") or "")
                if schema != IDA_RESULT_SCHEMA:
                    raise ValueError(f"Unsupported schema_version: {schema}")
                sha = str(row.get("library_sha256") or "").lower()
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    raise ValueError("library_sha256 must be a 64-character hexadecimal SHA-256.")
                matching_libraries = libraries_by_sha.get(sha) or []
                if not matching_libraries:
                    raise ValueError("library_sha256 does not match this workspace.")
                abi = str(row.get("abi") or "")
                matching_libraries = [
                    item
                    for item in matching_libraries
                    if abi == str(item.get("abi") or "")
                ]
                if not matching_libraries:
                    raise ValueError("ABI does not match the extracted library.")
                submitted_name = str(row.get("library_name") or "")
                if submitted_name:
                    matching_libraries = [
                        item
                        for item in matching_libraries
                        if submitted_name == str(item.get("name") or "")
                    ]
                    if not matching_libraries:
                        raise ValueError(
                            "library_name does not match the extracted library."
                        )
                library = matching_libraries[0]
                library_path = _resolve_library_binary(workspace, library)
                actual_library_sha = sha256_file(library_path).lower()
                if actual_library_sha != sha:
                    raise ValueError(
                        "The current extracted library hash does not match library_sha256."
                    )
                ida_version = str(row.get("ida_version") or "").strip()
                if not ida_version:
                    raise ValueError("ida_version is required.")
                submitted_task_id = str(row.get("task_id") or "").strip()
                if not submitted_task_id:
                    raise ValueError("task_id is required.")
                symbol = str(row.get("symbol") or "").strip()
                address = normalize_address(row.get("address"))
                if not symbol and not address:
                    raise ValueError("At least one of symbol or address is required.")

                candidates: list[dict[str, Any]] = []
                if symbol and address:
                    candidate = exact.get((sha, abi, symbol, address))
                    if candidate:
                        candidates = [candidate]
                    elif by_symbol.get((sha, abi, symbol)) or by_address.get(
                        (sha, abi, address)
                    ):
                        raise ValueError("Submitted symbol and address identify different tasks.")
                elif symbol:
                    candidates = by_symbol.get((sha, abi, symbol)) or []
                elif address:
                    candidates = by_address.get((sha, abi, address)) or []
                if len(candidates) > 1:
                    raise ValueError("Function identity is ambiguous; provide both symbol and address.")
                candidate = candidates[0] if candidates else None
                if not candidate:
                    library_tasks = [
                        item
                        for item in task_manifest.get("candidates") or []
                        if item.get("task_type") == "library_discovery"
                        and str(item.get("library_sha256") or "").lower() == sha
                        and str(item.get("abi") or "") == abi
                    ]
                    if not library_tasks or not address:
                        raise ValueError("Function is not present in ida_target_manifest.json.")
                    discovery_task = next(
                        (
                            item
                            for item in library_tasks
                            if str(item.get("task_id") or "") == submitted_task_id
                        ),
                        None,
                    )
                    if not discovery_task:
                        raise ValueError(
                            "task_id does not match the library discovery task."
                        )
                    identity_verification = (
                        "binary_hash_verified_manual_internal_address"
                    )
                    associated_java = discovery_task.get(
                        "associated_java_methods"
                    ) or []
                else:
                    if submitted_task_id != str(candidate.get("task_id") or ""):
                        raise ValueError("task_id does not match the selected function.")
                    identity_verification = (
                        "binary_hash_verified_manifest_task_metadata_matched"
                    )
                    symbol = symbol or str(candidate.get("symbol") or "")
                    address = address or normalize_address(candidate.get("address"))
                    associated_java = candidate.get("associated_java_methods") or []

                target_identity = (sha, str(address or ""), symbol)
                if target_identity in seen_targets:
                    raise ValueError("Duplicate manual IDA result for the same function.")
                pseudocode, pseudocode_path = _safe_result_text(
                    row,
                    metadata_path=metadata_path,
                    manual_root=manual_root,
                    source_root=source_dir,
                )
                nonempty_lines = [line for line in pseudocode.splitlines() if line.strip()]
                if not nonempty_lines:
                    raise ValueError("Pseudocode is empty.")
                expected_pseudocode_sha = str(row.get("pseudocode_sha256") or "").lower()
                actual_sha = (
                    sha256_file(Path(pseudocode_path))
                    if pseudocode_path
                    else hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()
                )
                if expected_pseudocode_sha:
                    if expected_pseudocode_sha != actual_sha:
                        raise ValueError("pseudocode_sha256 does not match pseudocode content.")

                semantic = classify_native_semantics(
                    symbol,
                    pseudocode=pseudocode,
                    features={
                        "call_targets": re.findall(
                            r"\b(?:sub_[0-9A-Fa-f]+|[A-Za-z_][A-Za-z0-9_:]*)\s*\(",
                            pseudocode,
                        )[:200],
                    },
                )
                classified = classify_text(f"{symbol}\n{pseudocode[:200000]}")
                pseudocode_fingerprint = token_fingerprint(
                    pseudocode,
                    max_chars=200_000,
                )
                evidence = {
                    "unit_id": unit_id(
                        "manual_ida",
                        sha,
                        abi,
                        address,
                        symbol,
                    ),
                    "phase": "phase3_native",
                    "kind": "manual_ida_function",
                    "evidence_source": "ida_classroom_manual",
                    "decompiled": True,
                    "algorithm_body_candidate": semantic.get("role") == "algorithm",
                    "algorithm_recovered": False,
                    "task_id": submitted_task_id,
                    "library": str(library_path),
                    "workspace_relative_path": library.get(
                        "workspace_relative_path"
                    ),
                    "library_name": library.get("name"),
                    "library_sha256": sha,
                    "sha256": sha,
                    "abi": abi,
                    "address": address,
                    "symbol": symbol,
                    "name": symbol,
                    "target_kind": "manual_ida_function",
                    "ida_version": ida_version,
                    "identity_verification": identity_verification,
                    "semantic_role": semantic.get("role"),
                    "semantic_confidence": semantic.get("confidence"),
                    "semantic_reasons": semantic.get("reasons") or [],
                    "capabilities": capability_names(classified.keys()),
                    "associated_java_methods": associated_java,
                    "pseudocode_path": pseudocode_path,
                    "pseudocode_excerpt": pseudocode[:6000],
                    "pseudocode_line_count": len(pseudocode.splitlines()),
                    "pseudocode_nonempty_line_count": len(nonempty_lines),
                    "pseudocode_sha256": actual_sha,
                    "pseudocode_fingerprint": pseudocode_fingerprint,
                    "token_fingerprint": pseudocode_fingerprint,
                    "source_metadata_path": str(metadata_path),
                    "ownership": library.get("ownership") or {},
                    "confidence": (
                        0.82
                        if identity_verification
                        == "binary_hash_verified_manifest_task_metadata_matched"
                        else 0.75
                    ),
                }
                accepted.append(evidence)
                seen_targets.add(target_identity)
            except Exception as exc:
                rejected.append(
                    {
                        "metadata_path": str(metadata_path),
                        "row_index": row_index,
                        "library_sha256": row.get("library_sha256"),
                        "abi": row.get("abi"),
                        "symbol": row.get("symbol"),
                        "address": row.get("address"),
                        "error": f"{type(exc).__name__}:{exc}",
                    }
                )

    if not metadata_paths:
        status = "no_results"
    elif accepted and rejected:
        status = "partial"
    elif accepted:
        status = "success"
    else:
        status = "failed"
    role_counts = Counter(
        str(item.get("semantic_role") or "uncertain") for item in accepted
    )
    summary = {
        "schema_version": IDA_IMPORT_SCHEMA,
        "status": status,
        "results_dir": str(source_dir),
        "metadata_file_count": len(metadata_paths),
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "semantic_role_counts": dict(sorted(role_counts.items())),
        "accepted_unit_ids": [item["unit_id"] for item in accepted],
        "rejected": rejected,
        "evidence_units_path": str(paths["evidence_units"]),
        "notes": [
            "decompiled=true means pseudocode was submitted for a task whose current binary SHA-256 was reverified.",
            "algorithm_body_candidate is a heuristic semantic label; algorithm_recovered remains false until research review confirms substance.",
            "Automated radare2/rizin evidence remains stored separately.",
        ],
    }
    safe_write_json(paths["evidence_units"], accepted)
    safe_write_json(paths["import_summary"], summary)
    return summary
