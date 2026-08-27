"""Phase 3: native library extraction, signals, and target selection."""

from __future__ import annotations

import hashlib
from itertools import chain
import json
import logging
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from .capability_taxonomy import (
    CAPABILITY_PATTERNS,
    capability_names,
    classify_text,
)
from .code_ownership import classify_native_ownership, normalize_hashes
from .deep_candidate_comparison import compare_decompiled_candidates
from .evidence import capability_confidence, compact_list, token_fingerprint, unit_id, write_jsonl
from .ida_backend import run_ida_inventory
from .ida_integration import (
    build_ida_task_manifest,
    build_java_native_hints,
    export_ida_handoff,
    import_manual_ida_results,
    normalize_address,
    prepare_manual_ida_workspace,
)
from .managed_candidate_comparison import compare_managed_candidates
from .models import PhaseResult
from .native_decompiler import (
    AUTOMATED_DECOMPILER_TOOLS,
    available_decompiler,
    build_decompile_plan,
    detect_native_toolchain,
    run_targeted_decompile,
    score_native_text,
    select_native_targets,
)
from .reuse_candidate_retrieval import (
    iter_jsonl,
    native_decompile_targets,
    retrieve_candidates,
    select_candidate_cohorts,
)
from .run_context import (
    build_phase_cache_spec,
    cached_phase_result,
    load_valid_phase_cache,
    write_phase_cache,
)
from .utils import (
    ensure_dir,
    printable_strings_from_bytes,
    reset_dir,
    run_cmd,
    safe_name,
    safe_read_text,
    safe_zip_target,
    safe_write_json,
    sha256_file,
    tool_exists,
    validate_zip,
)


URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
MAX_STRINGS = 20000
MAX_INTERESTING_STRINGS = 500
NATIVE_TOOL_TIMEOUT_SECONDS = 120
AUTO_DEEP_MIN_SCORE = 18
AUTO_DEEP_MIN_CAPABILITY_SCORE = 12
PHASE_SCHEMA = "2026-08-26.phase3.v13"
NATIVE_FULL_INDEX_SCHEMA = "2026-08-24.native-full-index.v2"
REUSE_REVIEW_LIMIT = 5000
MANAGED_DEEP_COMPARISON_LIMIT = 600
NATIVE_DEPTHS = {"none", "basic", "targeted", "auto", "deep"}
NATIVE_DECOMPILERS = {"auto", "none", "ida", "rizin", "radare2", "ghidra", "retdec"}
logger = logging.getLogger(__name__)


def _log_ida_progress(payload: dict[str, Any]) -> None:
    event = str(payload.get("event") or "")
    if event == "reuse_retrieval_checkpoint":
        logger.warning(
            "Reuse retrieval checkpoint: commercial_functions=%s, candidates=%s",
            payload.get("commercial_function_count"),
            payload.get("candidate_pair_count"),
        )
        return
    if not (
        event.startswith("ida_library_")
        or event.startswith("ida_inventory_library_")
    ):
        return
    library = Path(str(payload.get("library") or "unknown")).name
    index = payload.get("index")
    total = payload.get("total")
    if event == "ida_library_start":
        logger.warning(
            "IDA [%s/%s] started %s: %s seeds, %s function budget, %ss timeout",
            index,
            total,
            library,
            payload.get("seed_count"),
            payload.get("function_budget"),
            payload.get("timeout"),
        )
    elif event == "ida_library_heartbeat":
        logger.warning(
            "IDA [%s/%s] still analyzing %s: stage=%s, %ss elapsed, %s/%s functions checkpointed, current=%s (%ss)",
            index,
            total,
            library,
            payload.get("stage"),
            payload.get("elapsed_seconds"),
            payload.get("processed_functions"),
            payload.get("selected_functions"),
            payload.get("current_function"),
            payload.get("function_elapsed_seconds"),
        )
    elif event == "ida_library_finish":
        logger.warning(
            "IDA [%s/%s] finished %s: status=%s, results=%s, successful=%s",
            index,
            total,
            library,
            payload.get("status"),
            payload.get("result_count"),
            payload.get("successful_decompilations"),
        )
    elif event == "ida_inventory_library_start":
        logger.warning(
            "IDA lightweight index [%s/%s] started %s (%ss timeout)",
            index,
            total,
            library,
            payload.get("timeout"),
        )
    elif event == "ida_inventory_library_finish":
        logger.warning(
            "IDA lightweight index [%s/%s] finished %s: status=%s, functions=%s",
            index,
            total,
            library,
            payload.get("status"),
            payload.get("function_count"),
        )
    elif event == "ida_inventory_library_reused":
        logger.warning(
            "IDA lightweight index [%s/%s] reused %s: functions=%s",
            index,
            total,
            library,
            payload.get("function_count"),
        )


def _consolidate_native_inventory(
    backend_summary: dict[str, Any],
    output_path: Path,
    callgraph_output_path: Path | None = None,
) -> dict[str, Any]:
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    callgraph_temporary = (
        callgraph_output_path.with_suffix(callgraph_output_path.suffix + ".tmp")
        if callgraph_output_path is not None
        else None
    )
    function_count = 0
    ownership_counts: Counter[str] = Counter()
    component_function_counts: Counter[str] = Counter()
    capability_counts: Counter[str] = Counter()
    library_counts: Counter[str] = Counter()
    invalid_row_count = 0
    callgraph_edge_count = 0
    callgraph_destination = None
    try:
        if callgraph_temporary is not None:
            callgraph_destination = callgraph_temporary.open("w", encoding="utf-8")
        with temporary.open("w", encoding="utf-8") as destination:
            for library_summary in backend_summary.get("library_summaries") or []:
                inventory_value = library_summary.get("inventory_path")
                inventory_path = Path(str(inventory_value or ""))
                if not inventory_path.is_file():
                    continue
                for row in iter_jsonl(inventory_path):
                    if not row.get("function_id") or not row.get("address"):
                        invalid_row_count += 1
                        continue
                    text = "\n".join(
                        (
                            str(row.get("name") or ""),
                            str(row.get("demangled_name") or ""),
                            " ".join(
                                str(value) for value in row.get("call_targets") or []
                            ),
                            " ".join(
                                str(value) for value in row.get("string_refs") or []
                            ),
                        )
                    )
                    capabilities = capability_names(classify_text(text).keys())
                    row["capabilities"] = capabilities
                    row["coverage_note"] = (
                        "All IDA-discovered functions in this content-unique native "
                        "binary are indexed without requiring Hex-Rays pseudocode. "
                        "Instruction features are bounded by the configured "
                        "per-function scan limit."
                    )
                    destination.write(
                        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
                    )
                    if callgraph_destination is not None:
                        for target_name in row.get("call_targets") or []:
                            callgraph_destination.write(
                                json.dumps(
                                    {
                                        "caller_function_id": row.get("function_id"),
                                        "library_sha256": row.get("library_sha256"),
                                        "caller_address": row.get("address"),
                                        "caller_name": row.get("name"),
                                        "callee_name": target_name,
                                    },
                                    ensure_ascii=False,
                                    sort_keys=True,
                                )
                                + "\n"
                            )
                            callgraph_edge_count += 1
                    function_count += 1
                    ownership_counts.update(
                        [
                            str(
                                (row.get("ownership") or {}).get("category")
                                or "unknown"
                            )
                        ]
                    )
                    ownership = row.get("ownership") or {}
                    component = str(ownership.get("component") or "")
                    vendor = str(ownership.get("vendor") or "")
                    if component:
                        component_function_counts.update(
                            [f"{vendor}: {component}" if vendor else component]
                        )
                    capability_counts.update(capabilities)
                    library_counts.update(
                        [str(row.get("library_sha256") or "unknown")]
                    )
    finally:
        if callgraph_destination is not None:
            callgraph_destination.close()
    temporary.replace(output_path)
    if callgraph_temporary is not None and callgraph_output_path is not None:
        callgraph_temporary.replace(callgraph_output_path)
    return {
        "schema_version": NATIVE_FULL_INDEX_SCHEMA,
        "status": (
            "completed"
            if backend_summary.get("status") == "completed"
            else "partial"
        ),
        "backend_status": backend_summary.get("status"),
        "input_library_count": backend_summary.get("input_library_count", 0),
        "unique_library_count": backend_summary.get("unique_library_count", 0),
        "completed_library_count": backend_summary.get("completed_library_count", 0),
        "indexed_function_count": function_count,
        "callgraph_edge_count": callgraph_edge_count,
        "callgraph_path": (
            str(callgraph_output_path) if callgraph_output_path is not None else None
        ),
        "invalid_row_count": invalid_row_count,
        "ownership_function_counts": dict(sorted(ownership_counts.items())),
        "component_function_counts": dict(
            sorted(component_function_counts.items())
        ),
        "capability_counts": dict(sorted(capability_counts.items())),
        "indexed_library_hash_count": len(library_counts),
        "index_path": str(output_path),
        "backend_summary_path": None,
    }


def _primary_native_projection(
    library_records: list[dict[str, Any]],
) -> tuple[set[str], dict[str, Any]]:
    """Choose one preferred ABI layer per logical library for source retrieval."""

    abi_priority = {
        "arm64-v8a": 0,
        "armeabi-v7a": 1,
        "x86_64": 2,
        "x86": 3,
        "armeabi": 4,
    }
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in library_records:
        path = str(
            record.get("extracted_path")
            or record.get("path")
            or record.get("entry")
            or ""
        )
        logical_name = str(record.get("name") or Path(path).name or path)
        groups.setdefault(logical_name, []).append(record)

    selected_hashes: set[str] = set()
    selected_abi_counts: Counter[str] = Counter()
    excluded_abi_counts: Counter[str] = Counter()
    for records in groups.values():
        best_priority = min(
            abi_priority.get(str(record.get("abi") or ""), 99)
            for record in records
        )
        for record in records:
            abi = str(record.get("abi") or "unknown")
            library_hash = str(record.get("sha256") or "")
            if abi_priority.get(abi, 99) == best_priority and library_hash:
                selected_hashes.add(library_hash)
                selected_abi_counts[abi] += 1
            else:
                excluded_abi_counts[abi] += 1
    return selected_hashes, {
        "policy": "preferred_abi_per_logical_library",
        "logical_library_count": len(groups),
        "selected_library_hash_count": len(selected_hashes),
        "selected_abi_counts": dict(sorted(selected_abi_counts.items())),
        "excluded_abi_counts": dict(sorted(excluded_abi_counts.items())),
        "coverage_boundary": (
            "All ABI inventories remain on disk. Retrieval uses one preferred ABI "
            "layer per logical library to avoid scoring architecture duplicates."
        ),
    }


def _reusable_consolidated_inventory(
    backend_summary: dict[str, Any],
    summary_path: Path,
    index_path: Path,
    callgraph_path: Path,
) -> dict[str, Any] | None:
    previous = _load_json_object(summary_path)
    if (
        backend_summary.get("status") != "completed"
        or int(backend_summary.get("reused_library_count") or 0)
        != int(backend_summary.get("unique_library_count") or 0)
        or previous.get("status") != "completed"
        or int(previous.get("indexed_function_count") or 0)
        != int(backend_summary.get("indexed_function_count") or 0)
        or int(previous.get("completed_library_count") or 0)
        != int(backend_summary.get("completed_library_count") or 0)
        or not index_path.is_file()
        or index_path.stat().st_size <= 0
        or not callgraph_path.is_file()
    ):
        return None
    return {
        **previous,
        "cache_status": "reused",
        "backend_status": backend_summary.get("status"),
    }


def _iter_projected_native_rows(
    path: Path,
    selected_hashes: set[str],
) -> Any:
    for row in iter_jsonl(path):
        if not selected_hashes or str(row.get("library_sha256") or "") in selected_hashes:
            yield row


def _merge_native_targets(
    candidate_targets: list[dict[str, Any]],
    baseline_targets: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for target in [*candidate_targets, *baseline_targets]:
        key = (
            str(target.get("library_sha256") or target.get("library") or ""),
            str(normalize_address(target.get("address")) or ""),
            str(target.get("name") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(target)
        if len(merged) >= max(1, limit):
            break
    return merged


def _load_manifest_package(workspace: Path) -> str | None:
    path = workspace / "phase1_manifest" / "manifest_summary.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    package = payload.get("package") if isinstance(payload, dict) else None
    return str(package).strip() if package else None


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _ida_artifacts_valid(decompilation_path: Path) -> bool:
    payload = _load_json_object(decompilation_path)
    if payload.get("tool") != "ida":
        return True
    for result in payload.get("results") or []:
        if not isinstance(result, dict) or result.get("success") is not True:
            continue
        output_path = Path(str(result.get("output_path") or ""))
        if not output_path.is_file() or output_path.stat().st_size <= 0:
            return False
        expected_hash = str(result.get("pseudocode_sha256") or "")
        if expected_hash and sha256_file(output_path) != expected_hash:
            return False
    return True


def _manual_ida_input_fingerprint(results_dir: Path) -> str:
    digest = hashlib.sha256()
    if not results_dir.exists():
        return digest.hexdigest()
    for path in sorted(item for item in results_dir.rglob("*") if item.is_file()):
        relative = path.relative_to(results_dir).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _native_entries(apk_path: Path) -> list[zipfile.ZipInfo]:
    infos = validate_zip(apk_path)
    with zipfile.ZipFile(apk_path, "r") as zf:
        return [
            info
            for info in infos
            if not info.is_dir()
            and info.filename.lower().startswith("lib/")
            and info.filename.lower().endswith(".so")
        ]


def _extract_native_libraries(apk_paths: list[Path], libs_dir: Path) -> list[dict[str, Any]]:
    ensure_dir(libs_dir)
    records: list[dict[str, Any]] = []
    for apk_path in apk_paths:
        try:
            entries = _native_entries(apk_path)
        except Exception as exc:
            records.append(
                {
                    "apk": str(apk_path),
                    "success": False,
                    "error": repr(exc),
                }
            )
            continue

        apk_out_dir = ensure_dir(
            libs_dir
            / f"{safe_name(apk_path.stem)}-{sha256_file(apk_path)[:12]}"
        )
        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in entries:
                parts = [safe_name(part) for part in Path(info.filename).parts]
                output_path = safe_zip_target(apk_out_dir, "/".join(parts))
                ensure_dir(output_path.parent)
                with zf.open(info, "r") as src, output_path.open("wb") as dst:
                    for chunk in iter(lambda: src.read(1024 * 1024), b""):
                        dst.write(chunk)
                records.append(
                    {
                        "apk": str(apk_path),
                        "entry": info.filename,
                        "abi": Path(info.filename).parts[1] if len(Path(info.filename).parts) > 1 else None,
                        "name": Path(info.filename).name,
                        "extracted_path": str(output_path),
                        "workspace_relative_path": str(
                            output_path.resolve().relative_to(
                                libs_dir.parent.parent.resolve()
                            )
                        ),
                        "size_bytes": info.file_size,
                        "sha256": sha256_file(output_path),
                        "success": True,
                    }
                )
    return records


def _stratified_values(values: list[str], limit: int) -> list[str]:
    if len(values) <= limit:
        return values
    if limit <= 1:
        return values[:limit]
    indexes = {
        round(index * (len(values) - 1) / (limit - 1))
        for index in range(limit)
    }
    return [values[index] for index in sorted(indexes)]


def _sample_binary_bytes(path: Path, *, window_size: int = 8_000_000) -> bytes:
    size = path.stat().st_size
    if size <= window_size * 3:
        return path.read_bytes()
    offsets = (0, max(0, (size - window_size) // 2), size - window_size)
    chunks: list[bytes] = []
    with path.open("rb") as fh:
        for offset in offsets:
            fh.seek(offset)
            chunks.append(fh.read(window_size))
    return b"\0".join(chunks)


def _run_strings(path: Path) -> tuple[list[str], dict[str, Any]]:
    if tool_exists("strings"):
        try:
            completed = run_cmd(
                ["strings", "-a", str(path)],
                check=False,
                timeout=NATIVE_TOOL_TIMEOUT_SECONDS,
            )
            if completed.returncode == 0:
                all_strings = completed.stdout.splitlines()
                selected = _stratified_values(all_strings, MAX_STRINGS)
                return selected, {
                    "method": "gnu_strings_stratified",
                    "discovered_count": len(all_strings),
                    "selected_count": len(selected),
                    "excluded_count": max(0, len(all_strings) - len(selected)),
                    "selection_rule": "evenly_spaced_across_complete_strings_output",
                }
        except Exception:
            pass

    data = _sample_binary_bytes(path)
    selected = printable_strings_from_bytes(
        data,
        min_length=4,
        limit=MAX_STRINGS,
    )
    return selected, {
        "method": "binary_head_middle_tail_windows",
        "discovered_count": None,
        "selected_count": len(selected),
        "excluded_count": None,
        "selection_rule": "8MB windows from head, middle, and tail",
    }


def _extract_symbols(
    path: Path,
) -> tuple[list[str], list[str], list[dict[str, Any]], list[str]]:
    exported: set[str] = set()
    jni: set[str] = set()
    symbol_records: dict[tuple[str, str], dict[str, Any]] = {}
    warnings: list[str] = []

    commands: list[list[str]] = []
    if tool_exists("readelf"):
        commands.append(["readelf", "-Ws", str(path)])
    if tool_exists("llvm-readelf"):
        commands.append(["llvm-readelf", "-Ws", str(path)])
    if tool_exists("nm"):
        commands.append(["nm", "-D", "--defined-only", str(path)])

    for command in commands:
        try:
            completed = run_cmd(
                command,
                check=False,
                timeout=NATIVE_TOOL_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            warnings.append(f"{command[0]} failed: {exc!r}")
            continue
        if completed.returncode != 0:
            warnings.append(f"{command[0]} returned {completed.returncode}")
            continue
        for line in completed.stdout.splitlines():
            if " FUNC " not in line and command[0] != "nm":
                continue
            parts = line.split()
            if not parts:
                continue
            if command[0] == "nm":
                if len(parts) < 3:
                    continue
                raw_address, symbol_type, raw_name = parts[0], parts[-2], parts[-1]
                raw_size = None
                binding = None
                section = None
            else:
                if len(parts) < 8:
                    continue
                raw_address, raw_size = parts[1], parts[2]
                symbol_type, binding, section = parts[3], parts[4], parts[6]
                raw_name = parts[7]
                if symbol_type != "FUNC" or section == "UND":
                    continue
            name = raw_name.split("@@")[0].split("@")[0]
            if not name or name in {"UND", "ABS"}:
                continue
            if len(name) > 200:
                continue
            address = normalize_address(f"0x{raw_address}")
            try:
                size_bytes = int(raw_size) if raw_size is not None else None
            except (TypeError, ValueError):
                size_bytes = None
            exported.add(name)
            if name.startswith("Java_") or "JNI" in name or "jni" in name:
                jni.add(name)
            key = (name, str(address or ""))
            symbol_records[key] = {
                "name": name,
                "address": address,
                "size_bytes": size_bytes,
                "symbol_type": symbol_type,
                "binding": binding,
                "section": section,
                "symbol_source": command[0],
                "is_jni": name in jni,
            }
        if exported:
            break

    records = sorted(
        symbol_records.values(),
        key=lambda item: (
            str(item.get("address") or ""),
            str(item.get("name") or ""),
        ),
    )
    return sorted(exported), sorted(jni), records, warnings


def _interesting_strings(
    strings: list[str],
) -> tuple[list[dict[str, Any]], list[str], dict[str, int], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    capability_counts: Counter[str] = Counter()
    urls: set[str] = set()

    for value in strings:
        classified = classify_text(value)
        found_urls = URL_RE.findall(value)
        if not classified and not found_urls:
            continue
        capabilities = capability_names(classified.keys())
        for capability in capabilities:
            capability_counts[capability] += 1
        urls.update(found_urls)
        if len(rows) < MAX_INTERESTING_STRINGS:
            rows.append(
                {
                    "value": value[:500],
                    "capabilities": capabilities,
                    "urls": found_urls[:20],
                }
            )

    discovered_count = sum(capability_counts.values())
    return (
        rows,
        sorted(urls)[:200],
        dict(capability_counts),
        {
            "matched_capability_occurrence_count": discovered_count,
            "selected_string_count": len(rows),
            "selection_limit": MAX_INTERESTING_STRINGS,
            "selection_rule": "first_matching_strings_from_stratified_input",
        },
    )


def _analyze_library(record: dict[str, Any]) -> dict[str, Any]:
    if not record.get("success"):
        return record

    path = Path(str(record["extracted_path"]))
    strings, string_selection = _run_strings(path)
    interesting, urls, capability_counts, interesting_selection = _interesting_strings(
        strings
    )
    (
        exported_symbols,
        jni_symbols,
        symbol_records,
        symbol_warnings,
    ) = _extract_symbols(path)

    enriched = dict(record)
    enriched.update(
        {
            "string_count_sampled": len(strings),
            "string_selection": string_selection,
            "interesting_string_selection": interesting_selection,
            "interesting_strings": interesting,
            "urls": urls,
            "capability_counts": capability_counts,
            "exported_symbol_count": len(exported_symbols),
            "exported_symbols": exported_symbols,
            "jni_symbol_count": len(jni_symbols),
            "jni_symbols": jni_symbols,
            "symbol_record_count": len(symbol_records),
            "symbol_records": symbol_records,
            "warnings": symbol_warnings,
        }
    )
    return enriched


def _native_attribution_evidence_tokens(
    record: dict[str, Any],
    code_index: dict[str, Any],
) -> tuple[str, ...]:
    """Collect bounded managed-code evidence tied to one loaded library."""

    library_names = {
        Path(str(value or "")).name.casefold()
        for value in (
            record.get("name"),
            record.get("entry"),
            record.get("extracted_path"),
        )
        if value
    }
    library_stems = {
        name[3:-3] if name.startswith("lib") and name.endswith(".so") else name
        for name in library_names
    }
    evidence: set[str] = set()
    for loaded_name in (code_index.get("load_library_calls") or {}):
        normalized = Path(str(loaded_name)).name.casefold()
        normalized_stem = (
            normalized[3:-3]
            if normalized.startswith("lib") and normalized.endswith(".so")
            else normalized.removeprefix("lib").removesuffix(".so")
        )
        if normalized_stem in library_stems:
            evidence.add(f"load_library:{normalized}")
    for source in code_index.get("files") or []:
        if not isinstance(source, dict):
            continue
        loaded = {
            Path(str(value)).name.casefold()
            .removeprefix("lib")
            .removesuffix(".so")
            for value in source.get("load_libraries") or []
            if str(value).strip()
        }
        if not loaded.intersection(library_stems):
            continue
        for value in (
            source.get("package"),
            source.get("class_name"),
            source.get("file"),
            *(source.get("load_libraries") or []),
        ):
            if value:
                evidence.add(str(value).casefold())
        if len(evidence) >= 100:
            break
    return tuple(sorted(evidence))


def _library_id(record: dict[str, Any]) -> str:
    return unit_id(
        "native_library",
        record.get("sha256") or record.get("extracted_path"),
        record.get("abi"),
        record.get("name"),
    )


def _target_score(kind: str, library_path: str, name: str) -> tuple[int, list[str], list[str]]:
    score, capabilities, reasons = score_native_text(f"{library_path} {name}")
    if kind == "jni_symbol":
        score += 10
        reasons.append("jni_symbol")
    elif kind == "exported_symbol":
        score += 4
        reasons.append("exported_symbol")
    elif kind == "string":
        score += 2
        reasons.append("matched_string")
    return score, capability_names(capabilities), sorted(set(reasons))[:12]


def build_native_function_index(
    library_records: list[dict[str, Any]],
    *,
    max_entries_per_library: int | None = None,
) -> dict[str, Any]:
    libraries: list[dict[str, Any]] = []
    aggregate_capabilities: Counter[str] = Counter()

    for record in library_records:
        library_path = str(record.get("extracted_path") or record.get("entry") or "")
        library_caps = capability_names((record.get("capability_counts") or {}).keys())
        aggregate_capabilities.update(library_caps)
        functions: list[dict[str, Any]] = []
        seen_symbols: set[tuple[str, str]] = set()

        for symbol_record in record.get("symbol_records") or []:
            if not isinstance(symbol_record, dict):
                continue
            name = str(symbol_record.get("name") or "")
            address = normalize_address(symbol_record.get("address"))
            if not name:
                continue
            symbol_key = (name, str(address or ""))
            if symbol_key in seen_symbols:
                continue
            seen_symbols.add(symbol_key)
            kind = (
                "jni_symbol"
                if symbol_record.get("is_jni") or name in (record.get("jni_symbols") or [])
                else "exported_symbol"
            )
            score, capabilities, reasons = _target_score(kind, library_path, name)
            functions.append(
                {
                    "kind": kind,
                    "name": name,
                    "address": address,
                    "size_bytes": symbol_record.get("size_bytes"),
                    "symbol_type": symbol_record.get("symbol_type"),
                    "binding": symbol_record.get("binding"),
                    "section": symbol_record.get("section"),
                    "symbol_source": symbol_record.get("symbol_source"),
                    "score": score,
                    "capabilities": capabilities,
                    "reasons": reasons,
                }
            )

        if not seen_symbols:
            for kind, symbols in (
                ("jni_symbol", record.get("jni_symbols") or []),
                ("exported_symbol", record.get("exported_symbols") or []),
            ):
                for symbol in symbols:
                    name = str(symbol)
                    symbol_key = (name, "")
                    if symbol_key in seen_symbols:
                        continue
                    seen_symbols.add(symbol_key)
                    score, capabilities, reasons = _target_score(
                        kind,
                        library_path,
                        name,
                    )
                    functions.append(
                        {
                            "kind": kind,
                            "name": name,
                            "address": None,
                            "size_bytes": None,
                            "symbol_source": "legacy_name_list",
                            "score": score,
                            "capabilities": capabilities,
                            "reasons": reasons,
                        }
                    )

        for item in record.get("interesting_strings") or []:
            value = item.get("value") if isinstance(item, dict) else item
            if not value:
                continue
            name = str(value)
            score, capabilities, reasons = _target_score("string", library_path, name)
            item_capabilities = item.get("capabilities") if isinstance(item, dict) else []
            functions.append(
                {
                    "kind": "string",
                    "name": name[:500],
                    "score": score,
                    "capabilities": capability_names(set(capabilities).union(item_capabilities or [])),
                    "reasons": reasons,
                    "urls": item.get("urls") if isinstance(item, dict) else [],
                }
            )

        functions.sort(
            key=lambda item: (
                -int(item.get("score") or 0),
                item.get("kind") or "",
                item.get("address") or "",
                item.get("name") or "",
            )
        )
        retained_functions = (
            functions
            if max_entries_per_library is None
            else functions[:max_entries_per_library]
        )
        libraries.append(
            {
                "library_id": _library_id(record),
                "apk": record.get("apk"),
                "entry": record.get("entry"),
                "path": library_path,
                "name": record.get("name"),
                "abi": record.get("abi"),
                "sha256": record.get("sha256"),
                "size_bytes": record.get("size_bytes"),
                "capabilities": library_caps,
                "ownership": record.get("ownership") or {},
                "capability_counts": record.get("capability_counts") or {},
                "exported_symbol_count": record.get("exported_symbol_count") or 0,
                "jni_symbol_count": record.get("jni_symbol_count") or 0,
                "interesting_string_count": len(record.get("interesting_strings") or []),
                "function_count_discovered": len(functions),
                "function_count_indexed": len(retained_functions),
                "functions": retained_functions,
                "functions_truncated": (
                    max_entries_per_library is not None
                    and len(functions) > max_entries_per_library
                ),
            }
        )

    libraries.sort(
        key=lambda item: (
            -sum(int(value) for value in (item.get("capability_counts") or {}).values()),
            item.get("name") or "",
            item.get("abi") or "",
        )
    )
    return {
        "library_count": len(libraries),
        "aggregate_capabilities": dict(sorted(aggregate_capabilities.items())),
        "libraries": libraries,
    }


def _decompile_result_map(
    decompile_result: dict[str, Any] | None,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    mapped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for result in (decompile_result or {}).get("results") or []:
        target = result.get("target") or {}
        library = str(target.get("library") or "")
        name = str(target.get("name") or "")
        address = str(normalize_address(target.get("address")) or "")
        if library and name:
            mapped[(library, name, address)] = result
    return mapped


def _collect_function_features(decompile_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in (decompile_result or {}).get("results") or []:
        features = result.get("function_features")
        if isinstance(features, dict):
            enriched = dict(features)
            enriched["decompiler_success"] = result.get("success")
            enriched["pseudocode_path"] = result.get("output_path")
            rows.append(enriched)
    rows.sort(
        key=lambda item: (
            str(item.get("library") or ""),
            -int(item.get("score") or 0),
            str(item.get("name") or ""),
        )
    )
    return rows


def _collect_string_xrefs(decompile_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in (decompile_result or {}).get("results") or []:
        target = result.get("target") or {}
        features = result.get("function_features") or {}
        string_refs = features.get("string_refs") or []
        xrefs = result.get("xrefs") or []
        if not string_refs and not xrefs:
            continue
        rows.append(
            {
                "library": target.get("library"),
                "name": target.get("name"),
                "target_kind": target.get("kind"),
                "score": target.get("score"),
                "capabilities": target.get("capabilities") or [],
                "string_refs": string_refs,
                "xrefs": xrefs[:200] if isinstance(xrefs, list) else [],
                "pseudocode_path": result.get("output_path"),
            }
        )
    return rows


def _build_native_callgraph(decompile_result: dict[str, Any] | None) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for result in (decompile_result or {}).get("results") or []:
        target = result.get("target") or {}
        features = result.get("function_features") or {}
        source = unit_id("native_function", target.get("library"), target.get("name"))
        nodes[source] = {
            "id": source,
            "library": target.get("library"),
            "name": target.get("name"),
            "score": target.get("score"),
            "capabilities": target.get("capabilities") or [],
            "feature_hash": features.get("feature_hash"),
        }
        for call in features.get("call_targets") or []:
            target_id = unit_id("native_call", target.get("library"), call)
            nodes.setdefault(
                target_id,
                {
                    "id": target_id,
                    "library": target.get("library"),
                    "name": call,
                    "kind": "call_target",
                },
            )
            edges.append({"source": source, "target": target_id, "type": "calls"})
    return {
        "schema_version": "2026-07-05.native-callgraph.v1",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def build_native_evidence_units(
    library_records: list[dict[str, Any]],
    targets: list[dict[str, Any]],
    decompile_result: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    decompiled = _decompile_result_map(decompile_result)
    evidence_targets: list[dict[str, Any]] = []
    seen_targets: set[tuple[str, str, str]] = set()
    for candidate in [
        *targets,
        *[
            result.get("target") or {}
            for result in (decompile_result or {}).get("results") or []
            if isinstance(result, dict)
        ],
    ]:
        if not isinstance(candidate, dict):
            continue
        key = (
            str(candidate.get("library") or ""),
            str(candidate.get("name") or ""),
            str(normalize_address(candidate.get("address")) or ""),
        )
        if not key[0] or not key[1] or key in seen_targets:
            continue
        seen_targets.add(key)
        evidence_targets.append(candidate)

    for record in library_records:
        capabilities = capability_names((record.get("capability_counts") or {}).keys())
        interesting_strings = [
            str(item.get("value") if isinstance(item, dict) else item)
            for item in (record.get("interesting_strings") or [])[:80]
        ]
        fingerprint_text = "\n".join(
            [
                str(record.get("entry") or record.get("name") or ""),
                " ".join(capabilities),
                " ".join(record.get("exported_symbols") or []),
                " ".join(interesting_strings),
            ]
        )
        units.append(
            {
                "unit_id": _library_id(record),
                "phase": "phase3_native",
                "kind": "native_library",
                "library_id": _library_id(record),
                "apk": record.get("apk"),
                "entry": record.get("entry"),
                "library": record.get("extracted_path"),
                "name": record.get("name"),
                "abi": record.get("abi"),
                "sha256": record.get("sha256"),
                "size_bytes": record.get("size_bytes"),
                "capabilities": capabilities,
                "ownership": record.get("ownership") or {},
                "exported_symbol_count": record.get("exported_symbol_count") or 0,
                "jni_symbol_count": record.get("jni_symbol_count") or 0,
                "interesting_strings": compact_list(interesting_strings, 80),
                "token_fingerprint": token_fingerprint(fingerprint_text),
                "confidence": capability_confidence(capabilities, len(interesting_strings)),
            }
        )

    for target in evidence_targets:
        key = (
            str(target.get("library") or ""),
            str(target.get("name") or ""),
            str(normalize_address(target.get("address")) or ""),
        )
        result = decompiled.get(key)
        output_path = result.get("output_path") if result else None
        features = result.get("function_features") if result else None
        if not isinstance(features, dict):
            features = {}
        semantic_role = (
            result.get("semantic_role")
            if result and isinstance(result.get("semantic_role"), dict)
            else target.get("semantic_role_prior") or {}
        )
        pseudocode_excerpt = ""
        if output_path:
            pseudocode_excerpt = safe_read_text(Path(output_path), limit=4000)
        capabilities = capability_names(target.get("capabilities") or [])
        score = int(target.get("score") or 0)
        decompiler_success = result.get("success") if result else None
        comparison_eligible = bool(
            decompiler_success is True
            and output_path
            and features.get("pseudocode_fingerprint")
        )
        if comparison_eligible:
            comparison_exclusion_reason = None
        elif result:
            comparison_exclusion_reason = "native_decompilation_failed"
        else:
            comparison_exclusion_reason = "no_native_pseudocode"
        fingerprint_text = "\n".join(
            [
                str(target.get("library") or ""),
                str(target.get("kind") or ""),
                str(target.get("name") or ""),
                pseudocode_excerpt,
            ]
        )
        units.append(
            {
                "unit_id": unit_id(
                    "native_target",
                    target.get("library"),
                    target.get("kind"),
                    target.get("name"),
                    normalize_address(target.get("address")),
                ),
                "phase": "phase3_native",
                "kind": "native_target",
                "library": target.get("library"),
                "target_kind": target.get("kind"),
                "name": target.get("name"),
                "address": normalize_address(target.get("address")),
                "abi": target.get("abi"),
                "library_sha256": target.get("library_sha256"),
                "score": score,
                "capabilities": capabilities,
                "context_capabilities": target.get("context_capabilities") or [],
                "capability_provenance": target.get("capability_provenance"),
                "ownership": target.get("ownership") or {},
                "reasons": target.get("reasons") or [],
                "selection_source": target.get("selection_source"),
                "discovered_by": target.get("discovered_by"),
                "graph_depth_from_seed": target.get("graph_depth_from_seed"),
                "seed_context": target.get("seed_context") or {},
                "origin_seed_candidate": target.get("origin_seed_candidate") or {},
                "analysis_lane": target.get("analysis_lane"),
                "candidate_pair_id": target.get("candidate_pair_id"),
                "commercial_function_id": target.get("commercial_function_id"),
                "source_function_id": target.get("source_function_id"),
                "reuse_candidate": target.get("reuse_candidate") or {},
                "decompiler_success": decompiler_success,
                "decompiler_tool": result.get("tool") if result else None,
                "comparison_eligible": comparison_eligible,
                "comparison_exclusion_reason": comparison_exclusion_reason,
                "pseudocode_path": output_path,
                "pseudocode_sha256": (
                    result.get("pseudocode_sha256") if result else None
                ),
                "pseudocode_excerpt": pseudocode_excerpt[:4000],
                "feature_hash": features.get("feature_hash"),
                "pseudocode_fingerprint": features.get("pseudocode_fingerprint"),
                "semantic_role": semantic_role,
                "evidence_source": (
                    "automated_ida"
                    if result and result.get("tool") == "ida"
                    else "automated_native_decompiler"
                    if result
                    else "native_target_selection"
                ),
                "identity_verification": {
                    "library_sha256": target.get("library_sha256"),
                    "abi": target.get("abi"),
                    "address": normalize_address(target.get("address")),
                },
                "instruction_count": features.get("instruction_count"),
                "basic_block_count": features.get("basic_block_count"),
                "cfg_edge_count": features.get("cfg_edge_count"),
                "call_targets": compact_list(features.get("call_targets") or [], 80),
                "string_refs": compact_list(features.get("string_refs") or [], 80),
                "token_fingerprint": token_fingerprint(fingerprint_text),
                "confidence": (
                    min(
                        0.95,
                        0.35 + min(score, 60) / 100 + 0.05 * len(capabilities),
                    )
                    if comparison_eligible
                    else min(0.35, 0.15 + min(score, 40) / 200)
                ),
            }
        )

    units.sort(
        key=lambda item: (
            -float(item.get("confidence") or 0),
            item.get("kind") or "",
            item.get("name") or "",
        )
    )
    return units


def _auto_decompile_decision(
    targets: list[dict[str, Any]],
    *,
    native_decompiler: str,
    ida_install_dir: str | Path | None = None,
) -> dict[str, Any]:
    tool = available_decompiler(
        native_decompiler,
        ida_install_dir=ida_install_dir,
    )
    callable_targets = [
        target
        for target in targets
        if target.get("kind") in {"jni_symbol", "exported_symbol"}
        or (tool == "ida" and target.get("kind") == "library")
    ]
    if not callable_targets:
        return {
            "attempt": False,
            "reason": "no_callable_native_targets",
            "candidate_count": 0,
            "available_decompiler": available_decompiler(
                native_decompiler,
                ida_install_dir=ida_install_dir,
            ),
        }

    if not tool:
        return {
            "attempt": False,
            "reason": "decompiler_missing",
            "candidate_count": len(callable_targets),
            "available_decompiler": None,
        }
    if tool not in AUTOMATED_DECOMPILER_TOOLS:
        return {
            "attempt": False,
            "reason": "decompiler_adapter_not_automated",
            "candidate_count": len(callable_targets),
            "available_decompiler": tool,
        }

    high_value_targets = [
        target
        for target in callable_targets
        if int(target.get("score") or 0) >= AUTO_DEEP_MIN_SCORE
        or (
            bool(target.get("capabilities"))
            and int(target.get("score") or 0) >= AUTO_DEEP_MIN_CAPABILITY_SCORE
        )
    ]
    if high_value_targets:
        return {
            "attempt": True,
            "reason": "high_value_native_targets",
            "candidate_count": len(callable_targets),
            "high_value_target_count": len(high_value_targets),
            "available_decompiler": tool,
            "top_score": max(int(target.get("score") or 0) for target in high_value_targets),
        }

    return {
        "attempt": False,
        "reason": "low_value_native_targets",
        "candidate_count": len(callable_targets),
        "available_decompiler": tool,
        "top_score": max(int(target.get("score") or 0) for target in callable_targets),
    }


def run_phase3_multi(
    apk_paths: list[Path],
    workspace: Path,
    *,
    force: bool = False,
    native_depth: str = "auto",
    native_max_functions: int = 300,
    native_decompiler: str = "auto",
    native_max_libraries: int = 8,
    native_max_decompile_targets: int = 40,
    native_timeout_per_function: int = 90,
    native_timeout_per_app: int = 3600,
    ida_install_dir: Path | None = None,
    ida_python_executable: Path | None = None,
    ida_max_retries: int = 1,
    ida_callgraph_depth: int = 2,
    ida_review_limit: int = 120,
    ida_handoff_max_libraries: int = 12,
    full_native_index: bool = False,
    full_native_index_timeout_per_library: int = 1200,
    full_native_index_timeout_per_app: int = 14_400,
    full_native_index_max_instructions: int = 512,
    oss_function_index: Path | None = None,
    oss_binary_function_index: Path | None = None,
    reuse_candidate_top_k: int = 10,
    reuse_candidate_min_score: float = 0.28,
    reuse_candidate_decompile_limit: int = 120,
    native_target_capabilities: tuple[str, ...] = (),
    first_party_native_hashes: tuple[str, ...] = (),
    third_party_native_hashes: tuple[str, ...] = (),
    run_context: dict[str, Any] | None = None,
) -> PhaseResult:
    if native_depth not in NATIVE_DEPTHS:
        raise ValueError(
            "native_depth must be one of: " + ", ".join(sorted(NATIVE_DEPTHS))
        )
    if native_decompiler not in NATIVE_DECOMPILERS:
        raise ValueError(
            "native_decompiler must be one of: "
            + ", ".join(sorted(NATIVE_DECOMPILERS))
        )
    positive_values = {
        "native_max_functions": native_max_functions,
        "native_max_libraries": native_max_libraries,
        "native_max_decompile_targets": native_max_decompile_targets,
        "native_timeout_per_function": native_timeout_per_function,
        "native_timeout_per_app": native_timeout_per_app,
        "ida_review_limit": ida_review_limit,
        "ida_handoff_max_libraries": ida_handoff_max_libraries,
        "full_native_index_timeout_per_library": (
            full_native_index_timeout_per_library
        ),
        "full_native_index_timeout_per_app": full_native_index_timeout_per_app,
        "full_native_index_max_instructions": full_native_index_max_instructions,
        "reuse_candidate_top_k": reuse_candidate_top_k,
        "reuse_candidate_decompile_limit": reuse_candidate_decompile_limit,
    }
    invalid_values = [
        name for name, value in positive_values.items() if value <= 0
    ]
    if invalid_values:
        raise ValueError(
            "Native limits and timeout values must be positive: "
            + ", ".join(invalid_values)
        )
    if ida_max_retries < 0 or ida_callgraph_depth < 0:
        raise ValueError("IDA retry count and callgraph depth must be zero or greater.")
    if not 0 <= reuse_candidate_min_score <= 1:
        raise ValueError("reuse_candidate_min_score must be between zero and one")
    if full_native_index:
        if native_decompiler != "ida":
            raise ValueError("full_native_index requires native_decompiler=ida")
        if oss_function_index is None:
            raise ValueError("full_native_index requires oss_function_index")
        oss_function_index = oss_function_index.expanduser().resolve()
        if not oss_function_index.is_file():
            raise FileNotFoundError(
                f"OSS function index not found: {oss_function_index}"
            )
        if oss_binary_function_index is not None:
            oss_binary_function_index = (
                oss_binary_function_index.expanduser().resolve()
            )
            if not oss_binary_function_index.is_file():
                raise FileNotFoundError(
                    "OSS compiled function index not found: "
                    f"{oss_binary_function_index}"
                )
    native_target_capabilities = tuple(
        sorted(
            {
                value.strip()
                for value in native_target_capabilities
                if value and value.strip()
            }
        )
    )
    valid_capabilities = {pattern.name for pattern in CAPABILITY_PATTERNS}
    unknown_capabilities = sorted(
        set(native_target_capabilities) - valid_capabilities
    )
    if unknown_capabilities:
        raise ValueError(
            "Unknown native target capabilities: "
            + ", ".join(unknown_capabilities)
        )
    raw_first_party_hashes = tuple(
        value.strip().lower()
        for value in first_party_native_hashes
        if value.strip()
    )
    raw_third_party_hashes = tuple(
        value.strip().lower()
        for value in third_party_native_hashes
        if value.strip()
    )
    first_party_native_hashes = tuple(sorted(normalize_hashes(raw_first_party_hashes)))
    third_party_native_hashes = tuple(sorted(normalize_hashes(raw_third_party_hashes)))
    invalid_hashes = sorted(
        set(raw_first_party_hashes + raw_third_party_hashes)
        - set(first_party_native_hashes)
        - set(third_party_native_hashes)
    )
    if invalid_hashes:
        raise ValueError(
            "Native ownership hashes must be 64-character hexadecimal SHA-256 values: "
            + ", ".join(invalid_hashes)
        )
    conflicting_hashes = set(first_party_native_hashes).intersection(
        third_party_native_hashes
    )
    if conflicting_hashes:
        raise ValueError(
            "Native hashes cannot be both first-party and third-party: "
            + ", ".join(sorted(conflicting_hashes))
        )
    output_dir = ensure_dir(workspace / "phase3_native")
    libs_dir = output_dir / "libs"
    analysis_path = output_dir / "native_analysis.json"
    targets_path = output_dir / "native_targets.json"
    decompile_path = output_dir / "native_decompilation.json"
    ida_automated_summary_path = output_dir / "ida_automated_summary.json"
    decompile_plan_path = output_dir / "native_decompile_plan.json"
    toolchain_path = output_dir / "native_toolchain.json"
    function_features_path = output_dir / "native_function_features.jsonl"
    string_xrefs_path = output_dir / "native_string_xrefs.json"
    callgraph_path = output_dir / "native_callgraph.json"
    function_index_path = output_dir / "native_function_index.json"
    evidence_units_path = output_dir / "native_evidence_units.json"
    full_index_path = output_dir / "native_full_function_index.jsonl"
    full_callgraph_path = output_dir / "native_full_callgraph.jsonl"
    full_index_summary_path = output_dir / "native_full_index_summary.json"
    reuse_candidates_path = output_dir / "reuse_candidates.jsonl"
    reuse_review_path = output_dir / "reuse_candidates_review.jsonl"
    reuse_summary_path = output_dir / "reuse_candidate_summary.json"
    reuse_selection_summary_path = (
        output_dir / "reuse_candidate_selection_summary.json"
    )
    reuse_candidate_targets_path = output_dir / "reuse_candidate_targets.json"
    reuse_checkpoint_path = output_dir / "reuse_candidates.checkpoint.json"
    deep_comparisons_path = output_dir / "reuse_deep_comparisons.jsonl"
    deep_comparison_summary_path = (
        output_dir / "reuse_deep_comparison_summary.json"
    )
    canonical_implementations_path = (
        output_dir / "reuse_canonical_implementations.jsonl"
    )
    managed_deep_comparisons_path = (
        output_dir / "managed_reuse_deep_comparisons.jsonl"
    )
    managed_deep_summary_path = (
        output_dir / "managed_reuse_deep_comparison_summary.json"
    )
    deep_summary_path = output_dir / "native_deep_summary.json"
    ida_manifest_path = output_dir / "ida_target_manifest.json"
    ida_handoff_manifest_path = output_dir / "ida_handoff" / "ida_handoff_manifest.json"
    ida_handoff_zip_path = output_dir / "ida_handoff.zip"
    manual_ida_paths = prepare_manual_ida_workspace(output_dir / "manual_ida")
    cache_path = output_dir / "cache_manifest.json"
    manifest_path = workspace / "phase1_manifest" / "manifest_summary.json"
    code_index_path = workspace / "phase2_jadx" / "code_index.json"
    java_method_index_path = workspace / "phase2_jadx" / "java_method_index.jsonl"
    dex_method_index_path = workspace / "phase2_jadx" / "dex_method_index.jsonl"
    app_package = _load_manifest_package(workspace)

    output_paths = [
        analysis_path,
        targets_path,
        decompile_path,
        ida_automated_summary_path,
        decompile_plan_path,
        toolchain_path,
        function_features_path,
        string_xrefs_path,
        callgraph_path,
        function_index_path,
        evidence_units_path,
        full_index_path,
        full_callgraph_path,
        full_index_summary_path,
        reuse_candidates_path,
        reuse_review_path,
        reuse_summary_path,
        reuse_selection_summary_path,
        reuse_candidate_targets_path,
        deep_comparisons_path,
        deep_comparison_summary_path,
        managed_deep_comparisons_path,
        managed_deep_summary_path,
        deep_summary_path,
        ida_manifest_path,
        ida_handoff_manifest_path,
        ida_handoff_zip_path,
        manual_ida_paths["template"],
        manual_ida_paths["readme"],
        manual_ida_paths["import_summary"],
        manual_ida_paths["evidence_units"],
    ]
    cache_spec = build_phase_cache_spec(
        phase="phase3_native",
        phase_schema=PHASE_SCHEMA,
        phase_config={
            "native_depth": native_depth,
            "native_max_functions": native_max_functions,
            "native_decompiler": native_decompiler,
            "native_max_libraries": native_max_libraries,
            "native_max_decompile_targets": native_max_decompile_targets,
            "native_timeout_per_function": native_timeout_per_function,
            "native_timeout_per_app": native_timeout_per_app,
            "ida_install_dir": str(ida_install_dir) if ida_install_dir else None,
            "ida_python_executable": (
                str(ida_python_executable) if ida_python_executable else None
            ),
            "ida_max_retries": ida_max_retries,
            "ida_callgraph_depth": ida_callgraph_depth,
            "ida_review_limit": ida_review_limit,
            "ida_handoff_max_libraries": ida_handoff_max_libraries,
            "full_native_index": full_native_index,
            "full_native_index_timeout_per_library": (
                full_native_index_timeout_per_library
            ),
            "full_native_index_timeout_per_app": (
                full_native_index_timeout_per_app
            ),
            "full_native_index_max_instructions": (
                full_native_index_max_instructions
            ),
            "oss_function_index": (
                str(oss_function_index) if oss_function_index else None
            ),
            "oss_binary_function_index": (
                str(oss_binary_function_index)
                if oss_binary_function_index
                else None
            ),
            "reuse_candidate_top_k": reuse_candidate_top_k,
            "reuse_candidate_min_score": reuse_candidate_min_score,
            "reuse_candidate_decompile_limit": (
                reuse_candidate_decompile_limit
            ),
            "native_target_capabilities": list(native_target_capabilities),
            "app_package": app_package,
            "first_party_native_hashes": sorted(first_party_native_hashes),
            "third_party_native_hashes": sorted(third_party_native_hashes),
            "manual_ida_input_fingerprint": _manual_ida_input_fingerprint(
                manual_ida_paths["results_dir"]
            ),
        },
        input_paths=apk_paths,
        upstream_paths=[
            manifest_path,
            code_index_path,
            java_method_index_path,
            *([dex_method_index_path] if full_native_index else []),
            *([oss_function_index] if oss_function_index is not None else []),
            *(
                [oss_binary_function_index]
                if oss_binary_function_index is not None
                else []
            ),
        ],
        run_context=run_context,
    )
    if not force:
        cached = load_valid_phase_cache(cache_path, cache_spec, output_paths)
        if cached and _ida_artifacts_valid(decompile_path):
            return cached_phase_result("phase3_native", output_paths, cached)
        if cached:
            logger.warning(
                "Phase 3 cache references missing or modified IDA pseudocode; resuming IDA jobs."
            )

    reset_dir(libs_dir)
    decompiled_targets_dir = output_dir / "decompiled_targets"
    if force:
        reset_dir(decompiled_targets_dir)
    else:
        ensure_dir(decompiled_targets_dir)
    extracted = _extract_native_libraries(apk_paths, libs_dir)
    library_records = [_analyze_library(record) for record in extracted if record.get("success")]
    code_index = _load_json_object(code_index_path)
    for record in library_records:
        record["ownership"] = classify_native_ownership(
            record.get("name"),
            record.get("sha256"),
            app_package=app_package,
            jni_symbols=record.get("jni_symbols") or [],
            first_party_hashes=first_party_native_hashes,
            third_party_hashes=third_party_native_hashes,
            evidence_tokens=_native_attribution_evidence_tokens(
                record,
                code_index,
            ),
        ).to_dict()
    extraction_errors = [record for record in extracted if not record.get("success")]
    toolchain = detect_native_toolchain(
        native_decompiler,
        ida_install_dir=ida_install_dir,
    )
    safe_write_json(toolchain_path, toolchain)

    capability_counts: Counter[str] = Counter()
    comparison_capability_counts: Counter[str] = Counter()
    dependency_capability_counts: Counter[str] = Counter()
    abi_counts: Counter[str] = Counter()
    ownership_library_counts: Counter[str] = Counter()
    component_library_counts: Counter[str] = Counter()
    component_inventory: dict[tuple[str, str], dict[str, Any]] = {}
    for record in library_records:
        abi_counts.update([str(record.get("abi"))])
        record_capabilities = record.get("capability_counts") or {}
        capability_counts.update(record_capabilities)
        ownership = (record.get("ownership") or {}).get("category") or "unknown"
        ownership_library_counts[ownership] += 1
        attribution = record.get("ownership") or {}
        component = str(attribution.get("component") or "")
        vendor = str(attribution.get("vendor") or "")
        if component:
            component_key = f"{vendor}: {component}" if vendor else component
            component_library_counts[component_key] += 1
            identity = (str(record.get("sha256") or ""), component_key)
            component_inventory[identity] = {
                "library": record.get("name"),
                "library_sha256": record.get("sha256"),
                "abi": record.get("abi"),
                "vendor": vendor or None,
                "component": component,
                "category": attribution.get("category"),
                "confidence": attribution.get("confidence"),
                "attribution_kind": attribution.get("attribution_kind"),
                "corroboration": attribution.get("corroboration") or [],
                "comparison_excluded": ownership in {"third_party", "platform"},
                "exclusion_reason": (
                    "Known dependency or platform component; retained for dependency analysis only."
                    if ownership in {"third_party", "platform"}
                    else None
                ),
            }
        if ownership in {"first_party", "unknown"}:
            comparison_capability_counts.update(record_capabilities)
        else:
            dependency_capability_counts.update(record_capabilities)

    function_index = build_native_function_index(library_records)
    safe_write_json(function_index_path, function_index)
    java_native_hints = build_java_native_hints(code_index, library_records)

    reuse_candidates: list[dict[str, Any]] = []
    candidate_targets: list[dict[str, Any]] = []
    if full_native_index:
        inventory_jobs_dir = ensure_dir(output_dir / "full_native_index_jobs")
        if library_records:
            inventory_backend = run_ida_inventory(
                library_records,
                inventory_jobs_dir,
                install_dir=ida_install_dir,
                python_executable=ida_python_executable,
                timeout_per_library=full_native_index_timeout_per_library,
                timeout_per_app=full_native_index_timeout_per_app,
                max_retries=ida_max_retries,
                max_instructions_per_function=full_native_index_max_instructions,
                progress_callback=_log_ida_progress,
            )
        else:
            inventory_backend = {
                "schema_version": "2026-08-24.ida-backend.v4",
                "status": "completed",
                "job_mode": "inventory_only",
                "input_library_count": 0,
                "unique_library_count": 0,
                "completed_library_count": 0,
                "indexed_function_count": 0,
                "library_summaries": [],
                "message": "No native library was present; Java/Kotlin retrieval remains applicable.",
            }
            safe_write_json(
                inventory_jobs_dir / "ida_inventory_summary.json",
                inventory_backend,
            )
        full_index_summary = _reusable_consolidated_inventory(
            inventory_backend,
            full_index_summary_path,
            full_index_path,
            full_callgraph_path,
        ) or _consolidate_native_inventory(
            inventory_backend,
            full_index_path,
            full_callgraph_path,
        )
        full_index_summary["backend_summary_path"] = str(
            inventory_jobs_dir / "ida_inventory_summary.json"
        )
        safe_write_json(full_index_summary_path, full_index_summary)

        selected_native_hashes, native_projection = _primary_native_projection(
            library_records
        )
        java_index_available = (
            java_method_index_path.is_file()
            and java_method_index_path.stat().st_size > 0
        )
        include_dex_in_retrieval = bool(
            oss_binary_function_index is not None or not java_index_available
        )
        commercial_rows = chain(
            _iter_projected_native_rows(
                full_index_path,
                selected_native_hashes,
            ),
            iter_jsonl(java_method_index_path),
            (
                iter_jsonl(dex_method_index_path)
                if include_dex_in_retrieval
                else ()
            ),
        )
        retrieval_summary, reuse_candidates = retrieve_candidates(
            commercial_rows,
            chain(
                iter_jsonl(oss_function_index),
                (
                    iter_jsonl(oss_binary_function_index)
                    if oss_binary_function_index is not None
                    else ()
                ),
            ),
            top_k=reuse_candidate_top_k,
            minimum_score=reuse_candidate_min_score,
            max_candidates_per_commercial=200,
            project_top_k=12,
            output_path=reuse_candidates_path,
            summary_path=reuse_summary_path,
            checkpoint_path=reuse_checkpoint_path,
            resume_key=str(cache_spec.get("cache_key") or ""),
            retained_candidate_limit=0,
            progress_callback=_log_ida_progress,
        )
        retrieval_summary.update(
            {
                "full_native_index_status": full_index_summary.get("status"),
                "full_native_function_count": full_index_summary.get(
                    "indexed_function_count", 0
                ),
                "java_method_index_path": str(java_method_index_path),
                "java_method_index_available": java_index_available,
                "dex_method_index_path": str(dex_method_index_path),
                "dex_method_index_available": dex_method_index_path.is_file(),
                "dex_included_in_retrieval": include_dex_in_retrieval,
                "commercial_native_projection": native_projection,
                "oss_function_index": str(oss_function_index),
                "oss_binary_function_index": (
                    str(oss_binary_function_index)
                    if oss_binary_function_index is not None
                    else None
                ),
                "native_candidate_decompile_limit": (
                    reuse_candidate_decompile_limit
                ),
                "conclusion_boundary": (
                    "Rows are retrieval candidates for deeper comparison. They are "
                    "not final similarity scores and do not establish copying."
                ),
            }
        )
        selection_summary, review_candidates, native_candidate_pool = (
            select_candidate_cohorts(
                iter_jsonl(reuse_candidates_path),
                review_limit=REUSE_REVIEW_LIMIT,
                native_decompile_limit=reuse_candidate_decompile_limit,
            )
        )
        candidate_targets = native_decompile_targets(
            native_candidate_pool,
            limit=reuse_candidate_decompile_limit,
        )
        target_lane_counts = Counter(
            str(target.get("analysis_lane") or "unknown")
            for target in candidate_targets
        )
        selection_summary.update(
            {
                "native_decompile_target_count": len(candidate_targets),
                "native_decompile_target_lane_counts": dict(
                    sorted(target_lane_counts.items())
                ),
                "selection_starved": bool(
                    selection_summary.get("native_deep_eligible_count", 0)
                    and not candidate_targets
                ),
                "review_candidate_path": str(reuse_review_path),
            }
        )
        write_jsonl(reuse_review_path, review_candidates)
        managed_deep_summary = compare_managed_candidates(
            review_candidates,
            managed_deep_comparisons_path,
            managed_deep_summary_path,
            limit=MANAGED_DEEP_COMPARISON_LIMIT,
        )
        safe_write_json(reuse_selection_summary_path, selection_summary)
        retrieval_summary["review_candidate_count"] = len(review_candidates)
        retrieval_summary["review_candidate_limit"] = REUSE_REVIEW_LIMIT
        retrieval_summary["review_candidate_path"] = str(reuse_review_path)
        retrieval_summary["native_decompile_candidate_count"] = len(
            candidate_targets
        )
        retrieval_summary["candidate_selection"] = selection_summary
        retrieval_summary["candidate_selection_summary_path"] = str(
            reuse_selection_summary_path
        )
        safe_write_json(reuse_summary_path, retrieval_summary)
    else:
        write_jsonl(full_index_path, [])
        write_jsonl(full_callgraph_path, [])
        full_index_summary = {
            "schema_version": NATIVE_FULL_INDEX_SCHEMA,
            "status": "not_requested",
            "indexed_function_count": 0,
            "index_path": str(full_index_path),
            "message": (
                "Full native indexing is disabled for this profile; the frozen "
                "native selector remains active."
            ),
        }
        safe_write_json(full_index_summary_path, full_index_summary)
        write_jsonl(reuse_candidates_path, [])
        write_jsonl(reuse_review_path, [])
        selection_summary = {
            "schema_version": "2026-08-24.reuse-candidate-selection.v1",
            "status": "not_requested",
            "review_candidate_count": 0,
            "native_deep_eligible_count": 0,
            "native_decompile_target_count": 0,
            "selection_starved": False,
        }
        safe_write_json(reuse_selection_summary_path, selection_summary)
        write_jsonl(managed_deep_comparisons_path, [])
        managed_deep_summary = {
            "schema_version": "2026-08-26.managed-deep-comparison.v1",
            "status": "not_requested",
            "comparison_limit": MANAGED_DEEP_COMPARISON_LIMIT,
            "comparison_count": 0,
            "usage_review_ready_count": 0,
            "adaptation_review_ready_count": 0,
            "copying_conclusion_supported": False,
            "comparison_path": str(managed_deep_comparisons_path),
        }
        safe_write_json(managed_deep_summary_path, managed_deep_summary)
        retrieval_summary = {
            "schema_version": "2026-08-24.reuse-candidate-retrieval.v6",
            "status": "not_requested",
            "candidate_pair_count": 0,
            "review_candidate_count": 0,
            "review_candidate_limit": REUSE_REVIEW_LIMIT,
            "review_candidate_path": str(reuse_review_path),
            "native_decompile_candidate_count": 0,
            "candidate_selection": selection_summary,
            "candidate_selection_summary_path": str(
                reuse_selection_summary_path
            ),
            "message": "Open-source candidate retrieval is disabled for this profile.",
        }
        safe_write_json(reuse_summary_path, retrieval_summary)

    safe_write_json(
        reuse_candidate_targets_path,
        {
            "schema_version": "2026-08-25.reuse-candidate-targets.v1",
            "status": "completed" if full_native_index else "not_requested",
            "target_count": len(candidate_targets),
            "analysis_lane_counts": dict(
                sorted(
                    Counter(
                        str(target.get("analysis_lane") or "unknown")
                        for target in candidate_targets
                    ).items()
                )
            ),
            "targets": candidate_targets,
            "identity_contract": (
                "candidate_pair_id, analysis_lane, commercial/source identities, "
                "and selection evidence are authoritative for downstream IDA and "
                "post-decompilation comparison."
            ),
        },
    )

    baseline_targets = (
        []
        if native_depth == "none"
        else select_native_targets(
            library_records,
            max_targets=native_max_functions,
            max_libraries=native_max_libraries,
            per_library_limit=max(20, native_max_functions // max(1, native_max_libraries)),
            target_capabilities=native_target_capabilities,
            java_native_hints=java_native_hints,
        )
    )
    targets = _merge_native_targets(
        candidate_targets,
        baseline_targets,
        limit=native_max_functions,
    )
    decompile_targets = candidate_targets if full_native_index else targets
    target_payload = {
        "native_depth": native_depth,
        "native_max_functions": native_max_functions,
        "native_max_libraries": native_max_libraries,
        "native_target_capabilities": list(native_target_capabilities),
        "selection_mode": (
            "reuse_candidates_then_frozen_baseline"
            if full_native_index
            else "frozen_baseline"
        ),
        "reuse_candidate_target_count": len(candidate_targets),
        "reuse_candidate_target_lane_counts": dict(
            sorted(
                Counter(
                    str(target.get("analysis_lane") or "unknown")
                    for target in candidate_targets
                ).items()
            )
        ),
        "baseline_target_count": len(baseline_targets),
        "target_count": len(targets),
        "automated_decompile_target_count": len(decompile_targets),
        "automated_decompile_scope": (
            "retrieved_native_candidates_with_callgraph_expansion"
            if full_native_index
            else "frozen_baseline_targets"
        ),
        "targets": targets,
    }
    safe_write_json(targets_path, target_payload)
    decompile_plan = build_decompile_plan(
        decompile_targets,
        decompiler=native_decompiler if native_depth != "none" else "none",
        max_targets=min(native_max_functions, native_max_decompile_targets),
        max_libraries=native_max_libraries,
        target_capabilities=native_target_capabilities,
        ida_install_dir=ida_install_dir,
        adaptive_library_budget=full_native_index,
    )
    safe_write_json(decompile_plan_path, decompile_plan)

    auto_decision = _auto_decompile_decision(
        decompile_targets,
        native_decompiler=native_decompiler,
        ida_install_dir=ida_install_dir,
    )
    should_attempt_decompile = native_depth == "deep" or (
        native_depth == "auto" and bool(auto_decision.get("attempt"))
    )
    decompile_result: dict[str, Any] = {
        "status": "not_requested",
        "message": "Native pseudocode generation was not requested by this native_depth setting.",
        "auto_decision": auto_decision,
        "attempted_targets": 0,
        "results": [],
    }
    if native_depth == "auto" and not should_attempt_decompile:
        decompile_result = {
            "status": "auto_skipped",
            "message": "Auto mode skipped native pseudocode generation.",
            "auto_decision": auto_decision,
            "attempted_targets": 0,
            "results": [],
        }
    if should_attempt_decompile and decompile_targets:
        decompile_result = run_targeted_decompile(
            decompile_targets,
            decompiled_targets_dir,
            decompiler=native_decompiler,
            timeout_per_function=native_timeout_per_function,
            timeout_per_app=native_timeout_per_app,
            max_targets=min(native_max_functions, native_max_decompile_targets),
            max_libraries=native_max_libraries,
            target_capabilities=native_target_capabilities,
            ida_install_dir=ida_install_dir,
            ida_python_executable=ida_python_executable,
            ida_max_retries=ida_max_retries,
            ida_callgraph_depth=ida_callgraph_depth,
            adaptive_library_budget=full_native_index,
            progress_callback=_log_ida_progress,
        )
        decompile_result["auto_decision"] = auto_decision
        if decompile_result.get("plan"):
            decompile_plan = decompile_result["plan"]
            safe_write_json(decompile_plan_path, decompile_plan)
    safe_write_json(decompile_path, decompile_result)
    safe_write_json(
        ida_automated_summary_path,
        decompile_result
        if decompile_result.get("tool") == "ida"
        else {
            "schema_version": "2026-08-20.ida-automated-summary.v1",
            "status": "not_used",
            "selected_decompiler": (decompile_result or {}).get("tool"),
            "message": "The automated IDA backend was not selected for this run.",
        },
    )

    if full_native_index:
        deep_comparison_summary = compare_decompiled_candidates(
            decompile_result,
            reuse_review_path,
            [
                path
                for path in (oss_function_index, oss_binary_function_index)
                if path is not None
            ],
            deep_comparisons_path,
            deep_comparison_summary_path,
            canonical_mapping_path=canonical_implementations_path,
        )
    else:
        write_jsonl(deep_comparisons_path, [])
        write_jsonl(canonical_implementations_path, [])
        deep_comparison_summary = {
            "schema_version": "2026-08-25.open-source-deep-comparison.v2",
            "status": "not_requested",
            "source_family_comparison_count": 0,
            "usage_review_ready_count": 0,
            "adaptation_review_ready_count": 0,
            "copying_conclusion_supported": False,
            "comparison_path": str(deep_comparisons_path),
        }
        safe_write_json(deep_comparison_summary_path, deep_comparison_summary)

    function_features = _collect_function_features(decompile_result)
    write_jsonl(function_features_path, function_features)
    string_xrefs = _collect_string_xrefs(decompile_result)
    safe_write_json(string_xrefs_path, string_xrefs)
    callgraph = _build_native_callgraph(decompile_result)
    safe_write_json(callgraph_path, callgraph)

    native_evidence_units = build_native_evidence_units(library_records, targets, decompile_result)
    safe_write_json(evidence_units_path, native_evidence_units)
    ida_manifest = build_ida_task_manifest(
        library_records,
        function_index,
        targets,
        code_index=code_index,
        automated_callgraph=callgraph,
        review_limit=ida_review_limit,
    )
    safe_write_json(ida_manifest_path, ida_manifest)
    ida_handoff = export_ida_handoff(
        workspace,
        ida_manifest,
        max_libraries=ida_handoff_max_libraries,
    )
    manual_ida_import = import_manual_ida_results(
        workspace,
        task_manifest=ida_manifest,
        library_records=library_records,
    )

    deep_summary = {
        "native_depth": native_depth,
        "native_decompiler": native_decompiler,
        "native_max_functions": native_max_functions,
        "native_max_libraries": native_max_libraries,
        "native_max_decompile_targets": native_max_decompile_targets,
        "native_timeout_per_function": native_timeout_per_function,
        "native_timeout_per_app": native_timeout_per_app,
        "ida_install_dir": str(ida_install_dir) if ida_install_dir else None,
        "ida_python_executable": (
            str(ida_python_executable) if ida_python_executable else None
        ),
        "ida_max_retries": ida_max_retries,
        "ida_callgraph_depth": ida_callgraph_depth,
        "ida_review_limit": ida_review_limit,
        "ida_handoff_max_libraries": ida_handoff_max_libraries,
        "native_target_capabilities": list(native_target_capabilities),
        "auto_decision": auto_decision,
        "should_attempt_decompile": should_attempt_decompile,
        "target_count": len(targets),
        "function_index_path": str(function_index_path),
        "decompile_plan_path": str(decompile_plan_path),
        "evidence_units_path": str(evidence_units_path),
        "decompilation_path": str(decompile_path),
        "ida_automated_summary_path": str(ida_automated_summary_path),
        "full_native_index_path": str(full_index_path),
        "full_native_index_summary_path": str(full_index_summary_path),
        "reuse_candidates_path": str(reuse_candidates_path),
        "reuse_candidates_review_path": str(reuse_review_path),
        "reuse_candidate_summary_path": str(reuse_summary_path),
        "reuse_candidate_selection_summary_path": str(
            reuse_selection_summary_path
        ),
        "reuse_candidate_targets_path": str(reuse_candidate_targets_path),
        "reuse_deep_comparisons_path": str(deep_comparisons_path),
        "reuse_deep_comparison_summary_path": str(
            deep_comparison_summary_path
        ),
        "managed_reuse_deep_comparisons_path": str(
            managed_deep_comparisons_path
        ),
        "managed_reuse_deep_comparison_summary_path": str(
            managed_deep_summary_path
        ),
        "managed_reuse_deep_comparison_status": managed_deep_summary.get(
            "status"
        ),
        "managed_reuse_deep_comparison_count": managed_deep_summary.get(
            "comparison_count", 0
        ),
        "reuse_canonical_implementations_path": str(
            canonical_implementations_path
        ),
        "reuse_deep_comparison_status": deep_comparison_summary.get("status"),
        "reuse_deep_source_family_count": deep_comparison_summary.get(
            "source_family_comparison_count", 0
        ),
        "full_native_index_status": full_index_summary.get("status"),
        "full_native_function_count": full_index_summary.get(
            "indexed_function_count", 0
        ),
        "reuse_candidate_status": retrieval_summary.get("status"),
        "reuse_candidate_pair_count": retrieval_summary.get(
            "candidate_pair_count", 0
        ),
        "reuse_candidate_target_count": len(candidate_targets),
        "automated_decompile_target_count": len(decompile_targets),
        "toolchain_path": str(toolchain_path),
        "function_features_path": str(function_features_path),
        "string_xrefs_path": str(string_xrefs_path),
        "callgraph_path": str(callgraph_path),
        "ida_target_manifest_path": str(ida_manifest_path),
        "ida_handoff_manifest_path": str(ida_handoff_manifest_path),
        "ida_handoff_zip_path": str(ida_handoff_zip_path),
        "ida_handoff": ida_handoff,
        "manual_ida_import_path": str(manual_ida_paths["import_summary"]),
        "manual_ida_evidence_path": str(manual_ida_paths["evidence_units"]),
        "decompiler_status": decompile_result.get("status"),
        "attempted_targets": decompile_result.get("attempted_targets"),
        "successful_decompilations": sum(1 for item in decompile_result.get("results") or [] if item.get("success")),
        "function_feature_count": len(function_features),
        "string_xref_function_count": len(string_xrefs),
        "callgraph_node_count": callgraph.get("node_count"),
        "callgraph_edge_count": callgraph.get("edge_count"),
        "ida_candidate_count": ida_manifest.get("candidate_count"),
        "ida_review_queue_count": ida_manifest.get("review_queue_count"),
        "manual_ida_import": manual_ida_import,
    }
    safe_write_json(deep_summary_path, deep_summary)

    native_component_inventory = sorted(
        component_inventory.values(),
        key=lambda item: (
            str(item.get("vendor") or ""),
            str(item.get("component") or ""),
            str(item.get("library") or ""),
            str(item.get("abi") or ""),
        ),
    )
    confirmed_dependency_components = [
        item
        for item in native_component_inventory
        if item.get("category") in {"third_party", "platform"}
    ]
    unconfirmed_component_clues = [
        item
        for item in native_component_inventory
        if item.get("category") not in {"third_party", "platform"}
    ]
    payload = {
        "apk_paths": [str(path) for path in apk_paths],
        "native_library_count": len(library_records),
        "abi_counts": dict(sorted(abi_counts.items())),
        "capability_counts": dict(sorted(capability_counts.items())),
        "comparison_capability_counts": dict(
            sorted(comparison_capability_counts.items())
        ),
        "excluded_dependency_capability_counts": dict(
            sorted(dependency_capability_counts.items())
        ),
        "ownership_library_counts": dict(
            sorted(ownership_library_counts.items())
        ),
        "component_library_counts": dict(
            sorted(component_library_counts.items())
        ),
        "native_component_inventory": native_component_inventory,
        "native_dependency_components": confirmed_dependency_components,
        "unconfirmed_native_component_clues": unconfirmed_component_clues,
        "ownership_policy": {
            "comparison_included": ["first_party", "unknown"],
            "comparison_excluded_by_default": ["third_party", "platform"],
            "app_package": app_package,
            "hash_attribution": {
                "first_party_hash_count": len(first_party_native_hashes),
                "third_party_hash_count": len(third_party_native_hashes),
            },
        },
        "libraries": library_records,
        "extraction_errors": extraction_errors,
        "targets_path": str(targets_path),
        "function_index_path": str(function_index_path),
        "decompile_plan_path": str(decompile_plan_path),
        "toolchain_path": str(toolchain_path),
        "function_features_path": str(function_features_path),
        "string_xrefs_path": str(string_xrefs_path),
        "callgraph_path": str(callgraph_path),
        "evidence_units_path": str(evidence_units_path),
        "ida_target_manifest_path": str(ida_manifest_path),
        "ida_handoff_manifest_path": str(ida_handoff_manifest_path),
        "ida_handoff_zip_path": str(ida_handoff_zip_path),
        "manual_ida_import_path": str(manual_ida_paths["import_summary"]),
        "manual_ida_evidence_path": str(manual_ida_paths["evidence_units"]),
        "deep_summary_path": str(deep_summary_path),
        "decompilation_path": str(decompile_path),
        "ida_automated_summary_path": str(ida_automated_summary_path),
        "full_native_index_path": str(full_index_path),
        "full_native_index_summary_path": str(full_index_summary_path),
        "full_native_index_status": full_index_summary.get("status"),
        "full_native_function_count": full_index_summary.get(
            "indexed_function_count", 0
        ),
        "reuse_candidates_path": str(reuse_candidates_path),
        "reuse_candidates_review_path": str(reuse_review_path),
        "reuse_candidate_summary_path": str(reuse_summary_path),
        "reuse_candidate_selection_summary_path": str(
            reuse_selection_summary_path
        ),
        "reuse_candidate_targets_path": str(reuse_candidate_targets_path),
        "reuse_deep_comparisons_path": str(deep_comparisons_path),
        "reuse_deep_comparison_summary_path": str(
            deep_comparison_summary_path
        ),
        "managed_reuse_deep_comparisons_path": str(
            managed_deep_comparisons_path
        ),
        "managed_reuse_deep_comparison_summary_path": str(
            managed_deep_summary_path
        ),
        "managed_reuse_deep_comparison_status": managed_deep_summary.get(
            "status"
        ),
        "managed_reuse_deep_comparison_count": managed_deep_summary.get(
            "comparison_count", 0
        ),
        "reuse_deep_comparison_status": deep_comparison_summary.get("status"),
        "reuse_deep_source_family_count": deep_comparison_summary.get(
            "source_family_comparison_count", 0
        ),
        "reuse_candidate_status": retrieval_summary.get("status"),
        "reuse_candidate_pair_count": retrieval_summary.get(
            "candidate_pair_count", 0
        ),
        "reuse_candidate_target_count": len(candidate_targets),
        "native_evidence_unit_count": len(native_evidence_units),
        "native_function_feature_count": len(function_features),
        "ida_candidate_count": ida_manifest.get("candidate_count"),
        "ida_review_queue_count": ida_manifest.get("review_queue_count"),
        "ida_handoff_library_count": ida_handoff.get("selected_library_count"),
        "manual_ida_import": manual_ida_import,
    }
    safe_write_json(analysis_path, payload)

    decompile_results = decompile_result.get("results") or []
    decompile_failures = [item for item in decompile_results if not item.get("success")]
    requested_decompile_incomplete = bool(
        should_attempt_decompile
        and decompile_targets
        and decompile_result.get("status") != "completed"
    )
    manual_ida_import_incomplete = manual_ida_import.get("status") in {
        "partial",
        "failed",
    }
    ida_handoff_incomplete = ida_handoff.get("status") in {
        "partial",
        "failed",
    }
    reuse_search_incomplete = bool(
        full_native_index
        and (
            full_index_summary.get("status") != "completed"
            or retrieval_summary.get("status") != "completed"
        )
    )
    if extraction_errors and not library_records:
        status = "failed"
    elif (
        extraction_errors
        or requested_decompile_incomplete
        or manual_ida_import_incomplete
        or ida_handoff_incomplete
        or reuse_search_incomplete
    ):
        status = "partial"
    else:
        status = "success"
    warnings: list[str] = []
    if not library_records and not extraction_errors:
        warnings.append("No native libraries found.")
    warnings.extend(
        f"{item.get('apk')}: {item.get('error') or 'native_extraction_failed'}"
        for item in extraction_errors
    )
    if requested_decompile_incomplete:
        warnings.append(
            "Requested native pseudocode generation did not complete its scheduled library jobs."
        )
    if decompile_failures:
        warnings.append(
            "Some individual native functions could not be decompiled; failures are retained as auditable evidence."
        )
    if manual_ida_import_incomplete:
        warnings.append(
            "One or more manual IDA results failed identity or content validation."
        )
    if ida_handoff_incomplete:
        warnings.append(
            "One or more ranked native libraries could not be packaged for IDA; "
            "see ida_handoff_manifest.json."
        )
    if reuse_search_incomplete:
        warnings.append(
            "Full native indexing or open-source candidate retrieval was incomplete; "
            "baseline native evidence was retained."
        )
    result = PhaseResult(
        name="phase3_native",
        success=status == "success",
        status=status,
        output_paths=output_paths,
        details={
            "native_library_count": len(library_records),
            "target_count": len(targets),
            "native_evidence_unit_count": len(native_evidence_units),
            "capability_counts": payload["capability_counts"],
            "comparison_capability_counts": payload[
                "comparison_capability_counts"
            ],
            "ownership_library_counts": payload["ownership_library_counts"],
            "decompiler_status": (decompile_result or {}).get("status"),
            "extraction_error_count": len(extraction_errors),
            "decompile_failure_count": len(decompile_failures),
            "ida_candidate_count": ida_manifest.get("candidate_count"),
            "ida_review_queue_count": ida_manifest.get("review_queue_count"),
            "ida_handoff_library_count": ida_handoff.get(
                "selected_library_count"
            ),
            "ida_handoff_status": ida_handoff.get("status"),
            "ida_handoff_skipped_library_count": ida_handoff.get(
                "skipped_library_count"
            ),
            "manual_ida_status": manual_ida_import.get("status"),
            "manual_ida_accepted_count": manual_ida_import.get("accepted_count"),
            "manual_ida_rejected_count": manual_ida_import.get("rejected_count"),
            "full_native_index_status": full_index_summary.get("status"),
            "full_native_function_count": full_index_summary.get(
                "indexed_function_count", 0
            ),
            "reuse_candidate_status": retrieval_summary.get("status"),
            "reuse_candidate_pair_count": retrieval_summary.get(
                "candidate_pair_count", 0
            ),
            "reuse_candidate_target_count": len(candidate_targets),
            "automated_decompile_target_count": len(decompile_targets),
            "reuse_deep_comparison_status": deep_comparison_summary.get(
                "status"
            ),
            "reuse_deep_source_family_count": deep_comparison_summary.get(
                "source_family_comparison_count", 0
            ),
        },
        warnings=warnings,
    )
    write_phase_cache(cache_path, cache_spec, output_paths, result)
    return result


def run_phase3(apk_path: Path, workspace: Path, *, force: bool = False) -> PhaseResult:
    return run_phase3_multi([apk_path], workspace, force=force, native_depth="basic")
