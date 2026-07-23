"""Phase 3: native library extraction, signals, and target selection."""

from __future__ import annotations

import hashlib
import json
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
from .evidence import capability_confidence, compact_list, token_fingerprint, unit_id, write_jsonl
from .ida_integration import (
    build_ida_task_manifest,
    build_java_native_hints,
    import_manual_ida_results,
    normalize_address,
    prepare_manual_ida_workspace,
)
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
from .run_context import (
    build_phase_cache_spec,
    cached_phase_result,
    load_valid_phase_cache,
    write_phase_cache,
)
from .utils import (
    ensure_dir,
    printable_strings_from_bytes,
    run_cmd,
    safe_name,
    safe_read_text,
    safe_write_json,
    sha256_file,
    tool_exists,
)


URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
MAX_STRINGS = 5000
MAX_INTERESTING_STRINGS = 500
AUTO_DEEP_MIN_SCORE = 18
AUTO_DEEP_MIN_CAPABILITY_SCORE = 12
PHASE_SCHEMA = "2026-07-23.phase3.v4"
NATIVE_DEPTHS = {"none", "basic", "targeted", "auto", "deep"}
NATIVE_DECOMPILERS = {"auto", "none", "rizin", "radare2", "ghidra", "retdec"}


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
    with zipfile.ZipFile(apk_path, "r") as zf:
        return [
            info
            for info in zf.infolist()
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
                output_path = apk_out_dir.joinpath(*parts)
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
                        "size_bytes": info.file_size,
                        "sha256": sha256_file(output_path),
                        "success": True,
                    }
                )
    return records


def _run_strings(path: Path) -> list[str]:
    if tool_exists("strings"):
        completed = run_cmd(["strings", "-a", str(path)], check=False)
        if completed.returncode == 0:
            return completed.stdout.splitlines()[:MAX_STRINGS]

    data = path.read_bytes()[:20_000_000]
    return printable_strings_from_bytes(data, min_length=4, limit=MAX_STRINGS)


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
            completed = run_cmd(command, check=False)
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


def _interesting_strings(strings: list[str]) -> tuple[list[dict[str, Any]], list[str], dict[str, int]]:
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
        rows.append(
            {
                "value": value[:500],
                "capabilities": capabilities,
                "urls": found_urls[:20],
            }
        )
        if len(rows) >= MAX_INTERESTING_STRINGS:
            break

    return rows, sorted(urls)[:200], dict(capability_counts)


def _analyze_library(record: dict[str, Any]) -> dict[str, Any]:
    if not record.get("success"):
        return record

    path = Path(str(record["extracted_path"]))
    strings = _run_strings(path)
    interesting, urls, capability_counts = _interesting_strings(strings)
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


def _decompile_result_map(decompile_result: dict[str, Any] | None) -> dict[tuple[str, str], dict[str, Any]]:
    mapped: dict[tuple[str, str], dict[str, Any]] = {}
    for result in (decompile_result or {}).get("results") or []:
        target = result.get("target") or {}
        library = str(target.get("library") or "")
        name = str(target.get("name") or "")
        if library and name:
            mapped[(library, name)] = result
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

    for target in targets:
        key = (str(target.get("library") or ""), str(target.get("name") or ""))
        result = decompiled.get(key)
        output_path = result.get("output_path") if result else None
        features = result.get("function_features") if result else None
        if not isinstance(features, dict):
            features = {}
        pseudocode_excerpt = ""
        if output_path:
            pseudocode_excerpt = safe_read_text(Path(output_path), limit=4000)
        capabilities = capability_names(target.get("capabilities") or [])
        score = int(target.get("score") or 0)
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
                "unit_id": unit_id("native_target", target.get("library"), target.get("kind"), target.get("name")),
                "phase": "phase3_native",
                "kind": "native_target",
                "library": target.get("library"),
                "target_kind": target.get("kind"),
                "name": target.get("name"),
                "score": score,
                "capabilities": capabilities,
                "ownership": target.get("ownership") or {},
                "reasons": target.get("reasons") or [],
                "decompiler_success": result.get("success") if result else None,
                "decompiler_tool": result.get("tool") if result else None,
                "pseudocode_path": output_path,
                "pseudocode_excerpt": pseudocode_excerpt[:4000],
                "feature_hash": features.get("feature_hash"),
                "pseudocode_fingerprint": features.get("pseudocode_fingerprint"),
                "instruction_count": features.get("instruction_count"),
                "basic_block_count": features.get("basic_block_count"),
                "cfg_edge_count": features.get("cfg_edge_count"),
                "call_targets": compact_list(features.get("call_targets") or [], 80),
                "string_refs": compact_list(features.get("string_refs") or [], 80),
                "token_fingerprint": token_fingerprint(fingerprint_text),
                "confidence": min(0.95, 0.35 + min(score, 60) / 100 + 0.05 * len(capabilities)),
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
) -> dict[str, Any]:
    callable_targets = [
        target
        for target in targets
        if target.get("kind") in {"jni_symbol", "exported_symbol"}
    ]
    if not callable_targets:
        return {
            "attempt": False,
            "reason": "no_callable_native_targets",
            "candidate_count": 0,
            "available_decompiler": available_decompiler(native_decompiler),
        }

    tool = available_decompiler(native_decompiler)
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
    ida_review_limit: int = 120,
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
    }
    invalid_values = [
        name for name, value in positive_values.items() if value <= 0
    ]
    if invalid_values:
        raise ValueError(
            "Native limits and timeout values must be positive: "
            + ", ".join(invalid_values)
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
    decompile_plan_path = output_dir / "native_decompile_plan.json"
    toolchain_path = output_dir / "native_toolchain.json"
    function_features_path = output_dir / "native_function_features.jsonl"
    string_xrefs_path = output_dir / "native_string_xrefs.json"
    callgraph_path = output_dir / "native_callgraph.json"
    function_index_path = output_dir / "native_function_index.json"
    evidence_units_path = output_dir / "native_evidence_units.json"
    deep_summary_path = output_dir / "native_deep_summary.json"
    ida_manifest_path = output_dir / "ida_target_manifest.json"
    manual_ida_paths = prepare_manual_ida_workspace(output_dir / "manual_ida")
    cache_path = output_dir / "cache_manifest.json"
    manifest_path = workspace / "phase1_manifest" / "manifest_summary.json"
    code_index_path = workspace / "phase2_jadx" / "code_index.json"
    app_package = _load_manifest_package(workspace)

    output_paths = [
        analysis_path,
        targets_path,
        decompile_path,
        decompile_plan_path,
        toolchain_path,
        function_features_path,
        string_xrefs_path,
        callgraph_path,
        function_index_path,
        evidence_units_path,
        deep_summary_path,
        ida_manifest_path,
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
            "ida_review_limit": ida_review_limit,
            "native_target_capabilities": list(native_target_capabilities),
            "app_package": app_package,
            "first_party_native_hashes": sorted(first_party_native_hashes),
            "third_party_native_hashes": sorted(third_party_native_hashes),
            "manual_ida_input_fingerprint": _manual_ida_input_fingerprint(
                manual_ida_paths["results_dir"]
            ),
        },
        input_paths=apk_paths,
        upstream_paths=[manifest_path, code_index_path],
        run_context=run_context,
    )
    if not force:
        cached = load_valid_phase_cache(cache_path, cache_spec, output_paths)
        if cached:
            return cached_phase_result("phase3_native", output_paths, cached)

    extracted = _extract_native_libraries(apk_paths, libs_dir)
    library_records = [_analyze_library(record) for record in extracted if record.get("success")]
    for record in library_records:
        record["ownership"] = classify_native_ownership(
            record.get("name"),
            record.get("sha256"),
            app_package=app_package,
            jni_symbols=record.get("jni_symbols") or [],
            first_party_hashes=first_party_native_hashes,
            third_party_hashes=third_party_native_hashes,
        ).to_dict()
    extraction_errors = [record for record in extracted if not record.get("success")]
    toolchain = detect_native_toolchain(native_decompiler)
    safe_write_json(toolchain_path, toolchain)

    capability_counts: Counter[str] = Counter()
    comparison_capability_counts: Counter[str] = Counter()
    dependency_capability_counts: Counter[str] = Counter()
    abi_counts: Counter[str] = Counter()
    ownership_library_counts: Counter[str] = Counter()
    for record in library_records:
        abi_counts.update([str(record.get("abi"))])
        record_capabilities = record.get("capability_counts") or {}
        capability_counts.update(record_capabilities)
        ownership = (record.get("ownership") or {}).get("category") or "unknown"
        ownership_library_counts[ownership] += 1
        if ownership in {"first_party", "unknown"}:
            comparison_capability_counts.update(record_capabilities)
        else:
            dependency_capability_counts.update(record_capabilities)

    function_index = build_native_function_index(library_records)
    safe_write_json(function_index_path, function_index)
    code_index = _load_json_object(code_index_path)
    java_native_hints = build_java_native_hints(code_index, library_records)

    targets = (
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
    target_payload = {
        "native_depth": native_depth,
        "native_max_functions": native_max_functions,
        "native_max_libraries": native_max_libraries,
        "native_target_capabilities": list(native_target_capabilities),
        "target_count": len(targets),
        "targets": targets,
    }
    safe_write_json(targets_path, target_payload)
    decompile_plan = build_decompile_plan(
        targets,
        decompiler=native_decompiler if native_depth != "none" else "none",
        max_targets=min(native_max_functions, native_max_decompile_targets),
        max_libraries=native_max_libraries,
        target_capabilities=native_target_capabilities,
    )
    safe_write_json(decompile_plan_path, decompile_plan)

    auto_decision = _auto_decompile_decision(targets, native_decompiler=native_decompiler)
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
    if should_attempt_decompile and targets:
        decompile_result = run_targeted_decompile(
            targets,
            output_dir / "decompiled_targets",
            decompiler=native_decompiler,
            timeout_per_function=native_timeout_per_function,
            timeout_per_app=native_timeout_per_app,
            max_targets=min(native_max_functions, native_max_decompile_targets),
            max_libraries=native_max_libraries,
            target_capabilities=native_target_capabilities,
        )
        decompile_result["auto_decision"] = auto_decision
        if decompile_result.get("plan"):
            decompile_plan = decompile_result["plan"]
            safe_write_json(decompile_plan_path, decompile_plan)
    safe_write_json(decompile_path, decompile_result)

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
        "ida_review_limit": ida_review_limit,
        "native_target_capabilities": list(native_target_capabilities),
        "auto_decision": auto_decision,
        "should_attempt_decompile": should_attempt_decompile,
        "target_count": len(targets),
        "function_index_path": str(function_index_path),
        "decompile_plan_path": str(decompile_plan_path),
        "evidence_units_path": str(evidence_units_path),
        "decompilation_path": str(decompile_path),
        "toolchain_path": str(toolchain_path),
        "function_features_path": str(function_features_path),
        "string_xrefs_path": str(string_xrefs_path),
        "callgraph_path": str(callgraph_path),
        "ida_target_manifest_path": str(ida_manifest_path),
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
        "manual_ida_import_path": str(manual_ida_paths["import_summary"]),
        "manual_ida_evidence_path": str(manual_ida_paths["evidence_units"]),
        "deep_summary_path": str(deep_summary_path),
        "decompilation_path": str(decompile_path),
        "native_evidence_unit_count": len(native_evidence_units),
        "native_function_feature_count": len(function_features),
        "ida_candidate_count": ida_manifest.get("candidate_count"),
        "ida_review_queue_count": ida_manifest.get("review_queue_count"),
        "manual_ida_import": manual_ida_import,
    }
    safe_write_json(analysis_path, payload)

    decompile_results = decompile_result.get("results") or []
    decompile_failures = [item for item in decompile_results if not item.get("success")]
    requested_decompile_incomplete = bool(
        should_attempt_decompile
        and targets
        and (
            decompile_result.get("status") != "completed"
            or decompile_failures
        )
    )
    manual_ida_import_incomplete = manual_ida_import.get("status") in {
        "partial",
        "failed",
    }
    if extraction_errors and not library_records:
        status = "failed"
    elif (
        extraction_errors
        or requested_decompile_incomplete
        or manual_ida_import_incomplete
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
            "Requested native pseudocode generation did not complete for every selected target."
        )
    if manual_ida_import_incomplete:
        warnings.append(
            "One or more manual IDA results failed identity or content validation."
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
            "manual_ida_status": manual_ida_import.get("status"),
            "manual_ida_accepted_count": manual_ida_import.get("accepted_count"),
            "manual_ida_rejected_count": manual_ida_import.get("rejected_count"),
        },
        warnings=warnings,
    )
    write_phase_cache(cache_path, cache_spec, output_paths, result)
    return result


def run_phase3(apk_path: Path, workspace: Path, *, force: bool = False) -> PhaseResult:
    return run_phase3_multi([apk_path], workspace, force=force, native_depth="basic")
