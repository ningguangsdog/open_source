"""Phase 3: native library extraction, signals, and target selection."""

from __future__ import annotations

import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from .capability_taxonomy import capability_names, classify_text
from .evidence import capability_confidence, compact_list, token_fingerprint, unit_id
from .models import PhaseResult
from .native_decompiler import available_decompiler, run_targeted_decompile, score_native_text, select_native_targets
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
AUTOMATED_DECOMPILER_TOOLS = {"rizin", "radare2"}


def _native_entries(apk_path: Path) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(apk_path, "r") as zf:
        return [
            info
            for info in zf.infolist()
            if not info.is_dir()
            and info.filename.startswith("lib/")
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

        apk_out_dir = ensure_dir(libs_dir / safe_name(apk_path.stem))
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


def _extract_symbols(path: Path) -> tuple[list[str], list[str], list[str]]:
    exported: set[str] = set()
    jni: set[str] = set()
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
            name = parts[-1].split("@@")[0].split("@")[0]
            if not name or name in {"UND", "ABS"}:
                continue
            if len(name) > 200:
                continue
            exported.add(name)
            if name.startswith("Java_") or "JNI" in name or "jni" in name:
                jni.add(name)
        if exported:
            break

    return sorted(exported)[:2000], sorted(jni)[:1000], warnings


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
    exported_symbols, jni_symbols, symbol_warnings = _extract_symbols(path)

    enriched = dict(record)
    enriched.update(
        {
            "string_count_sampled": len(strings),
            "interesting_strings": interesting,
            "urls": urls,
            "capability_counts": capability_counts,
            "exported_symbol_count": len(exported_symbols),
            "exported_symbols": exported_symbols[:500],
            "jni_symbol_count": len(jni_symbols),
            "jni_symbols": jni_symbols[:500],
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
    max_entries_per_library: int = 1500,
) -> dict[str, Any]:
    libraries: list[dict[str, Any]] = []
    aggregate_capabilities: Counter[str] = Counter()

    for record in library_records:
        library_path = str(record.get("extracted_path") or record.get("entry") or "")
        library_caps = capability_names((record.get("capability_counts") or {}).keys())
        aggregate_capabilities.update(library_caps)
        functions: list[dict[str, Any]] = []
        seen_names: set[tuple[str, str]] = set()

        for symbol in record.get("jni_symbols") or []:
            name = str(symbol)
            score, capabilities, reasons = _target_score("jni_symbol", library_path, name)
            seen_names.add(("jni_symbol", name))
            functions.append(
                {
                    "kind": "jni_symbol",
                    "name": name,
                    "score": score,
                    "capabilities": capabilities,
                    "reasons": reasons,
                }
            )

        for symbol in record.get("exported_symbols") or []:
            name = str(symbol)
            if ("jni_symbol", name) in seen_names:
                continue
            score, capabilities, reasons = _target_score("exported_symbol", library_path, name)
            seen_names.add(("exported_symbol", name))
            functions.append(
                {
                    "kind": "exported_symbol",
                    "name": name,
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

        functions.sort(key=lambda item: (-int(item.get("score") or 0), item.get("kind") or "", item.get("name") or ""))
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
                "capability_counts": record.get("capability_counts") or {},
                "exported_symbol_count": record.get("exported_symbol_count") or 0,
                "jni_symbol_count": record.get("jni_symbol_count") or 0,
                "interesting_string_count": len(record.get("interesting_strings") or []),
                "function_count_indexed": min(len(functions), max_entries_per_library),
                "functions": functions[:max_entries_per_library],
                "functions_truncated": len(functions) > max_entries_per_library,
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
                "reasons": target.get("reasons") or [],
                "decompiler_success": result.get("success") if result else None,
                "decompiler_tool": result.get("tool") if result else None,
                "pseudocode_path": output_path,
                "pseudocode_excerpt": pseudocode_excerpt[:4000],
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
    native_target_capabilities: tuple[str, ...] = (),
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase3_native")
    libs_dir = output_dir / "libs"
    analysis_path = output_dir / "native_analysis.json"
    targets_path = output_dir / "native_targets.json"
    decompile_path = output_dir / "native_decompilation.json"
    function_index_path = output_dir / "native_function_index.json"
    evidence_units_path = output_dir / "native_evidence_units.json"
    deep_summary_path = output_dir / "native_deep_summary.json"

    output_paths = [
        analysis_path,
        targets_path,
        decompile_path,
        function_index_path,
        evidence_units_path,
        deep_summary_path,
    ]
    if all(path.exists() for path in output_paths) and not force:
        return PhaseResult(
            name="phase3_native",
            success=True,
            output_paths=output_paths,
            details={"cached": True},
        )

    extracted = _extract_native_libraries(apk_paths, libs_dir)
    library_records = [_analyze_library(record) for record in extracted if record.get("success")]
    extraction_errors = [record for record in extracted if not record.get("success")]

    capability_counts: Counter[str] = Counter()
    abi_counts: Counter[str] = Counter()
    for record in library_records:
        abi_counts.update([str(record.get("abi"))])
        capability_counts.update(record.get("capability_counts") or {})

    function_index = build_native_function_index(library_records)
    safe_write_json(function_index_path, function_index)

    targets = (
        []
        if native_depth == "none"
        else select_native_targets(
            library_records,
            max_targets=native_max_functions,
            max_libraries=native_max_libraries,
            per_library_limit=max(20, native_max_functions // max(1, native_max_libraries)),
            target_capabilities=native_target_capabilities,
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
    safe_write_json(decompile_path, decompile_result)

    native_evidence_units = build_native_evidence_units(library_records, targets, decompile_result)
    safe_write_json(evidence_units_path, native_evidence_units)

    deep_summary = {
        "native_depth": native_depth,
        "native_decompiler": native_decompiler,
        "native_max_functions": native_max_functions,
        "native_max_libraries": native_max_libraries,
        "native_max_decompile_targets": native_max_decompile_targets,
        "native_timeout_per_function": native_timeout_per_function,
        "native_timeout_per_app": native_timeout_per_app,
        "native_target_capabilities": list(native_target_capabilities),
        "auto_decision": auto_decision,
        "should_attempt_decompile": should_attempt_decompile,
        "target_count": len(targets),
        "function_index_path": str(function_index_path),
        "evidence_units_path": str(evidence_units_path),
        "decompilation_path": str(decompile_path),
        "decompiler_status": decompile_result.get("status"),
        "attempted_targets": decompile_result.get("attempted_targets"),
        "successful_decompilations": sum(1 for item in decompile_result.get("results") or [] if item.get("success")),
    }
    safe_write_json(deep_summary_path, deep_summary)

    payload = {
        "apk_paths": [str(path) for path in apk_paths],
        "native_library_count": len(library_records),
        "abi_counts": dict(sorted(abi_counts.items())),
        "capability_counts": dict(sorted(capability_counts.items())),
        "libraries": library_records,
        "extraction_errors": extraction_errors,
        "targets_path": str(targets_path),
        "function_index_path": str(function_index_path),
        "evidence_units_path": str(evidence_units_path),
        "deep_summary_path": str(deep_summary_path),
        "decompilation_path": str(decompile_path),
        "native_evidence_unit_count": len(native_evidence_units),
    }
    safe_write_json(analysis_path, payload)

    return PhaseResult(
        name="phase3_native",
        success=True,
        output_paths=output_paths,
        details={
            "native_library_count": len(library_records),
            "target_count": len(targets),
            "native_evidence_unit_count": len(native_evidence_units),
            "capability_counts": payload["capability_counts"],
            "decompiler_status": (decompile_result or {}).get("status"),
        },
        warnings=["No native libraries found."] if not library_records else [],
    )


def run_phase3(apk_path: Path, workspace: Path, *, force: bool = False) -> PhaseResult:
    return run_phase3_multi([apk_path], workspace, force=force, native_depth="basic")
