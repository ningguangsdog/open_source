"""Phase 3: native library extraction, signals, and target selection."""

from __future__ import annotations

import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from .capability_taxonomy import capability_names, classify_text
from .models import PhaseResult
from .native_decompiler import run_targeted_decompile, select_native_targets
from .utils import (
    ensure_dir,
    printable_strings_from_bytes,
    run_cmd,
    safe_name,
    safe_write_json,
    sha256_file,
    tool_exists,
)


URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
MAX_STRINGS = 5000
MAX_INTERESTING_STRINGS = 500


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


def run_phase3_multi(
    apk_paths: list[Path],
    workspace: Path,
    *,
    force: bool = False,
    native_depth: str = "targeted",
    native_max_functions: int = 300,
    native_timeout: int = 600,
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase3_native")
    libs_dir = output_dir / "libs"
    analysis_path = output_dir / "native_analysis.json"
    targets_path = output_dir / "native_targets.json"
    decompile_path = output_dir / "native_decompilation.json"

    if analysis_path.exists() and targets_path.exists() and not force:
        outputs = [analysis_path, targets_path]
        if decompile_path.exists():
            outputs.append(decompile_path)
        return PhaseResult(
            name="phase3_native",
            success=True,
            output_paths=outputs,
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

    targets = (
        []
        if native_depth == "none"
        else select_native_targets(library_records, max_targets=native_max_functions)
    )
    target_payload = {
        "native_depth": native_depth,
        "target_count": len(targets),
        "targets": targets,
    }
    safe_write_json(targets_path, target_payload)

    decompile_result: dict[str, Any] | None = None
    if native_depth == "targeted" and targets:
        decompile_result = run_targeted_decompile(
            targets,
            output_dir / "decompiled_targets",
            timeout=native_timeout,
            max_targets=min(native_max_functions, 40),
        )
        safe_write_json(decompile_path, decompile_result)

    payload = {
        "apk_paths": [str(path) for path in apk_paths],
        "native_library_count": len(library_records),
        "abi_counts": dict(sorted(abi_counts.items())),
        "capability_counts": dict(sorted(capability_counts.items())),
        "libraries": library_records,
        "extraction_errors": extraction_errors,
        "targets_path": str(targets_path),
        "decompilation_path": str(decompile_path) if decompile_result is not None else None,
    }
    safe_write_json(analysis_path, payload)

    outputs = [analysis_path, targets_path]
    if decompile_result is not None:
        outputs.append(decompile_path)

    return PhaseResult(
        name="phase3_native",
        success=True,
        output_paths=outputs,
        details={
            "native_library_count": len(library_records),
            "target_count": len(targets),
            "capability_counts": payload["capability_counts"],
            "decompiler_status": (decompile_result or {}).get("status"),
        },
        warnings=["No native libraries found."] if not library_records else [],
    )


def run_phase3(apk_path: Path, workspace: Path, *, force: bool = False) -> PhaseResult:
    return run_phase3_multi([apk_path], workspace, force=force, native_depth="basic")
