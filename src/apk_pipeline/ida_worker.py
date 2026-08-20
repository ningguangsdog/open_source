"""Isolated IDALib worker used by the Phase 3 IDA backend.

This module intentionally depends only on the standard library until IDALib is
activated.  The parent pipeline runs one worker process per native library so a
timeout or IDA failure cannot corrupt the main analysis process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any


JOB_SCHEMA = "2026-08-20.ida-worker-job.v1"
RESULT_SCHEMA = "2026-08-20.ida-worker-result.v1"
HIGH_VALUE_MARKERS = (
    "ocr",
    "recogn",
    "segment",
    "detect",
    "classif",
    "infer",
    "predict",
    "dewarp",
    "deskew",
    "perspective",
    "binar",
    "threshold",
    "shadow",
    "enhance",
    "filter",
    "transform",
    "encrypt",
    "decrypt",
    "render",
    "compress",
    "model",
    "tensor",
    "image",
    "scan",
    "pdf",
)
WRAPPER_MARKERS = (
    "thunk",
    "trampoline",
    "wrapper",
    "bridge",
    "register_natives",
    "registernatives",
    "jni_onload",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str, limit: int = 96) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    if not cleaned:
        cleaned = "unnamed"
    if len(cleaned) <= limit:
        return cleaned
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{cleaned[: limit - 13]}_{digest}"


def _atomic_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(path)


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _current_job_rows(path: Path, job_hash: str) -> list[dict[str, Any]]:
    """Return the most recent checkpoint row for each function address."""

    by_address: dict[str, dict[str, Any]] = {}
    for row in _load_jsonl(path):
        if row.get("job_hash") != job_hash:
            continue
        address = str(row.get("address") or "")
        if address:
            by_address[address] = row
    return list(by_address.values())


def _successful_checkpoint(row: dict[str, Any]) -> bool:
    if row.get("success") is not True:
        return False
    path = Path(str(row.get("pseudocode_path") or ""))
    if not path.is_file() or path.stat().st_size <= 0:
        return False
    expected = str(row.get("pseudocode_sha256") or "")
    return not expected or _sha256_file(path) == expected


def _completed_checkpoint(row: dict[str, Any]) -> bool:
    """Treat verified pseudocode and terminal watchdog failures as complete."""

    return _successful_checkpoint(row) or row.get("terminal_failure") is True


def _activate_idalib(ida_install_dir: Path) -> Any:
    runtime_dir = ida_install_dir
    if ida_install_dir.suffix == ".app":
        runtime_dir = ida_install_dir / "Contents" / "MacOS"
    wheel_dir = runtime_dir / "idalib" / "python"
    wheels = sorted(wheel_dir.glob("idapro-*.whl"), reverse=True)
    if not wheels:
        raise RuntimeError(f"IDALib Python wheel not found below {wheel_dir}")
    sys.path.insert(0, str(wheels[0]))
    os.environ["IDADIR"] = str(runtime_dir)
    import idapro  # type: ignore

    return idapro


def _normalize_address(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def _hex(value: int | None) -> str | None:
    return f"0x{value:X}" if isinstance(value, int) else None


def _function_refs(start_ea: int) -> tuple[list[int], list[int], int]:
    import ida_funcs  # type: ignore
    import idautils  # type: ignore

    function = ida_funcs.get_func(start_ea)
    if function is None:
        return [], [], 0
    callees: set[int] = set()
    instruction_count = 0
    for instruction_ea in idautils.FuncItems(start_ea):
        instruction_count += 1
        for ref in idautils.CodeRefsFrom(instruction_ea, False):
            target = ida_funcs.get_func(ref)
            if target is not None and target.start_ea != start_ea:
                callees.add(int(target.start_ea))
    callers: set[int] = set()
    for ref in idautils.CodeRefsTo(start_ea, False):
        source = ida_funcs.get_func(ref)
        if source is not None and source.start_ea != start_ea:
            callers.add(int(source.start_ea))
    return sorted(callers), sorted(callees), instruction_count


def _inventory() -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]]]:
    import ida_funcs  # type: ignore
    import ida_ida  # type: ignore
    import ida_segment  # type: ignore
    import idautils  # type: ignore
    import idc  # type: ignore

    rows: list[dict[str, Any]] = []
    by_address: dict[int, dict[str, Any]] = {}
    demangle_flags = idc.get_inf_attr(idc.INF_SHORT_DN)
    for start_ea in idautils.Functions():
        function = ida_funcs.get_func(start_ea)
        if function is None:
            continue
        name = idc.get_func_name(start_ea) or f"sub_{start_ea:X}"
        segment = ida_segment.getseg(start_ea)
        row = {
            "address": _hex(int(start_ea)),
            "end_address": _hex(int(function.end_ea)),
            "size_bytes": max(0, int(function.end_ea - start_ea)),
            "name": name,
            "demangled_name": idc.demangle_name(name, demangle_flags),
            "segment": ida_segment.get_segm_name(segment) if segment else None,
            "processor": ida_ida.inf_get_procname(),
        }
        rows.append(row)
        by_address[int(start_ea)] = row
    return rows, by_address


def _resolve_seed_addresses(
    seeds: list[dict[str, Any]],
    inventory: list[dict[str, Any]],
) -> tuple[set[int], dict[int, dict[str, Any]]]:
    import ida_funcs  # type: ignore

    by_name: dict[str, list[int]] = {}
    by_address: dict[int, dict[str, Any]] = {}
    for row in inventory:
        address = _normalize_address(row.get("address"))
        if address is None:
            continue
        by_address[address] = row
        for value in (row.get("name"), row.get("demangled_name")):
            if value:
                by_name.setdefault(str(value), []).append(address)

    resolved: set[int] = set()
    seed_by_address: dict[int, dict[str, Any]] = {}
    for seed in seeds:
        address = _normalize_address(seed.get("address"))
        if address is not None:
            function = ida_funcs.get_func(address)
            if function is not None:
                resolved.add(int(function.start_ea))
                seed_by_address[int(function.start_ea)] = seed
                continue
        name = str(seed.get("name") or "")
        matches = by_name.get(name) or []
        if not matches and name:
            lowered = name.lower()
            matches = [
                item_address
                for candidate_name, addresses in by_name.items()
                if lowered in candidate_name.lower()
                for item_address in addresses
            ][:4]
        for match in matches:
            resolved.add(match)
            seed_by_address.setdefault(match, seed)
    return resolved, seed_by_address


def _selection_score(
    row: dict[str, Any],
    *,
    seed_addresses: set[int],
    depth_by_address: dict[int, int],
) -> tuple[int, list[str]]:
    address = _normalize_address(row.get("address"))
    name = str(row.get("demangled_name") or row.get("name") or "")
    lowered = name.lower()
    size = int(row.get("size_bytes") or 0)
    score = 0
    reasons: list[str] = []
    if address in seed_addresses:
        score += 1000
        reasons.append("pipeline_seed")
    depth = depth_by_address.get(address) if address is not None else None
    if depth is not None and depth > 0:
        graph_bonus = max(40, 260 - (depth - 1) * 100)
        score += graph_bonus
        reasons.append(f"seed_callgraph_depth:{depth}")
    marker_hits = [marker for marker in HIGH_VALUE_MARKERS if marker in lowered]
    if marker_hits:
        score += min(180, 30 * len(marker_hits))
        reasons.extend(f"name:{marker}" for marker in marker_hits[:6])
    if name.startswith("Java_"):
        score += 20
        reasons.append("jni_entry")
    if 64 <= size <= 200_000:
        score += min(100, max(5, size // 160))
        reasons.append("substantive_size")
    elif size < 24:
        score -= 200
        reasons.append("tiny_function_penalty")
    wrapper_hits = [marker for marker in WRAPPER_MARKERS if marker in lowered]
    if wrapper_hits:
        score -= 180
        reasons.extend(f"wrapper:{marker}" for marker in wrapper_hits[:4])
    if name.startswith(("nullsub_", "j_")):
        score -= 240
        reasons.append("stub_or_thunk_penalty")
    return score, reasons


def _select_functions(
    seeds: list[dict[str, Any]],
    inventory: list[dict[str, Any]],
    *,
    max_targets: int,
    callgraph_depth: int,
) -> list[dict[str, Any]]:
    seed_addresses, seed_by_address = _resolve_seed_addresses(seeds, inventory)
    context_seed_by_address = dict(seed_by_address)
    depth_by_address: dict[int, int] = {address: 0 for address in seed_addresses}
    frontier = set(seed_addresses)
    refs_by_address: dict[int, tuple[list[int], list[int], int]] = {}
    for depth in range(1, max(0, callgraph_depth) + 1):
        next_frontier: set[int] = set()
        for address in sorted(frontier):
            refs = refs_by_address.get(address)
            if refs is None:
                refs = _function_refs(address)
                refs_by_address[address] = refs
            for neighbor in [*refs[0], *refs[1]]:
                if neighbor in depth_by_address:
                    continue
                depth_by_address[neighbor] = depth
                context_seed_by_address[neighbor] = context_seed_by_address.get(
                    address,
                    {},
                )
                next_frontier.add(neighbor)
        frontier = next_frontier
        if not frontier:
            break

    ranked: list[dict[str, Any]] = []
    for row in inventory:
        function_address = _normalize_address(row.get("address"))
        if function_address is None:
            continue
        score, reasons = _selection_score(
            row,
            seed_addresses=seed_addresses,
            depth_by_address=depth_by_address,
        )
        if score <= 0:
            continue
        seed = context_seed_by_address.get(function_address) or {}
        ranked.append(
            {
                **row,
                "selection_score": score,
                "selection_reasons": reasons,
                "seed_target": seed,
                "is_pipeline_seed": function_address in seed_addresses,
                "graph_depth_from_seed": depth_by_address.get(function_address),
            }
        )
    ranked.sort(
        key=lambda row: (
            -int(row.get("selection_score") or 0),
            -int(row.get("size_bytes") or 0),
            str(row.get("address") or ""),
        )
    )
    return ranked[: max(1, max_targets)]


def _string_refs(start_ea: int, max_items: int = 100) -> list[str]:
    import ida_bytes  # type: ignore
    import ida_nalt  # type: ignore
    import idautils  # type: ignore

    values: set[str] = set()
    for instruction_ea in idautils.FuncItems(start_ea):
        for ref in idautils.DataRefsFrom(instruction_ea):
            raw = ida_bytes.get_strlit_contents(ref, -1, ida_nalt.STRTYPE_C)
            if not raw:
                continue
            try:
                value = raw.decode("utf-8", errors="ignore")
            except AttributeError:
                value = str(raw)
            value = value.strip()
            if 3 < len(value) <= 500:
                values.add(value)
            if len(values) >= max_items:
                return sorted(values)
    return sorted(values)


def _flow_metrics(start_ea: int) -> tuple[int, int]:
    import ida_funcs  # type: ignore
    import ida_gdl  # type: ignore

    function = ida_funcs.get_func(start_ea)
    if function is None:
        return 0, 0
    blocks = list(ida_gdl.FlowChart(function))
    edges = sum(len(list(block.succs())) for block in blocks)
    return len(blocks), edges


def _decompile_record(
    selected: dict[str, Any],
    *,
    job: dict[str, Any],
    pseudocode_dir: Path,
) -> dict[str, Any]:
    import ida_hexrays  # type: ignore
    import idc  # type: ignore

    started = time.monotonic()
    address = _normalize_address(selected.get("address"))
    if address is None:
        raise ValueError("selected function has no address")
    callers, callees, instruction_count = _function_refs(address)
    block_count, edge_count = _flow_metrics(address)
    record: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA,
        "job_hash": job.get("job_hash"),
        "library": job.get("library"),
        "library_sha256": job.get("library_sha256"),
        "abi": job.get("abi"),
        "ownership": job.get("ownership") or {},
        "address": _hex(address),
        "end_address": selected.get("end_address"),
        "size_bytes": selected.get("size_bytes"),
        "name": selected.get("name"),
        "demangled_name": selected.get("demangled_name"),
        "selection_score": selected.get("selection_score"),
        "selection_reasons": selected.get("selection_reasons") or [],
        "graph_depth_from_seed": selected.get("graph_depth_from_seed"),
        "seed_target": selected.get("seed_target") or {},
        "is_pipeline_seed": bool(selected.get("is_pipeline_seed")),
        "callers": [_hex(item) for item in callers],
        "callees": [_hex(item) for item in callees],
        "call_targets": [idc.get_func_name(item) or _hex(item) for item in callees],
        "instruction_count": instruction_count,
        "basic_block_count": block_count,
        "cfg_edge_count": edge_count,
        "string_refs": _string_refs(address),
        "tool": "ida",
        "backend": "idalib_hexrays",
    }
    try:
        cfunc = ida_hexrays.decompile(address)
        if cfunc is None:
            raise RuntimeError("Hex-Rays returned no cfunc")
        pseudocode = str(cfunc)
        limit = int(job.get("max_pseudocode_chars") or 500_000)
        truncated = len(pseudocode) > limit
        if truncated:
            pseudocode = pseudocode[:limit]
        filename = "__".join(
            (
                _safe_name(str(record.get("address") or "unknown")),
                _safe_name(str(record.get("demangled_name") or record.get("name") or "function")),
            )
        ) + ".c"
        output_path = pseudocode_dir / filename
        output_path.write_text(pseudocode, encoding="utf-8")
        record.update(
            {
                "success": bool(pseudocode.strip()),
                "pseudocode_path": str(output_path),
                "pseudocode_sha256": _sha256_file(output_path),
                "pseudocode_line_count": len(pseudocode.splitlines()),
                "pseudocode_nonempty_line_count": len(
                    [line for line in pseudocode.splitlines() if line.strip()]
                ),
                "pseudocode_truncated": truncated,
                "error": None,
            }
        )
    except Exception as error:
        record.update(
            {
                "success": False,
                "pseudocode_path": None,
                "pseudocode_sha256": None,
                "pseudocode_line_count": 0,
                "pseudocode_nonempty_line_count": 0,
                "pseudocode_truncated": False,
                "error": f"{type(error).__name__}: {error}",
            }
        )
    record["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return record


def _preflight(ida_install_dir: Path, result_path: Path) -> int:
    try:
        idapro = _activate_idalib(ida_install_dir)
        payload = {
            "schema_version": RESULT_SCHEMA,
            "available": True,
            "library_version": idapro.get_library_version(),
            "ida_install_dir": str(ida_install_dir),
            "hexrays_status": "not_tested_without_database",
            "error": None,
        }
        exit_code = 0
    except Exception as error:
        payload = {
            "schema_version": RESULT_SCHEMA,
            "available": False,
            "ida_install_dir": str(ida_install_dir),
            "error": f"{type(error).__name__}: {error}",
        }
        exit_code = 1
    result_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_json(result_path, payload)
    return exit_code


def _run_job(job_path: Path, output_dir: Path, ida_install_dir: Path) -> int:
    job = json.loads(job_path.read_text(encoding="utf-8"))
    if job.get("schema_version") != JOB_SCHEMA:
        raise ValueError(f"Unsupported job schema: {job.get('schema_version')}")
    output_dir.mkdir(parents=True, exist_ok=True)
    pseudocode_dir = output_dir / "pseudocode"
    pseudocode_dir.mkdir(parents=True, exist_ok=True)
    results_path = output_dir / "functions.jsonl"
    progress_path = output_dir / "progress.json"
    summary_path = output_dir / "summary.json"
    inventory_path = output_dir / "inventory.json"

    library = Path(str(job.get("library") or ""))
    analysis_binary = Path(str(job.get("analysis_binary") or library))
    if not analysis_binary.is_file():
        raise FileNotFoundError(f"Native library not found: {analysis_binary}")
    expected_hash = str(job.get("library_sha256") or "")
    actual_hash = _sha256_file(analysis_binary)
    if expected_hash and actual_hash != expected_hash:
        raise ValueError(
            f"Native library hash mismatch: expected {expected_hash}, got {actual_hash}"
        )

    idapro = _activate_idalib(ida_install_dir)
    started = time.monotonic()
    open_result = idapro.open_database(str(analysis_binary), True)
    if open_result != 0:
        raise RuntimeError(f"IDALib open_database failed with code {open_result}")
    try:
        import ida_auto  # type: ignore
        import ida_hexrays  # type: ignore
        import idaapi  # type: ignore

        _atomic_json(
            progress_path,
            {
                "schema_version": RESULT_SCHEMA,
                "job_hash": job.get("job_hash"),
                "stage": "autoanalysis",
                "processed": 0,
                "selected": 0,
                "current_function": None,
                "updated_at_epoch": time.time(),
            },
        )
        ida_auto.auto_wait()
        inventory, _ = _inventory()
        _atomic_json(
            inventory_path,
            {
                "schema_version": RESULT_SCHEMA,
                "job_hash": job.get("job_hash"),
                "library": str(library),
                "analysis_binary": str(analysis_binary),
                "library_sha256": actual_hash,
                "function_count": len(inventory),
                "functions": inventory,
            },
        )
        selected = _select_functions(
            [item for item in job.get("seed_targets") or [] if isinstance(item, dict)],
            inventory,
            max_targets=int(job.get("max_targets") or 1),
            callgraph_depth=int(job.get("callgraph_depth") or 2),
        )
        current_rows = _current_job_rows(
            results_path,
            str(job.get("job_hash") or ""),
        )
        existing = {
            str(row.get("address"))
            for row in current_rows
            if _completed_checkpoint(row)
        }
        decompiler_available = bool(ida_hexrays.init_hexrays_plugin())
        if not decompiler_available:
            raise RuntimeError("Hex-Rays decompiler API is unavailable for this database")

        processed = len(existing)
        _atomic_json(
            progress_path,
            {
                "schema_version": RESULT_SCHEMA,
                "job_hash": job.get("job_hash"),
                "stage": "decompilation",
                "processed": processed,
                "selected": len(selected),
                "current_function": None,
                "updated_at_epoch": time.time(),
            },
        )
        for item in selected:
            if str(item.get("address")) in existing:
                continue
            current_started_at = time.time()
            _atomic_json(
                progress_path,
                {
                    "schema_version": RESULT_SCHEMA,
                    "job_hash": job.get("job_hash"),
                    "stage": "decompilation",
                    "processed": processed,
                    "selected": len(selected),
                    "current_function": item,
                    "current_started_at_epoch": current_started_at,
                    "updated_at_epoch": current_started_at,
                },
            )
            record = _decompile_record(
                item,
                job=job,
                pseudocode_dir=pseudocode_dir,
            )
            record["ida_version"] = idaapi.get_kernel_version()
            record["hexrays_version"] = ida_hexrays.get_hexrays_version()
            _append_jsonl(results_path, record)
            processed += 1
            _atomic_json(
                progress_path,
                {
                    "schema_version": RESULT_SCHEMA,
                    "job_hash": job.get("job_hash"),
                    "processed": processed,
                    "selected": len(selected),
                    "stage": "decompilation",
                    "current_function": None,
                    "updated_at_epoch": time.time(),
                },
            )

        rows = _current_job_rows(
            results_path,
            str(job.get("job_hash") or ""),
        )
        summary = {
            "schema_version": RESULT_SCHEMA,
            "job_hash": job.get("job_hash"),
            "status": "completed",
            "library": str(library),
            "library_sha256": actual_hash,
            "abi": job.get("abi"),
            "ida_version": idaapi.get_kernel_version(),
            "hexrays_version": ida_hexrays.get_hexrays_version(),
            "inventory_function_count": len(inventory),
            "selected_function_count": len(selected),
            "processed_function_count": len(rows),
            "successful_decompilations": sum(1 for row in rows if row.get("success")),
            "failed_decompilations": sum(1 for row in rows if not row.get("success")),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "completed": True,
        }
        _atomic_json(
            progress_path,
            {
                "schema_version": RESULT_SCHEMA,
                "job_hash": job.get("job_hash"),
                "stage": "completed",
                "processed": len(rows),
                "selected": len(selected),
                "current_function": None,
                "updated_at_epoch": time.time(),
            },
        )
        _atomic_json(summary_path, summary)
        return 0
    finally:
        idapro.close_database(False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Isolated IDALib worker")
    parser.add_argument("--ida-install-dir", type=Path, required=True)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--result", type=Path)
    parser.add_argument("--job", type=Path)
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.preflight:
        if args.result is None:
            raise SystemExit("--result is required with --preflight")
        return _preflight(args.ida_install_dir, args.result)
    if args.job is None or args.output_dir is None:
        raise SystemExit("--job and --output-dir are required")
    try:
        return _run_job(args.job, args.output_dir, args.ida_install_dir)
    except Exception as error:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        _atomic_json(
            args.output_dir / "summary.json",
            {
                "schema_version": RESULT_SCHEMA,
                "status": "failed",
                "completed": False,
                "error": f"{type(error).__name__}: {error}",
            },
        )
        print(f"IDA worker failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
