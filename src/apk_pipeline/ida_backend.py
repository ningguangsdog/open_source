"""Automated IDA Classroom backend for Phase 3 native analysis."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

from .evidence import token_fingerprint
from .native_semantics import classify_native_semantics
from .utils import ensure_dir, safe_name, safe_read_text, safe_write_json, sha256_file


logger = logging.getLogger(__name__)

IDA_JOB_SCHEMA = "2026-08-20.ida-worker-job.v1"
IDA_BACKEND_SCHEMA = "2026-08-20.ida-backend.v1"
ProgressCallback = Callable[[dict[str, Any]], None]


def _emit(callback: ProgressCallback | None, payload: dict[str, Any]) -> None:
    if callback is not None:
        callback(payload)


def _runtime_dir(install_dir: Path) -> Path:
    if install_dir.suffix == ".app":
        return install_dir / "Contents" / "MacOS"
    return install_dir


def _idalib_name() -> str:
    if sys.platform == "darwin":
        return "libidalib.dylib"
    if sys.platform.startswith("linux"):
        return "libidalib.so"
    if sys.platform == "win32":
        return "idalib.dll"
    return "libidalib"


def discover_ida_installation(configured: str | Path | None = None) -> Path | None:
    """Find an IDA 9.x installation with both IDALib and its Python wheel."""

    candidates: list[Path] = []
    for value in (
        configured,
        os.environ.get("IDA_INSTALL_DIR"),
        os.environ.get("IDADIR"),
    ):
        if value:
            candidates.append(Path(value).expanduser())
    if sys.platform == "darwin":
        applications = Path("/Applications")
        candidates.extend(
            [
                applications / "IDA Classroom 9.4.app",
                applications / "IDA Professional 9.4.app",
                applications / "IDA Pro 9.4.app",
                applications / "IDA Classroom.app",
                applications / "IDA Professional.app",
            ]
        )
        if applications.is_dir():
            candidates.extend(sorted(applications.glob("IDA*.app"), reverse=True))

    seen: set[str] = set()
    for candidate in candidates:
        normalized = candidate.expanduser().resolve()
        key = str(normalized)
        if key in seen:
            continue
        seen.add(key)
        runtime = _runtime_dir(normalized)
        if not (runtime / _idalib_name()).is_file():
            continue
        if not list((runtime / "idalib" / "python").glob("idapro-*.whl")):
            continue
        return normalized
    return None


def ida_installation_info(configured: str | Path | None = None) -> dict[str, Any]:
    install_dir = discover_ida_installation(configured)
    if install_dir is None:
        return {
            "available": False,
            "automated_adapter": True,
            "install_dir": None,
            "runtime_dir": None,
            "idalib_path": None,
            "python_wheel": None,
            "reason": "IDA 9.x with IDALib and the idapro wheel was not found.",
        }
    runtime = _runtime_dir(install_dir)
    wheels = sorted((runtime / "idalib" / "python").glob("idapro-*.whl"), reverse=True)
    return {
        "available": True,
        "automated_adapter": True,
        "install_dir": str(install_dir),
        "runtime_dir": str(runtime),
        "idalib_path": str(runtime / _idalib_name()),
        "python_wheel": str(wheels[0]),
        "reason": "IDA IDALib runtime and Python package were found.",
    }


def _copy_ida_user_files(destination: Path) -> None:
    source_value = os.environ.get("IDAUSR")
    source = Path(source_value).expanduser() if source_value else Path.home() / ".idapro"
    destination.mkdir(parents=True, exist_ok=True)
    if not source.is_dir():
        return
    for name in ("ida.reg", "ida-config.json"):
        path = source / name
        if path.is_file():
            shutil.copy2(path, destination / name)


def run_ida_preflight(
    configured: str | Path | None = None,
    *,
    python_executable: str | Path | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    info = ida_installation_info(configured)
    if not info.get("available"):
        return info
    install_dir = Path(str(info["install_dir"]))
    worker = Path(__file__).with_name("ida_worker.py")
    executable = str(python_executable or sys.executable)
    with tempfile.TemporaryDirectory(prefix="apk-pipeline-ida-preflight-") as temporary:
        root = Path(temporary)
        idausr = root / "idausr"
        _copy_ida_user_files(idausr)
        result_path = root / "result.json"
        environment = os.environ.copy()
        environment["IDAUSR"] = str(idausr)
        command = [
            executable,
            str(worker),
            "--ida-install-dir",
            str(install_dir),
            "--preflight",
            "--result",
            str(result_path),
        ]
        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
                env=environment,
            )
        except subprocess.TimeoutExpired:
            return {
                **info,
                "available": False,
                "preflight_status": "timeout",
                "error": f"IDALib preflight exceeded {timeout} seconds.",
            }
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        return {
            **info,
            **payload,
            "available": completed.returncode == 0 and bool(payload.get("available")),
            "preflight_status": "success" if completed.returncode == 0 else "failed",
            "returncode": completed.returncode,
            "stdout_tail": (completed.stdout or "")[-2000:],
            "stderr_tail": (completed.stderr or "")[-4000:],
        }


def _canonical_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            value = json.loads(line)
        except Exception:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _latest_job_rows(path: Path, job_hash: str) -> list[dict[str, Any]]:
    """Return the final checkpoint state for each function in one IDA job."""

    by_address: dict[str, dict[str, Any]] = {}
    for row in _read_jsonl(path):
        if row.get("job_hash") != job_hash:
            continue
        address = str(row.get("address") or "")
        if not address:
            continue
        by_address[address] = row
    return list(by_address.values())


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _record_function_timeout(
    job_dir: Path,
    job: dict[str, Any],
    selected: dict[str, Any],
    *,
    timeout: int,
) -> None:
    """Checkpoint a watchdog timeout so the next worker can continue."""

    address = str(selected.get("address") or "")
    if not address:
        return
    current = {
        str(row.get("address")): row
        for row in _latest_job_rows(
            job_dir / "functions.jsonl",
            str(job.get("job_hash") or ""),
        )
    }
    if current.get(address, {}).get("terminal_failure") is True:
        return
    _append_jsonl(
        job_dir / "functions.jsonl",
        {
            "schema_version": "2026-08-20.ida-worker-result.v1",
            "job_hash": job.get("job_hash"),
            "library": job.get("library"),
            "library_sha256": job.get("library_sha256"),
            "abi": job.get("abi"),
            "ownership": job.get("ownership") or {},
            "address": address,
            "end_address": selected.get("end_address"),
            "size_bytes": selected.get("size_bytes"),
            "name": selected.get("name"),
            "demangled_name": selected.get("demangled_name"),
            "selection_score": selected.get("selection_score"),
            "selection_reasons": selected.get("selection_reasons") or [],
            "graph_depth_from_seed": selected.get("graph_depth_from_seed"),
            "seed_target": selected.get("seed_target") or {},
            "is_pipeline_seed": bool(selected.get("is_pipeline_seed")),
            "success": False,
            "terminal_failure": True,
            "pseudocode_path": None,
            "pseudocode_sha256": None,
            "pseudocode_line_count": 0,
            "pseudocode_nonempty_line_count": 0,
            "pseudocode_truncated": False,
            "callers": [],
            "callees": [],
            "call_targets": [],
            "instruction_count": 0,
            "basic_block_count": 0,
            "cfg_edge_count": 0,
            "string_refs": [],
            "tool": "ida",
            "backend": "idalib_hexrays",
            "elapsed_seconds": timeout,
            "error": f"function_timeout:{timeout}",
        },
    )


def _run_worker_with_heartbeat(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: int,
    timeout_per_function: int,
    job_dir: Path,
    progress_callback: ProgressCallback | None,
    library: str,
    index: int,
    total: int,
    attempt: int,
) -> tuple[int | None, str, str, str | None, dict[str, Any] | None]:
    """Run one worker while reporting checkpoint progress to the parent."""

    process = subprocess.Popen(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    started = time.monotonic()
    last_heartbeat = started
    deadline = started + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            stdout, stderr = process.communicate()
            return (
                None,
                stdout or "",
                stderr or "",
                f"worker_timeout:{timeout}",
                None,
            )
        try:
            stdout, stderr = process.communicate(timeout=min(2, remaining))
            return process.returncode, stdout or "", stderr or "", None, None
        except subprocess.TimeoutExpired:
            progress = _read_json(job_dir / "progress.json")
            current_value = progress.get("current_function")
            current = current_value if isinstance(current_value, dict) else None
            current_started = float(progress.get("current_started_at_epoch") or 0)
            function_elapsed = (
                max(0.0, time.time() - current_started)
                if current is not None and current_started > 0
                else 0.0
            )
            if current is not None and function_elapsed >= timeout_per_function:
                process.kill()
                stdout, stderr = process.communicate()
                return (
                    None,
                    stdout or "",
                    stderr or "",
                    f"function_timeout:{timeout_per_function}",
                    current,
                )
            now = time.monotonic()
            if now - last_heartbeat >= 20:
                _emit(
                    progress_callback,
                    {
                        "event": "ida_library_heartbeat",
                        "index": index,
                        "total": total,
                        "library": library,
                        "attempt": attempt,
                        "elapsed_seconds": round(now - started, 1),
                        "processed_functions": int(progress.get("processed") or 0),
                        "selected_functions": int(progress.get("selected") or 0),
                        "stage": progress.get("stage"),
                        "current_function": (
                            current.get("demangled_name")
                            or current.get("name")
                            or current.get("address")
                            if current
                            else None
                        ),
                        "function_elapsed_seconds": round(function_elapsed, 1),
                    },
                )
                last_heartbeat = now


def _allocate_library_budgets(
    targets_by_library: dict[str, list[dict[str, Any]]],
    max_targets: int,
) -> dict[str, int]:
    libraries = sorted(
        targets_by_library,
        key=lambda library: (
            -max(
                [int(item.get("score") or 0) for item in targets_by_library[library]]
                or [0]
            ),
            library,
        ),
    )
    if not libraries:
        return {}
    max_targets = max(len(libraries), max_targets)
    budgets = {library: 1 for library in libraries}
    remaining = max_targets - len(libraries)
    cursor = 0
    while remaining > 0:
        budgets[libraries[cursor % len(libraries)]] += 1
        cursor += 1
        remaining -= 1
    return budgets


def _prepare_job_directory(
    root: Path,
    library_path: Path,
    library_sha256: str,
    job: dict[str, Any],
) -> tuple[Path, Path]:
    identity = "__".join(
        (
            safe_name(str(job.get("abi") or "unknown_abi")),
            safe_name(library_path.name),
            library_sha256[:12],
        )
    )
    job_dir = ensure_dir(root / "libraries" / identity)
    manifest_path = job_dir / "job.json"
    previous = _read_json(manifest_path)
    if previous.get("job_hash") != job.get("job_hash"):
        for name in (
            "functions.jsonl",
            "inventory.json",
            "progress.json",
            "summary.json",
        ):
            (job_dir / name).unlink(missing_ok=True)
        pseudocode = job_dir / "pseudocode"
        if pseudocode.exists():
            shutil.rmtree(pseudocode)
    input_dir = ensure_dir(job_dir / "input")
    analysis_binary = input_dir / library_path.name
    if not analysis_binary.is_file() or sha256_file(analysis_binary) != library_sha256:
        shutil.copy2(library_path, analysis_binary)
    job["analysis_binary"] = str(analysis_binary)
    safe_write_json(manifest_path, job)
    return job_dir, analysis_binary


def _result_from_worker_row(row: dict[str, Any]) -> dict[str, Any]:
    seed_value = row.get("seed_target")
    seed: dict[str, Any] = seed_value if isinstance(seed_value, dict) else {}
    name = str(row.get("demangled_name") or row.get("name") or "")
    pseudocode_path = Path(str(row.get("pseudocode_path") or ""))
    pseudocode = safe_read_text(pseudocode_path, limit=500_000) if pseudocode_path.is_file() else ""
    target = {
        "library": row.get("library"),
        "kind": (
            seed.get("kind")
            if row.get("is_pipeline_seed")
            else "internal_callee"
        )
        or "internal_callee",
        "name": name,
        "address": row.get("address"),
        "size_bytes": row.get("size_bytes"),
        "score": row.get("selection_score") or seed.get("score") or 0,
        "capabilities": seed.get("capabilities") or [],
        "reasons": [
            *(seed.get("reasons") or []),
            *(row.get("selection_reasons") or []),
        ],
        "ownership": row.get("ownership") or seed.get("ownership") or {},
        "library_sha256": row.get("library_sha256"),
        "abi": row.get("abi"),
        "abi_analysis_role": seed.get("abi_analysis_role"),
        "associated_java_methods": seed.get("associated_java_methods") or [],
        "discovered_by": "ida_callgraph_expansion",
        "graph_depth_from_seed": row.get("graph_depth_from_seed"),
    }
    features = {
        "schema_version": "2026-08-20.native-function-features.v2",
        "library": row.get("library"),
        "library_sha256": row.get("library_sha256"),
        "abi": row.get("abi"),
        "target_kind": target["kind"],
        "name": name,
        "address": row.get("address"),
        "resolved_name": name,
        "resolved_offset": row.get("address"),
        "score": target["score"],
        "capabilities": target["capabilities"],
        "reasons": target["reasons"],
        "instruction_count": row.get("instruction_count") or 0,
        "basic_block_count": row.get("basic_block_count") or 0,
        "cfg_edge_count": row.get("cfg_edge_count") or 0,
        "xref_count": len(row.get("callers") or []),
        "pseudocode_line_count": row.get("pseudocode_line_count") or 0,
        "pseudocode_nonempty_line_count": row.get("pseudocode_nonempty_line_count") or 0,
        "call_targets": row.get("call_targets") or [],
        "caller_addresses": row.get("callers") or [],
        "callee_addresses": row.get("callees") or [],
        "string_refs": row.get("string_refs") or [],
        "pseudocode_fingerprint": token_fingerprint(pseudocode),
    }
    feature_payload = {
        key: value
        for key, value in features.items()
        if key not in {"schema_version", "feature_hash"}
    }
    features["feature_hash"] = _canonical_hash(feature_payload)
    semantic = classify_native_semantics(
        name,
        pseudocode=pseudocode,
        features=features,
    )
    target["semantic_role_prior"] = semantic
    return {
        "success": bool(row.get("success")),
        "tool": "ida",
        "backend": row.get("backend") or "idalib_hexrays",
        "ida_version": row.get("ida_version"),
        "hexrays_version": row.get("hexrays_version"),
        "output_path": str(pseudocode_path) if pseudocode_path.is_file() else None,
        "pseudocode_sha256": row.get("pseudocode_sha256"),
        "target": target,
        "function_features": features,
        "semantic_role": semantic,
        "xrefs": [
            *(
                {"type": "caller", "address": address}
                for address in row.get("callers") or []
            ),
            *(
                {"type": "callee", "address": address}
                for address in row.get("callees") or []
            ),
        ],
        "cfg_summary": {
            "basic_block_count": features["basic_block_count"],
            "cfg_edge_count": features["cfg_edge_count"],
            "instruction_count": features["instruction_count"],
        },
        "pseudocode_truncated": bool(row.get("pseudocode_truncated")),
        "elapsed_seconds": row.get("elapsed_seconds"),
        "error": row.get("error"),
    }


def run_ida_decompile(
    targets: list[dict[str, Any]],
    output_dir: Path,
    *,
    install_dir: str | Path | None = None,
    python_executable: str | Path | None = None,
    timeout_per_function: int = 120,
    timeout_per_app: int = 7200,
    max_targets: int = 120,
    max_retries: int = 1,
    callgraph_depth: int = 2,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Run serial, checkpointed IDALib jobs for the selected native libraries."""

    started = time.monotonic()
    output_dir = ensure_dir(output_dir)
    installation = ida_installation_info(install_dir)
    if not installation.get("available"):
        return {
            "schema_version": IDA_BACKEND_SCHEMA,
            "status": "tool_missing",
            "tool": "ida",
            "attempted_targets": 0,
            "results": [],
            "installation": installation,
            "message": installation.get("reason"),
        }
    resolved_install = Path(str(installation["install_dir"]))
    worker = Path(__file__).with_name("ida_worker.py")
    executable = str(python_executable or sys.executable)

    targets_by_library: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for target in targets:
        library = str(target.get("library") or "")
        if library:
            targets_by_library[library].append(target)
    budgets = _allocate_library_budgets(targets_by_library, max_targets)
    results: list[dict[str, Any]] = []
    library_summaries: list[dict[str, Any]] = []
    status = "completed"

    for index, library_name in enumerate(budgets, start=1):
        elapsed = time.monotonic() - started
        if elapsed >= timeout_per_app:
            status = "app_timeout"
            break
        library_path = Path(library_name)
        seeds = targets_by_library[library_name]
        expected_hash = str(seeds[0].get("library_sha256") or "")
        if not library_path.is_file():
            status = "partial"
            library_summaries.append(
                {
                    "library": library_name,
                    "status": "failed",
                    "error": "library_not_found",
                }
            )
            continue
        actual_hash = sha256_file(library_path)
        if expected_hash and expected_hash != actual_hash:
            status = "partial"
            library_summaries.append(
                {
                    "library": library_name,
                    "status": "failed",
                    "error": "library_hash_mismatch",
                    "expected_sha256": expected_hash,
                    "actual_sha256": actual_hash,
                }
            )
            continue

        job_core = {
            "schema_version": IDA_JOB_SCHEMA,
            "library": str(library_path),
            "library_sha256": actual_hash,
            "abi": seeds[0].get("abi"),
            "ownership": seeds[0].get("ownership") or {},
            "seed_targets": seeds,
            "max_targets": budgets[library_name],
            "callgraph_depth": max(0, callgraph_depth),
            "max_pseudocode_chars": 500_000,
        }
        job_core["job_hash"] = _canonical_hash(job_core)
        job_dir, _ = _prepare_job_directory(
            output_dir,
            library_path,
            actual_hash,
            job_core,
        )
        job_path = job_dir / "job.json"
        remaining = max(1, int(timeout_per_app - (time.monotonic() - started)))
        library_timeout = min(
            remaining,
            max(180, 120 + timeout_per_function * budgets[library_name]),
        )
        _emit(
            progress_callback,
            {
                "event": "ida_library_start",
                "index": index,
                "total": len(budgets),
                "library": library_name,
                "seed_count": len(seeds),
                "function_budget": budgets[library_name],
                "timeout": library_timeout,
            },
        )

        final_returncode: int | None = None
        final_error: str | None = None
        attempts = 0
        process_failures = 0
        function_timeouts = 0
        library_deadline = time.monotonic() + library_timeout
        while True:
            attempts += 1
            attempt_remaining = int(
                min(
                    timeout_per_app - (time.monotonic() - started),
                    library_deadline - time.monotonic(),
                )
            )
            if attempt_remaining <= 0:
                final_returncode = None
                final_error = "app_timeout_before_retry"
                break
            with tempfile.TemporaryDirectory(
                prefix=".idausr-",
                dir=str(job_dir),
            ) as temporary:
                idausr = Path(temporary)
                _copy_ida_user_files(idausr)
                environment = os.environ.copy()
                environment["IDAUSR"] = str(idausr)
                command = [
                    executable,
                    str(worker),
                    "--ida-install-dir",
                    str(resolved_install),
                    "--job",
                    str(job_path),
                    "--output-dir",
                    str(job_dir),
                ]
                (
                    final_returncode,
                    _worker_stdout,
                    worker_stderr,
                    timeout_error,
                    timed_out_function,
                ) = _run_worker_with_heartbeat(
                    command,
                    environment=environment,
                    timeout=min(library_timeout, max(1, attempt_remaining)),
                    timeout_per_function=timeout_per_function,
                    job_dir=job_dir,
                    progress_callback=progress_callback,
                    library=library_name,
                    index=index,
                    total=len(budgets),
                    attempt=attempts,
                )
                final_error = timeout_error or (
                    worker_stderr[-4000:]
                    if final_returncode not in {0, None}
                    else None
                )
                if final_returncode == 0:
                    break
                if timed_out_function is not None:
                    _record_function_timeout(
                        job_dir,
                        job_core,
                        timed_out_function,
                        timeout=timeout_per_function,
                    )
                    function_timeouts += 1
                    continue
                process_failures += 1
                if (
                    process_failures > max(0, max_retries)
                    or time.monotonic() - started >= timeout_per_app
                    or time.monotonic() >= library_deadline
                ):
                    break

        summary = _read_json(job_dir / "summary.json")
        worker_rows = _latest_job_rows(
            job_dir / "functions.jsonl",
            str(job_core["job_hash"]),
        )
        converted = [_result_from_worker_row(row) for row in worker_rows]
        results.extend(converted)
        job_status = str(summary.get("status") or "failed")
        if final_returncode != 0 or job_status != "completed":
            status = "partial"
        library_summary = {
            **summary,
            "library": library_name,
            "library_sha256": actual_hash,
            "returncode": final_returncode,
            "attempts": attempts,
            "process_failures": process_failures,
            "function_timeouts": function_timeouts,
            "function_budget": budgets[library_name],
            "result_count": len(converted),
            "error": summary.get("error") or final_error,
        }
        library_summaries.append(library_summary)
        _emit(
            progress_callback,
            {
                "event": "ida_library_finish",
                "index": index,
                "total": len(budgets),
                "library": library_name,
                "status": job_status,
                "result_count": len(converted),
                "successful_decompilations": sum(
                    1 for result in converted if result.get("success")
                ),
                "error": library_summary.get("error"),
            },
        )

    attempted_targets = len(results)
    summary = {
        "schema_version": IDA_BACKEND_SCHEMA,
        "status": status,
        "tool": "ida",
        "backend": "idalib_hexrays",
        "installation": installation,
        "attempted_targets": attempted_targets,
        "selected_target_count": sum(budgets.values()),
        "unattempted_target_count": max(0, sum(budgets.values()) - attempted_targets),
        "libraries_selected": budgets,
        "libraries_attempted": len(library_summaries),
        "successful_decompilations": sum(1 for result in results if result.get("success")),
        "failed_decompilations": sum(1 for result in results if not result.get("success")),
        "library_summaries": library_summaries,
        "budget": {
            "max_targets": max_targets,
            "timeout_per_function": timeout_per_function,
            "timeout_per_app": timeout_per_app,
            "max_retries": max_retries,
            "callgraph_depth": callgraph_depth,
            "worker_count": 1,
        },
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "results": results,
    }
    safe_write_json(output_dir / "ida_backend_summary.json", summary)
    return summary
