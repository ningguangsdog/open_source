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

from .capability_taxonomy import capability_names, classify_text
from .evidence import token_fingerprint
from .native_semantics import classify_native_semantics
from .utils import ensure_dir, safe_name, safe_read_text, safe_write_json, sha256_file


logger = logging.getLogger(__name__)

IDA_JOB_SCHEMA = "2026-08-25.ida-worker-job.v5"
IDA_RESULT_SCHEMA = "2026-08-25.ida-worker-result.v5"
IDA_BACKEND_SCHEMA = "2026-08-25.ida-backend.v5"
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
) -> bool:
    """Checkpoint a watchdog timeout so the next worker can continue."""

    address = str(selected.get("address") or "")
    if not address:
        return False
    current = {
        str(row.get("address")): row
        for row in _latest_job_rows(
            job_dir / "functions.jsonl",
            str(job.get("job_hash") or ""),
        )
    }
    existing = current.get(address, {})
    if existing.get("success") is True or existing.get("terminal_failure") is True:
        return False
    _append_jsonl(
        job_dir / "functions.jsonl",
        {
            "schema_version": IDA_RESULT_SCHEMA,
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
            "selection_source": selected.get("selection_source"),
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
    return True


def _current_worker_progress(
    path: Path,
    *,
    job_hash: str,
    worker_started_at_epoch: float,
) -> dict[str, Any]:
    """Read progress only when it was written by the current worker launch."""

    progress = _read_json(path)
    if progress.get("job_hash") != job_hash:
        return {}
    try:
        updated_at = float(progress.get("updated_at_epoch") or 0)
    except (TypeError, ValueError):
        return {}
    if updated_at < worker_started_at_epoch:
        return {}
    return progress


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
    job_hash: str,
) -> tuple[int | None, str, str, str | None, dict[str, Any] | None]:
    """Run one worker while reporting checkpoint progress to the parent."""

    progress_path = job_dir / "progress.json"
    progress_path.unlink(missing_ok=True)
    worker_started_at_epoch = time.time()
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
            progress = _current_worker_progress(
                progress_path,
                job_hash=job_hash,
                worker_started_at_epoch=worker_started_at_epoch,
            )
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
    seed_counts = {
        library: len(targets_by_library[library]) for library in libraries
    }
    # Every upstream-selected seed is an explicit research decision.  Reserve
    # those slots first; graph and inventory expansion may only consume the
    # remaining context budget.
    effective_max_targets = max(
        len(libraries),
        max_targets,
        sum(seed_counts.values()),
    )
    budgets = dict(seed_counts)
    remaining = effective_max_targets - sum(seed_counts.values())
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
            "inventory.jsonl",
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


def _valid_inventory_checkpoint(
    job_dir: Path,
    *,
    job_hash: str,
    library_sha256: str,
) -> dict[str, Any] | None:
    """Return a completed inventory summary only when its identity still matches."""

    summary = _read_json(job_dir / "summary.json")
    inventory_manifest = _read_json(job_dir / "inventory.json")
    inventory_path = job_dir / "inventory.jsonl"
    if (
        summary.get("status") != "completed"
        or summary.get("completed") is not True
        or str(summary.get("job_hash") or "") != job_hash
        or str(summary.get("library_sha256") or "") != library_sha256
        or str(inventory_manifest.get("job_hash") or "") != job_hash
        or str(inventory_manifest.get("library_sha256") or "")
        != library_sha256
        or not inventory_path.is_file()
    ):
        return None
    expected_count = int(summary.get("inventory_function_count") or 0)
    if expected_count != int(inventory_manifest.get("function_count") or 0):
        return None
    if expected_count > 0 and inventory_path.stat().st_size <= 0:
        return None
    return summary


def _result_from_worker_row(row: dict[str, Any]) -> dict[str, Any]:
    seed_value = row.get("seed_target")
    seed: dict[str, Any] = seed_value if isinstance(seed_value, dict) else {}
    name = str(row.get("demangled_name") or row.get("name") or "")
    pseudocode_path = Path(str(row.get("pseudocode_path") or ""))
    pseudocode = safe_read_text(pseudocode_path, limit=500_000) if pseudocode_path.is_file() else ""
    selection_source = str(row.get("selection_source") or "")
    if not selection_source:
        selection_source = (
            "pipeline_seed"
            if row.get("is_pipeline_seed")
            else "seed_callgraph"
            if row.get("graph_depth_from_seed") is not None
            else "library_inventory"
        )
    context_capabilities = capability_names(seed.get("capabilities") or [])
    function_text = "\n".join(
        [
            name,
            pseudocode,
            " ".join(str(item) for item in (row.get("string_refs") or [])),
            " ".join(str(item) for item in (row.get("call_targets") or [])),
        ]
    )
    classified = classify_text(function_text)
    function_capabilities = capability_names(classified.keys())
    if selection_source in {"pipeline_seed", "seed_callgraph"}:
        function_capabilities = capability_names(
            [*function_capabilities, *context_capabilities]
        )
    target_kind = (
        (seed.get("kind") or "pipeline_seed")
        if selection_source == "pipeline_seed"
        else "internal_callgraph"
        if selection_source == "seed_callgraph"
        else "internal_inventory"
    )
    target = {
        "library": row.get("library"),
        "kind": target_kind,
        "name": name,
        "address": row.get("address"),
        "size_bytes": row.get("size_bytes"),
        "score": row.get("selection_score") or seed.get("score") or 0,
        "capabilities": function_capabilities,
        "context_capabilities": context_capabilities,
        "capability_provenance": (
            "function_and_seed_context"
            if selection_source in {"pipeline_seed", "seed_callgraph"}
            else "function_content_only"
        ),
        "reasons": [
            *(seed.get("reasons") or []),
            *(row.get("selection_reasons") or []),
        ],
        "ownership": row.get("ownership") or seed.get("ownership") or {},
        "library_sha256": row.get("library_sha256"),
        "abi": row.get("abi"),
        "abi_analysis_role": seed.get("abi_analysis_role"),
        "associated_java_methods": seed.get("associated_java_methods") or [],
        "discovered_by": (
            "ida_pipeline_seed"
            if selection_source == "pipeline_seed"
            else "ida_callgraph_expansion"
            if selection_source == "seed_callgraph"
            else "ida_inventory_ranking"
        ),
        "selection_source": selection_source,
        "graph_depth_from_seed": row.get("graph_depth_from_seed"),
        "seed_context": {
            key: seed.get(key)
            for key in (
                "kind",
                "name",
                "address",
                "capabilities",
                "reasons",
                "context_only",
            )
            if seed.get(key) is not None
        },
    }
    if selection_source == "pipeline_seed":
        if seed.get("analysis_lane") is not None:
            target["analysis_lane"] = seed.get("analysis_lane")
        if isinstance(seed.get("reuse_candidate"), dict):
            target["reuse_candidate"] = seed.get("reuse_candidate")
        for key in (
            "candidate_pair_id",
            "commercial_function_id",
            "source_function_id",
        ):
            if seed.get(key) is not None:
                target[key] = seed.get(key)
    elif selection_source == "seed_callgraph":
        # The neighbor remains traceable to the seed that discovered it, but it
        # is a different commercial function and must not inherit the seed's
        # direct open-source identity.  Post-IDA comparison resolves the
        # neighbor independently by its own library hash and address.
        target["origin_seed_candidate"] = {
            key: seed.get(key)
            for key in (
                "analysis_lane",
                "candidate_pair_id",
                "commercial_function_id",
                "source_function_id",
            )
            if seed.get(key) is not None
        }
    features = {
        "schema_version": "2026-08-21.native-function-features.v3",
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
        "context_capabilities": target["context_capabilities"],
        "capability_provenance": target["capability_provenance"],
        "selection_source": selection_source,
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
            app_remaining = timeout_per_app - (time.monotonic() - started)
            library_remaining = library_deadline - time.monotonic()
            attempt_remaining = int(min(app_remaining, library_remaining))
            if attempt_remaining <= 0:
                final_returncode = None
                final_error = (
                    "app_timeout_before_retry"
                    if app_remaining <= 0
                    else "library_timeout_before_retry"
                )
                break
            attempts += 1
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
                    job_hash=str(job_core["job_hash"]),
                )
                final_error = timeout_error or (
                    worker_stderr[-4000:]
                    if final_returncode not in {0, None}
                    else None
                )
                if final_returncode == 0:
                    break
                if timed_out_function is not None:
                    recorded = _record_function_timeout(
                        job_dir,
                        job_core,
                        timed_out_function,
                        timeout=timeout_per_function,
                    )
                    if recorded:
                        function_timeouts += 1
                        continue
                    checkpoint = next(
                        (
                            row
                            for row in _latest_job_rows(
                                job_dir / "functions.jsonl",
                                str(job_core["job_hash"]),
                            )
                            if str(row.get("address") or "")
                            == str(timed_out_function.get("address") or "")
                        ),
                        {},
                    )
                    if checkpoint.get("success") is True:
                        continue
                    process_failures += 1
                    final_error = "duplicate_function_timeout_checkpoint"
                    break
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
    requested_seed_count = sum(len(rows) for rows in targets_by_library.values())
    resolved_seed_count = sum(
        int(item.get("resolved_seed_count") or 0) for item in library_summaries
    )
    selected_seed_count = sum(
        int(item.get("selected_seed_count") or 0) for item in library_summaries
    )
    unresolved_seed_count = sum(
        int(item.get("unresolved_seed_count") or 0) for item in library_summaries
    )
    selection_source_counts = Counter(
        str((result.get("target") or {}).get("selection_source") or "unknown")
        for result in results
    )
    summary = {
        "schema_version": IDA_BACKEND_SCHEMA,
        "status": status,
        "tool": "ida",
        "backend": "idalib_hexrays",
        "installation": installation,
        "attempted_targets": attempted_targets,
        "selected_target_count": sum(budgets.values()),
        "unattempted_target_count": max(0, sum(budgets.values()) - attempted_targets),
        "requested_seed_count": requested_seed_count,
        "resolved_seed_count": resolved_seed_count,
        "selected_seed_count": selected_seed_count,
        "unresolved_seed_count": unresolved_seed_count,
        "unselected_resolved_seed_count": max(
            0, resolved_seed_count - selected_seed_count
        ),
        "selection_source_counts": dict(sorted(selection_source_counts.items())),
        "libraries_selected": budgets,
        "libraries_attempted": len(library_summaries),
        "successful_decompilations": sum(1 for result in results if result.get("success")),
        "failed_decompilations": sum(1 for result in results if not result.get("success")),
        "library_summaries": library_summaries,
        "budget": {
            "max_targets": max_targets,
            "effective_max_targets": sum(budgets.values()),
            "expanded_for_seed_coverage": sum(budgets.values()) > max_targets,
            "allocation_policy": "seed_floor_then_context_round_robin",
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


def _library_record_path(record: dict[str, Any]) -> Path | None:
    value = record.get("extracted_path") or record.get("path") or record.get("entry")
    if not value:
        return None
    return Path(str(value))


def run_ida_inventory(
    library_records: list[dict[str, Any]],
    output_dir: Path,
    *,
    install_dir: str | Path | None = None,
    python_executable: str | Path | None = None,
    timeout_per_library: int = 1200,
    timeout_per_app: int = 14_400,
    max_retries: int = 1,
    max_instructions_per_function: int = 512,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Build a content-deduplicated full native index without Hex-Rays calls."""

    if timeout_per_library <= 0 or timeout_per_app <= 0:
        raise ValueError("IDA inventory timeout values must be positive")
    if max_retries < 0:
        raise ValueError("IDA inventory retry count must be zero or greater")
    if max_instructions_per_function <= 0:
        raise ValueError("max_instructions_per_function must be positive")

    started = time.monotonic()
    output_dir = ensure_dir(output_dir)
    installation = ida_installation_info(install_dir)
    if not installation.get("available"):
        result = {
            "schema_version": IDA_BACKEND_SCHEMA,
            "status": "tool_missing",
            "job_mode": "inventory_only",
            "installation": installation,
            "library_summaries": [],
            "message": installation.get("reason"),
        }
        safe_write_json(output_dir / "ida_inventory_summary.json", result)
        return result

    unique_records: list[tuple[dict[str, Any], Path, str]] = []
    duplicate_records: list[dict[str, Any]] = []
    seen_hashes: dict[str, str] = {}
    invalid_records: list[dict[str, Any]] = []
    for record in library_records:
        path = _library_record_path(record)
        if path is None or not path.is_file():
            invalid_records.append(
                {
                    "library": str(path) if path else None,
                    "status": "failed",
                    "error": "library_not_found",
                }
            )
            continue
        actual_hash = str(record.get("sha256") or "") or sha256_file(path)
        previous = seen_hashes.get(actual_hash)
        if previous is not None:
            duplicate_records.append(
                {
                    "library": str(path),
                    "library_sha256": actual_hash,
                    "status": "content_duplicate_skipped",
                    "canonical_library": previous,
                }
            )
            continue
        seen_hashes[actual_hash] = str(path)
        unique_records.append((record, path, actual_hash))

    worker = Path(__file__).with_name("ida_worker.py")
    executable = str(python_executable or sys.executable)
    resolved_install = Path(str(installation["install_dir"]))
    summaries: list[dict[str, Any]] = []
    status = "completed"
    reused_library_count = 0
    executed_library_count = 0

    def finalize(run_status: str) -> dict[str, Any]:
        processed = len(summaries)
        if processed < len(unique_records) and run_status == "completed":
            run_status = "partial"
        result = {
            "schema_version": IDA_BACKEND_SCHEMA,
            "status": run_status,
            "job_mode": "inventory_only",
            "tool": "ida",
            "backend": "idalib_disassembly_inventory",
            "installation": installation,
            "input_library_count": len(library_records),
            "unique_library_count": len(unique_records),
            "duplicate_library_count": len(duplicate_records),
            "invalid_library_count": len(invalid_records),
            # Kept for schema compatibility: this is the number of jobs resolved
            # by either a valid checkpoint or a worker invocation.
            "attempted_library_count": processed,
            "executed_library_count": executed_library_count,
            "reused_library_count": reused_library_count,
            "completed_library_count": sum(
                1 for row in summaries if row.get("status") == "completed"
            ),
            "indexed_function_count": sum(
                int(row.get("inventory_function_count") or 0)
                for row in summaries
            ),
            "library_summaries": summaries,
            "duplicates": duplicate_records,
            "invalid_records": invalid_records,
            "budget": {
                "timeout_per_library": timeout_per_library,
                "timeout_per_app": timeout_per_app,
                "max_retries": max_retries,
                "max_instructions_per_function": (
                    max_instructions_per_function
                ),
                "worker_count": 1,
            },
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        safe_write_json(output_dir / "ida_inventory_summary.json", result)
        return result

    try:
        for index, (record, library_path, library_hash) in enumerate(
            unique_records,
            start=1,
        ):
            job = {
                "schema_version": IDA_JOB_SCHEMA,
                "job_mode": "inventory_only",
                "inventory_detail": "fingerprint",
                "library": str(library_path),
                "library_sha256": library_hash,
                "abi": record.get("abi"),
                "ownership": record.get("ownership") or {},
                "seed_targets": [],
                "max_targets": 1,
                "callgraph_depth": 0,
                "max_inventory_instructions_per_function": (
                    max_instructions_per_function
                ),
            }
            job["job_hash"] = _canonical_hash(job)
            job_dir, _ = _prepare_job_directory(
                output_dir,
                library_path,
                library_hash,
                job,
            )
            inventory_path = job_dir / "inventory.jsonl"
            checkpoint = _valid_inventory_checkpoint(
                job_dir,
                job_hash=str(job["job_hash"]),
                library_sha256=library_hash,
            )
            if checkpoint is not None:
                reused_library_count += 1
                summary = {
                    **checkpoint,
                    "library": str(library_path),
                    "library_sha256": library_hash,
                    "abi": record.get("abi"),
                    "ownership": record.get("ownership") or {},
                    "returncode": 0,
                    "attempts": 0,
                    "cache_status": "reused",
                    "inventory_path": str(inventory_path),
                    "error": None,
                }
                summaries.append(summary)
                _emit(
                    progress_callback,
                    {
                        "event": "ida_inventory_library_reused",
                        "index": index,
                        "total": len(unique_records),
                        "library": str(library_path),
                        "function_count": int(
                            summary.get("inventory_function_count") or 0
                        ),
                    },
                )
                continue

            app_remaining = timeout_per_app - (time.monotonic() - started)
            if app_remaining <= 0:
                status = "app_timeout"
                break
            executed_library_count += 1
            job_path = job_dir / "job.json"
            library_timeout = min(
                max(1, int(app_remaining)), timeout_per_library
            )
            _emit(
                progress_callback,
                {
                    "event": "ida_inventory_library_start",
                    "index": index,
                    "total": len(unique_records),
                    "library": str(library_path),
                    "timeout": library_timeout,
                },
            )
            returncode: int | None = None
            final_error: str | None = None
            attempts = 0
            for attempt in range(max_retries + 1):
                attempts = attempt + 1
                app_remaining = timeout_per_app - (time.monotonic() - started)
                if app_remaining <= 0:
                    final_error = "app_timeout_before_inventory_retry"
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
                        returncode,
                        _stdout,
                        stderr,
                        timeout_error,
                        _timed_out_function,
                    ) = _run_worker_with_heartbeat(
                        command,
                        environment=environment,
                        timeout=min(
                            library_timeout,
                            max(1, int(app_remaining)),
                        ),
                        timeout_per_function=library_timeout + 1,
                        job_dir=job_dir,
                        progress_callback=progress_callback,
                        library=str(library_path),
                        index=index,
                        total=len(unique_records),
                        attempt=attempts,
                        job_hash=str(job["job_hash"]),
                    )
                    final_error = timeout_error or (
                        stderr[-4000:]
                        if returncode not in {0, None}
                        else None
                    )
                if returncode == 0:
                    break

            worker_summary = _read_json(job_dir / "summary.json")
            completed = (
                returncode == 0
                and worker_summary.get("status") == "completed"
                and inventory_path.is_file()
            )
            if not completed:
                status = "partial"
            summary = {
                **worker_summary,
                "library": str(library_path),
                "library_sha256": library_hash,
                "abi": record.get("abi"),
                "ownership": record.get("ownership") or {},
                "returncode": returncode,
                "attempts": attempts,
                "cache_status": "executed",
                "inventory_path": (
                    str(inventory_path) if inventory_path.is_file() else None
                ),
                "error": worker_summary.get("error") or final_error,
            }
            summaries.append(summary)
            _emit(
                progress_callback,
                {
                    "event": "ida_inventory_library_finish",
                    "index": index,
                    "total": len(unique_records),
                    "library": str(library_path),
                    "status": summary.get("status") or "failed",
                    "function_count": int(
                        summary.get("inventory_function_count") or 0
                    ),
                    "error": summary.get("error"),
                },
            )
    except KeyboardInterrupt:
        finalize("interrupted")
        raise

    return finalize(status)
