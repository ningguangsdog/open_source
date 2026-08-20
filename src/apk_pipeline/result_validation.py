"""Post-run quality gate for automated extraction and IDA evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .models import PhaseResult
from .utils import safe_write_json, sha256_file


VALIDATION_SCHEMA = "2026-08-20.pipeline-validation.v1"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
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


def _check(
    check_id: str,
    status: str,
    message: str,
    *,
    details: dict[str, Any] | None = None,
    blocking: bool = False,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": status,
        "blocking": blocking,
        "message": message,
        "details": details or {},
    }


def _phase_status(phases: Iterable[PhaseResult]) -> dict[str, str]:
    return {phase.name: str(phase.status) for phase in phases}


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def build_pipeline_validation(
    workspace: Path,
    phases: list[PhaseResult],
    *,
    expect_automated_ida: bool,
    require_evidence_packet: bool,
) -> dict[str, Any]:
    """Validate that generated native evidence reached the final review layer."""

    workspace = workspace.expanduser().resolve()
    phase_status = _phase_status(phases)
    checks: list[dict[str, Any]] = []
    failed_phases = [
        name for name, status in phase_status.items() if status == "failed"
    ]
    partial_phases = [
        name for name, status in phase_status.items() if status == "partial"
    ]
    checks.append(
        _check(
            "phase_execution",
            "failed" if failed_phases else "partial" if partial_phases else "passed",
            "Pipeline phases completed without a hard failure."
            if not failed_phases
            else "One or more pipeline phases failed.",
            details={
                "phase_status": phase_status,
                "failed_phases": failed_phases,
                "partial_phases": partial_phases,
            },
            blocking=bool(failed_phases),
        )
    )

    native_analysis = _load_json(
        workspace / "phase3_native" / "native_analysis.json"
    )
    if expect_automated_ida and not isinstance(native_analysis, dict):
        checks.append(
            _check(
                "phase3_native_inventory",
                "failed",
                "Phase 3 native inventory is missing or invalid.",
                blocking=True,
            )
        )
        return {
            "schema_version": VALIDATION_SCHEMA,
            "status": "failed",
            "ready_for_similarity": False,
            "automated_ida_required": True,
            "checks": checks,
        }
    native_libraries = (
        native_analysis.get("libraries") or []
        if isinstance(native_analysis, dict)
        else []
    )
    if not expect_automated_ida:
        checks.append(
            _check(
                "automated_ida",
                "not_applicable",
                "Automated IDA was not required by this analysis profile.",
            )
        )
        status = "failed" if failed_phases else "partial" if partial_phases else "passed"
        return {
            "schema_version": VALIDATION_SCHEMA,
            "status": status,
            "ready_for_similarity": status == "passed",
            "automated_ida_required": False,
            "checks": checks,
        }

    if not native_libraries:
        checks.append(
            _check(
                "automated_ida",
                "not_applicable",
                "No native libraries were present, so IDA had no binary input.",
            )
        )
        status = "failed" if failed_phases else "partial" if partial_phases else "passed"
        return {
            "schema_version": VALIDATION_SCHEMA,
            "status": status,
            "ready_for_similarity": status == "passed",
            "automated_ida_required": True,
            "automated_ida_applicable": False,
            "checks": checks,
        }

    ida_summary = _load_json(
        workspace / "phase3_native" / "ida_automated_summary.json"
    )
    if not isinstance(ida_summary, dict):
        ida_summary = {}
    backend_status = str(ida_summary.get("status") or "missing")
    selected_libraries = ida_summary.get("libraries_selected") or {}
    attempted_libraries = _safe_int(ida_summary.get("libraries_attempted"))
    successful = _safe_int(ida_summary.get("successful_decompilations"))
    failed = _safe_int(ida_summary.get("failed_decompilations"))
    backend_ok = backend_status == "completed"
    checks.append(
        _check(
            "ida_backend_completion",
            "passed" if backend_ok else "failed" if backend_status in {"missing", "tool_missing"} else "partial",
            "All scheduled IDA library jobs completed."
            if backend_ok
            else "Automated IDA did not complete all scheduled library jobs.",
            details={
                "backend_status": backend_status,
                "selected_library_count": len(selected_libraries),
                "attempted_library_count": attempted_libraries,
            },
            blocking=backend_status in {"missing", "tool_missing"},
        )
    )
    checks.append(
        _check(
            "ida_pseudocode_yield",
            "passed" if successful > 0 else "failed",
            "IDA produced non-empty pseudocode for at least one selected function."
            if successful > 0
            else "IDA produced no usable pseudocode.",
            details={
                "successful_decompilations": successful,
                "failed_decompilations": failed,
            },
            blocking=successful == 0,
        )
    )

    phase3_units_value = _load_json(
        workspace / "phase3_native" / "native_evidence_units.json"
    )
    phase3_units = (
        [row for row in phase3_units_value if isinstance(row, dict)]
        if isinstance(phase3_units_value, list)
        else []
    )
    ida_units = [
        row
        for row in phase3_units
        if row.get("evidence_source") == "automated_ida"
        and row.get("decompiler_success") is True
    ]
    checks.append(
        _check(
            "phase3_ida_evidence",
            "passed" if ida_units else "failed",
            "Automated IDA functions were materialized as Phase 3 evidence units."
            if ida_units
            else "No successful automated IDA function reached Phase 3 evidence units.",
            details={"automated_ida_evidence_unit_count": len(ida_units)},
            blocking=not ida_units,
        )
    )

    library_hashes = {
        str(record.get("sha256") or "")
        for record in native_libraries
        if isinstance(record, dict) and record.get("sha256")
    }
    identity_violations: list[dict[str, Any]] = []
    missing_pseudocode: list[str] = []
    pseudocode_hash_mismatches: list[str] = []
    for unit in ida_units:
        identity = unit.get("identity_verification") or {}
        library_hash = str(identity.get("library_sha256") or "")
        if not library_hash or library_hash not in library_hashes:
            identity_violations.append(
                {
                    "unit_id": unit.get("unit_id"),
                    "library_sha256": library_hash or None,
                    "reason": "library_hash_not_present_in_phase3_inventory",
                }
            )
        pseudocode_path = Path(str(unit.get("pseudocode_path") or ""))
        if not pseudocode_path.is_file():
            missing_pseudocode.append(str(unit.get("unit_id") or "unknown"))
        else:
            expected_pseudocode_hash = str(unit.get("pseudocode_sha256") or "")
            try:
                hash_matches = (
                    not expected_pseudocode_hash
                    or sha256_file(pseudocode_path) == expected_pseudocode_hash
                )
            except OSError:
                hash_matches = False
            if not hash_matches:
                pseudocode_hash_mismatches.append(
                    str(unit.get("unit_id") or "unknown")
                )
    identity_ok = (
        not identity_violations
        and not missing_pseudocode
        and not pseudocode_hash_mismatches
    )
    checks.append(
        _check(
            "ida_evidence_identity",
            "passed" if identity_ok else "failed",
            "IDA evidence retains a valid library hash and a readable pseudocode artifact."
            if identity_ok
            else "One or more IDA evidence units failed provenance or artifact validation.",
            details={
                "identity_violations": identity_violations,
                "missing_pseudocode_unit_ids": missing_pseudocode,
                "pseudocode_hash_mismatch_unit_ids": pseudocode_hash_mismatches,
            },
            blocking=not identity_ok,
        )
    )

    if require_evidence_packet:
        phase5_units = _load_jsonl(
            workspace / "phase5_evidence" / "evidence_units.jsonl"
        )
        phase5_ids = {
            str(row.get("unit_id"))
            for row in phase5_units
            if row.get("evidence_source") == "automated_ida"
        }
        missing_from_phase5 = [
            str(unit.get("unit_id"))
            for unit in ida_units
            if str(unit.get("unit_id")) not in phase5_ids
        ]
        phase5_ok = bool(ida_units) and not missing_from_phase5
        checks.append(
            _check(
                "phase5_ida_integration",
                "passed" if phase5_ok else "failed",
                "All successful IDA evidence units reached the Phase 5 review packet."
                if phase5_ok
                else "Automated IDA evidence is missing from the Phase 5 review layer.",
                details={
                    "phase5_automated_ida_unit_count": len(phase5_ids),
                    "missing_unit_ids": missing_from_phase5,
                },
                blocking=not phase5_ok,
            )
        )

    blocking_failures = [
        item for item in checks if item["blocking"] and item["status"] == "failed"
    ]
    incomplete = [
        item for item in checks if item["status"] == "partial"
    ]
    if blocking_failures:
        status = "failed"
    elif incomplete or partial_phases:
        status = "partial"
    else:
        status = "passed"
    return {
        "schema_version": VALIDATION_SCHEMA,
        "status": status,
        "ready_for_similarity": status == "passed",
        "automated_ida_required": True,
        "automated_ida_applicable": True,
        "summary": {
            "successful_ida_functions": successful,
            "phase3_ida_evidence_units": len(ida_units),
            "blocking_failure_count": len(blocking_failures),
            "partial_check_count": len(incomplete),
        },
        "checks": checks,
    }


def write_pipeline_validation(
    workspace: Path,
    phases: list[PhaseResult],
    *,
    expect_automated_ida: bool,
    require_evidence_packet: bool,
) -> dict[str, Any]:
    payload = build_pipeline_validation(
        workspace,
        phases,
        expect_automated_ida=expect_automated_ida,
        require_evidence_packet=require_evidence_packet,
    )
    path = workspace / "pipeline_validation.json"
    payload["path"] = str(path)
    safe_write_json(path, payload)
    return payload
