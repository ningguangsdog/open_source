"""Replay post-IDA comparison and final evidence assembly from saved artifacts."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any

from .deep_candidate_comparison import compare_decompiled_candidates
from .models import PhaseResult
from .phase5_evidence import run_phase5_evidence
from .result_validation import write_pipeline_validation
from .utils import ensure_dir, safe_write_json


REANALYSIS_SCHEMA = "2026-08-25.post-ida-reanalysis.v1"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _phase_results(summary: dict[str, Any]) -> list[PhaseResult]:
    results: list[PhaseResult] = []
    for row in summary.get("phases") or []:
        if not isinstance(row, dict):
            continue
        results.append(
            PhaseResult(
                name=str(row.get("phase") or "unknown_phase"),
                success=bool(row.get("success")),
                status=str(row.get("status") or "failed"),
                output_paths=[Path(str(path)) for path in row.get("output_paths") or []],
                details=row.get("details") or {},
                error=row.get("error"),
                warnings=[str(value) for value in row.get("warnings") or []],
            )
        )
    return results


def _candidate_target_payload(workspace: Path) -> dict[str, Any]:
    phase3 = workspace / "phase3_native"
    existing = _load_json(phase3 / "reuse_candidate_targets.json")
    if existing.get("targets"):
        return existing
    native_targets = _load_json(phase3 / "native_targets.json")
    targets = [
        row
        for row in native_targets.get("targets") or []
        if isinstance(row, dict) and row.get("kind") == "reuse_candidate"
    ]
    lane_counts: dict[str, int] = {}
    for target in targets:
        lane = str(
            target.get("analysis_lane")
            or (target.get("reuse_candidate") or {}).get("analysis_lane")
            or "unknown"
        )
        lane_counts[lane] = lane_counts.get(lane, 0) + 1
    return {
        "schema_version": "2026-08-25.reuse-candidate-targets.v1",
        "status": "completed",
        "target_count": len(targets),
        "analysis_lane_counts": dict(sorted(lane_counts.items())),
        "targets": targets,
        "recovered_from": str(phase3 / "native_targets.json"),
        "identity_contract": (
            "candidate_pair_id, analysis_lane, commercial/source identities, and "
            "selection evidence are authoritative for downstream comparison."
        ),
    }


def _replace_phase_result(
    phases: list[PhaseResult],
    replacement: PhaseResult,
) -> list[PhaseResult]:
    output: list[PhaseResult] = []
    replaced = False
    for phase in phases:
        if phase.name == replacement.name:
            output.append(replacement)
            replaced = True
        else:
            output.append(phase)
    if not replaced:
        output.append(replacement)
    return output


def replay_post_ida_analysis(
    workspace: Path,
    *,
    output_dir: Path | None = None,
    apply: bool = False,
    oss_function_index: Path | None = None,
    oss_binary_function_index: Path | None = None,
) -> dict[str, Any]:
    """Recompute deep comparisons; optionally promote them and rebuild Phase 5."""

    workspace = workspace.expanduser().resolve()
    phase3 = workspace / "phase3_native"
    if not phase3.is_dir():
        raise FileNotFoundError(f"Phase 3 directory not found: {phase3}")
    run_context = _load_json(workspace / "run_context.json")
    config = run_context.get("config") or {}
    if oss_function_index is None and config.get("oss_function_index"):
        oss_function_index = Path(str(config["oss_function_index"]))
    if oss_binary_function_index is None and config.get(
        "oss_binary_function_index"
    ):
        oss_binary_function_index = Path(str(config["oss_binary_function_index"]))
    source_indexes = [
        path.expanduser().resolve()
        for path in (oss_function_index, oss_binary_function_index)
        if path is not None
    ]
    missing_source_indexes = [str(path) for path in source_indexes if not path.is_file()]
    if missing_source_indexes:
        raise FileNotFoundError(
            "Open-source function index not found: "
            + ", ".join(missing_source_indexes)
        )
    if not source_indexes:
        raise ValueError(
            "No open-source function index was configured in run_context.json."
        )

    decompile_result = _load_json(phase3 / "ida_automated_summary.json")
    if not decompile_result.get("results"):
        decompile_result = _load_json(phase3 / "native_decompilation.json")
    if not decompile_result.get("results"):
        raise ValueError("No saved IDA result rows are available for reanalysis.")
    review_candidates = phase3 / "reuse_candidates_review.jsonl"
    if not review_candidates.is_file():
        raise FileNotFoundError(
            f"Review-candidate stream not found: {review_candidates}"
        )

    staging = ensure_dir(
        (output_dir or (workspace / "reanalysis" / "post_ida"))
        .expanduser()
        .resolve()
    )
    staged_comparisons = staging / "reuse_deep_comparisons.jsonl"
    staged_summary = staging / "reuse_deep_comparison_summary.json"
    staged_canonical = staging / "reuse_canonical_implementations.jsonl"
    staged_targets = staging / "reuse_candidate_targets.json"
    target_payload = _candidate_target_payload(workspace)
    safe_write_json(staged_targets, target_payload)
    comparison_summary = compare_decompiled_candidates(
        decompile_result,
        review_candidates,
        source_indexes,
        staged_comparisons,
        staged_summary,
        canonical_mapping_path=staged_canonical,
    )
    integrity_ok = comparison_summary.get("metadata_integrity_status") == "passed"
    report: dict[str, Any] = {
        "schema_version": REANALYSIS_SCHEMA,
        "status": "completed" if integrity_ok else "failed",
        "workspace": str(workspace),
        "staging_directory": str(staging),
        "applied": False,
        "source_indexes": [str(path) for path in source_indexes],
        "candidate_target_count": int(target_payload.get("target_count") or 0),
        "comparison_summary": comparison_summary,
    }
    if not integrity_ok:
        safe_write_json(staging / "reanalysis_summary.json", report)
        raise RuntimeError(
            "Post-IDA comparison failed metadata-integrity validation; canonical "
            "Phase 3/5 artifacts were not changed."
        )

    if apply:
        canonical_comparisons = phase3 / "reuse_deep_comparisons.jsonl"
        canonical_summary = phase3 / "reuse_deep_comparison_summary.json"
        canonical_mapping = phase3 / "reuse_canonical_implementations.jsonl"
        canonical_targets = phase3 / "reuse_candidate_targets.json"
        shutil.copy2(staged_comparisons, canonical_comparisons)
        shutil.copy2(staged_summary, canonical_summary)
        shutil.copy2(staged_canonical, canonical_mapping)
        shutil.copy2(staged_targets, canonical_targets)

        pipeline_summary_path = workspace / "pipeline_summary.json"
        pipeline_summary = _load_json(pipeline_summary_path)
        phases = _phase_results(pipeline_summary)
        phase5 = run_phase5_evidence(
            workspace,
            force=True,
            run_context=run_context,
            upstream_results=[
                phase for phase in phases if phase.name != "phase5_evidence"
            ],
            require_resources=bool(config.get("resource_scan", True)),
        )
        phases = _replace_phase_result(phases, phase5)
        validation = write_pipeline_validation(
            workspace,
            phases,
            expect_automated_ida=True,
            require_evidence_packet=bool(config.get("emit_evidence_packets", True)),
            expect_reuse_search=True,
        )
        if pipeline_summary:
            pipeline_summary["phases"] = [phase.to_dict() for phase in phases]
            pipeline_summary["validation"] = validation
            pipeline_summary["all_success"] = bool(
                validation.get("status") == "passed"
                and all(
                    phase.status in {"success", "skipped"} for phase in phases
                )
            )
            pipeline_summary["has_partial"] = any(
                phase.status == "partial" for phase in phases
            )
            pipeline_summary["has_failed"] = any(
                phase.status == "failed" for phase in phases
            )
            safe_write_json(pipeline_summary_path, pipeline_summary)
        report["applied"] = True
        report["phase5_status"] = phase5.status
        report["validation_status"] = validation.get("status")
        report["pipeline_validation_path"] = str(
            workspace / "pipeline_validation.json"
        )

    safe_write_json(staging / "reanalysis_summary.json", report)
    return report
