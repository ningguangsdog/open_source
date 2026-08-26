"""Post-run quality gate for automated extraction and IDA evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .models import PhaseResult
from .utils import safe_write_json, sha256_file


VALIDATION_SCHEMA = "2026-08-25.pipeline-validation.v10"
REUSE_EVIDENCE_UNIT_LIMIT = 5000


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_jsonl(
    path: Path,
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file() or (limit is not None and limit <= 0):
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except Exception:
                continue
            if isinstance(value, dict):
                rows.append(value)
                if limit is not None and len(rows) >= max(0, limit):
                    break
    return rows


def _reuse_review_source(workspace: Path) -> Path:
    review_path = workspace / "phase3_native" / "reuse_candidates_review.jsonl"
    if review_path.is_file():
        return review_path
    return workspace / "phase3_native" / "reuse_candidates.jsonl"


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


def _readiness_fields(
    status: str,
    checks: list[dict[str, Any]],
    *,
    reuse_required: bool,
) -> dict[str, Any]:
    check_status = {str(row.get("id")): str(row.get("status")) for row in checks}
    deep_status = check_status.get("post_ida_deep_comparison")
    canonical_status = check_status.get("canonical_implementation_resolution")
    pipeline_execution_complete = check_status.get("phase_execution") == "passed"
    evidence_check_ids = {
        "phase3_ida_evidence",
        "ida_evidence_identity",
        "phase5_ida_integration",
        "phase5_reuse_candidate_integration",
        "phase5_deep_comparison_integration",
        "phase5_reuse_traceability",
    }
    evidence_complete = bool(
        pipeline_execution_complete
        and all(
            check_status.get(check_id) in {None, "passed", "not_applicable"}
            for check_id in evidence_check_ids
        )
    )
    retrieval_validated = bool(
        status == "passed"
        and reuse_required
        and deep_status in {"passed", "not_applicable"}
        and canonical_status in {"passed", "not_applicable"}
    )
    reuse_ready = bool(
        retrieval_validated and evidence_complete
    )
    return {
        "pipeline_execution_complete": pipeline_execution_complete,
        "evidence_complete": evidence_complete,
        "retrieval_validated": retrieval_validated,
        "known_positive_regression_status": "not_run_in_pipeline",
        "ready_for_similarity": status == "passed" and evidence_complete,
        "ready_for_usage_analysis": reuse_ready,
        "ready_for_adaptation_analysis": reuse_ready,
        "ready_for_copying_review": reuse_ready,
        # Backward-compatible field: readiness to review evidence, never a
        # statement that copying was established.
        "ready_for_copying_assessment": reuse_ready,
        "copying_conclusion_supported": False,
    }


def _reuse_search_checks(
    workspace: Path,
    *,
    native_library_count: int,
    require_evidence_packet: bool,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    method_summary = _load_json(
        workspace / "phase2_jadx" / "java_method_index_summary.json"
    )
    dex_method_summary = _load_json(
        workspace / "phase2_jadx" / "dex_method_index_summary.json"
    )
    full_summary = _load_json(
        workspace / "phase3_native" / "native_full_index_summary.json"
    )
    retrieval_summary = _load_json(
        workspace / "phase3_native" / "reuse_candidate_summary.json"
    )
    selection_summary = _load_json(
        workspace
        / "phase3_native"
        / "reuse_candidate_selection_summary.json"
    )
    deep_summary = _load_json(
        workspace / "phase3_native" / "reuse_deep_comparison_summary.json"
    )
    if not isinstance(method_summary, dict):
        method_summary = {}
    if not isinstance(dex_method_summary, dict):
        dex_method_summary = {}
    if not isinstance(full_summary, dict):
        full_summary = {}
    if not isinstance(retrieval_summary, dict):
        retrieval_summary = {}
    if not isinstance(selection_summary, dict):
        selection_summary = retrieval_summary.get("candidate_selection") or {}
    if not isinstance(selection_summary, dict):
        selection_summary = {}
    if not isinstance(deep_summary, dict):
        deep_summary = {}

    method_status = str(method_summary.get("status") or "missing")
    method_count = _safe_int(method_summary.get("indexed_method_count"))
    checks.append(
        _check(
            "java_method_index",
            "passed" if method_status == "completed" else "failed",
            "The complete JADX output was indexed at method level."
            if method_status == "completed"
            else "The Java/Kotlin method index is missing or incomplete.",
            details={
                "status": method_status,
                "indexed_method_count": method_count,
                "source_file_count": _safe_int(
                    method_summary.get("source_file_count")
                ),
                "read_error_count": _safe_int(
                    method_summary.get("read_error_count")
                ),
            },
            blocking=method_status != "completed",
        )
    )

    dex_method_status = str(dex_method_summary.get("status") or "missing")
    dex_method_count = _safe_int(dex_method_summary.get("indexed_method_count"))
    dex_method_ok = dex_method_status == "completed"
    checks.append(
        _check(
            "dex_method_index",
            "passed" if dex_method_ok else "failed",
            (
                "DEX methods were indexed directly from Dalvik bytecode."
                if dex_method_ok
                else "The direct DEX method index is missing or incomplete."
            ),
            details={
                "status": dex_method_status,
                "dex_file_count": _safe_int(
                    dex_method_summary.get("dex_file_count")
                ),
                "declared_method_count": _safe_int(
                    dex_method_summary.get("declared_method_count")
                ),
                "indexed_method_count": dex_method_count,
                "code_bearing_method_count": _safe_int(
                    dex_method_summary.get("code_bearing_method_count")
                ),
                "error_count": _safe_int(dex_method_summary.get("error_count")),
            },
            blocking=not dex_method_ok,
        )
    )

    full_status = str(full_summary.get("status") or "missing")
    native_function_count = _safe_int(full_summary.get("indexed_function_count"))
    full_ok = full_status == "completed" and (
        native_library_count == 0 or native_function_count > 0
    )
    checks.append(
        _check(
            "native_full_lightweight_index",
            "passed" if full_ok else "failed" if full_status == "missing" else "partial",
            "All content-unique native libraries completed lightweight function indexing."
            if full_ok
            else "The native lightweight function index is missing or incomplete.",
            details={
                "status": full_status,
                "native_library_count": native_library_count,
                "unique_library_count": _safe_int(
                    full_summary.get("unique_library_count")
                ),
                "indexed_library_hash_count": _safe_int(
                    full_summary.get("indexed_library_hash_count")
                ),
                "indexed_function_count": native_function_count,
                "callgraph_edge_count": _safe_int(
                    full_summary.get("callgraph_edge_count")
                ),
                "invalid_row_count": _safe_int(
                    full_summary.get("invalid_row_count")
                ),
            },
            blocking=full_status == "missing",
        )
    )

    retrieval_status = str(retrieval_summary.get("status") or "missing")
    commercial_count = _safe_int(
        retrieval_summary.get("commercial_function_count")
    )
    source_count = _safe_int(retrieval_summary.get("source_function_count"))
    candidate_pair_count = _safe_int(
        retrieval_summary.get("candidate_pair_count")
    )
    retrieval_ok = (
        retrieval_status == "completed"
        and commercial_count > 0
        and source_count > 0
    )
    retrieval_blocking = retrieval_status == "missing" or source_count == 0
    checks.append(
        _check(
            "open_source_candidate_retrieval",
            "passed" if retrieval_ok else "failed" if retrieval_blocking else "partial",
            (
                "Commercial function indexes were searched against the configured "
                "open-source corpus."
                if retrieval_ok
                else "Open-source candidate retrieval did not complete with usable inputs."
            ),
            details={
                "status": retrieval_status,
                "commercial_function_count": commercial_count,
                "eligible_commercial_function_count": _safe_int(
                    retrieval_summary.get("eligible_commercial_function_count")
                ),
                "searchable_commercial_function_count": _safe_int(
                    retrieval_summary.get("searchable_commercial_function_count")
                ),
                "skipped_commercial_ownership_counts": (
                    retrieval_summary.get("skipped_commercial_ownership_counts")
                    or {}
                ),
                "source_function_count": source_count,
                "candidate_pair_count": candidate_pair_count,
                "review_candidate_count": _safe_int(
                    retrieval_summary.get("review_candidate_count")
                ),
                "review_candidate_limit": _safe_int(
                    retrieval_summary.get("review_candidate_limit")
                ),
                "source_project_count": _safe_int(
                    retrieval_summary.get("source_project_count")
                ),
                "representation_relation_counts": (
                    retrieval_summary.get("representation_relation_counts")
                    or {}
                ),
                "commercial_native_projection": (
                    retrieval_summary.get("commercial_native_projection")
                    or {}
                ),
                "dex_included_in_retrieval": retrieval_summary.get(
                    "dex_included_in_retrieval"
                ),
                "commercial_function_with_candidate_count": _safe_int(
                    retrieval_summary.get(
                        "commercial_function_with_candidate_count"
                    )
                ),
                "interpretation": (
                    "Zero candidates is a valid negative retrieval result. Retrieval "
                    "scores are review priorities, not copying probabilities."
                ),
            },
            blocking=retrieval_blocking,
        )
    )

    selection_status = str(selection_summary.get("status") or "missing")
    native_deep_eligible_count = _safe_int(
        selection_summary.get("native_deep_eligible_count")
    )
    selected_native_count = _safe_int(
        selection_summary.get("native_decompile_target_count")
    )
    selection_starved = bool(selection_summary.get("selection_starved")) or (
        native_deep_eligible_count > 0 and selected_native_count == 0
    )
    selection_required = candidate_pair_count > 0
    selection_ok = (
        not selection_required
        or (selection_status == "completed" and not selection_starved)
    )
    checks.append(
        _check(
            "reuse_candidate_cohort_selection",
            "passed" if selection_ok else "partial",
            (
                "Retrieval candidates were retained in representation-aware usage, "
                "adaptation, and control cohorts."
                if selection_ok and selection_required
                else "No retrieval candidate required cohort selection."
                if not selection_required
                else "Candidate cohort selection is missing or native candidates were starved."
            ),
            details={
                "status": selection_status,
                "candidate_lane_counts": selection_summary.get(
                    "candidate_lane_counts"
                )
                or {},
                "review_bucket_counts": selection_summary.get(
                    "review_bucket_counts"
                )
                or {},
                "native_deep_eligible_counts": selection_summary.get(
                    "native_deep_eligible_counts"
                )
                or {},
                "native_deep_eligible_count": native_deep_eligible_count,
                "selected_native_candidate_count": selected_native_count,
                "selected_native_lane_counts": selection_summary.get(
                    "native_decompile_target_lane_counts"
                )
                or {},
                "selection_starved": selection_starved,
            },
            blocking=False,
        )
    )

    authoritative_targets = _load_json(
        workspace / "phase3_native" / "reuse_candidate_targets.json"
    )
    authoritative_rows = (
        [
            row
            for row in authoritative_targets.get("targets") or []
            if isinstance(row, dict)
        ]
        if isinstance(authoritative_targets, dict)
        else []
    )
    missing_pair_ids: list[int] = []
    invalid_lanes: list[dict[str, Any]] = []
    incomplete_metadata: list[dict[str, Any]] = []
    for index, target in enumerate(authoritative_rows):
        candidate = target.get("reuse_candidate") or {}
        commercial = candidate.get("commercial") or {}
        source = candidate.get("source") or {}
        pair_id = str(
            target.get("candidate_pair_id")
            or candidate.get("candidate_pair_id")
            or ""
        )
        lane = str(
            target.get("analysis_lane")
            or candidate.get("analysis_lane")
            or ""
        )
        if not pair_id:
            missing_pair_ids.append(index)
        if lane not in {"usage", "adaptation", "control"}:
            invalid_lanes.append({"index": index, "analysis_lane": lane or None})
        required = {
            "commercial_function_id": target.get("commercial_function_id")
            or candidate.get("commercial_function_id")
            or commercial.get("function_id"),
            "library_sha256": target.get("library_sha256")
            or commercial.get("library_sha256"),
            "address": target.get("address") or commercial.get("address"),
            "source_function_id": target.get("source_function_id")
            or candidate.get("source_function_id")
            or source.get("function_id"),
            "source_project": candidate.get("source_project")
            or source.get("repository_full_name")
            or source.get("corpus_id"),
        }
        missing_fields = sorted(key for key, value in required.items() if not value)
        if missing_fields:
            incomplete_metadata.append(
                {
                    "index": index,
                    "candidate_pair_id": pair_id or None,
                    "missing_fields": missing_fields,
                }
            )
    targets_required = selected_native_count > 0
    target_identity_ok = bool(
        not targets_required
        or (
            isinstance(authoritative_targets, dict)
            and len(authoritative_rows) == selected_native_count
            and not missing_pair_ids
            and not invalid_lanes
            and not incomplete_metadata
        )
    )
    checks.append(
        _check(
            "reuse_candidate_target_identity",
            "passed"
            if target_identity_ok and targets_required
            else "not_applicable"
            if not targets_required
            else "failed",
            (
                "Selected reuse candidates retain authoritative pair, lane, and source identities."
                if target_identity_ok and targets_required
                else "No native reuse candidate required an authoritative target record."
                if not targets_required
                else "Selected reuse-candidate identity metadata is missing or inconsistent."
            ),
            details={
                "expected_target_count": selected_native_count,
                "authoritative_target_count": len(authoritative_rows),
                "missing_candidate_pair_id_indexes": missing_pair_ids,
                "invalid_analysis_lanes": invalid_lanes,
                "incomplete_metadata": incomplete_metadata[:100],
            },
            blocking=targets_required and not target_identity_ok,
        )
    )

    targets = _load_json(workspace / "phase3_native" / "native_targets.json")
    candidate_target_count = (
        _safe_int(targets.get("reuse_candidate_target_count"))
        if isinstance(targets, dict)
        else 0
    )
    native_units_value = _load_json(
        workspace / "phase3_native" / "native_evidence_units.json"
    )
    native_units = (
        [row for row in native_units_value if isinstance(row, dict)]
        if isinstance(native_units_value, list)
        else []
    )
    candidate_units = [
        row for row in native_units if row.get("target_kind") == "reuse_candidate"
    ]
    candidate_success_count = sum(
        row.get("decompiler_success") is True for row in candidate_units
    )
    if candidate_target_count == 0 and native_deep_eligible_count > 0:
        follow_status = "partial"
        follow_message = (
            "Native candidates were eligible for deep comparison but none reached "
            "the Hex-Rays target queue."
        )
    elif candidate_target_count == 0:
        follow_status = "passed"
        follow_message = (
            "No native retrieval candidate required Hex-Rays follow-up in this run."
        )
    elif candidate_units and candidate_success_count > 0:
        follow_status = "passed"
        follow_message = (
            "Retrieved native candidates reached targeted Hex-Rays decompilation."
        )
    else:
        follow_status = "partial"
        follow_message = (
            "Native retrieval candidates were selected but produced no successful "
            "deep-decompilation evidence."
        )
    checks.append(
        _check(
            "reuse_candidate_deep_follow_through",
            follow_status,
            follow_message,
            details={
                "selected_candidate_target_count": candidate_target_count,
                "candidate_evidence_unit_count": len(candidate_units),
                "successful_candidate_decompilation_count": (
                    candidate_success_count
                ),
                "native_deep_eligible_count": native_deep_eligible_count,
                "selection_starved": selection_starved,
            },
            blocking=False,
        )
    )

    deep_status = str(deep_summary.get("status") or "missing")
    deep_family_count = _safe_int(
        deep_summary.get("source_family_comparison_count")
    )
    deep_metadata_ok = bool(
        deep_summary.get("metadata_integrity_status") == "passed"
        and _safe_int(deep_summary.get("null_candidate_pair_id_count")) == 0
        and _safe_int(deep_summary.get("incomplete_source_metadata_count")) == 0
        and _safe_int(deep_summary.get("incomplete_commercial_metadata_count"))
        == 0
        and not (deep_summary.get("missing_seed_pair_ids") or [])
        and not (deep_summary.get("lane_mismatch_pair_ids") or [])
    )
    canonical_seed_count = _safe_int(deep_summary.get("canonical_seed_count"))
    wrapper_seed_count = _safe_int(deep_summary.get("wrapper_seed_count"))
    resolved_wrapper_count = _safe_int(
        deep_summary.get("resolved_wrapper_seed_count")
    )
    unresolved_wrapper_count = _safe_int(
        deep_summary.get("unresolved_wrapper_seed_count")
    )
    claim_eligible_wrapper_count = _safe_int(
        deep_summary.get("claim_eligible_wrapper_seed_count")
    )
    unresolved_claim_eligible_wrapper_count = _safe_int(
        deep_summary.get("unresolved_claim_eligible_wrapper_seed_count")
    )
    if candidate_target_count == 0:
        canonical_status = "not_applicable"
        canonical_message = "No selected native seed required canonical resolution."
    elif canonical_seed_count == 0:
        canonical_status = "failed"
        canonical_message = (
            "Selected native seeds were not mapped to comparison implementations."
        )
    else:
        canonical_status = "passed"
        if unresolved_claim_eligible_wrapper_count:
            canonical_message = (
                "All selected seeds retain provenance and a comparison body; unresolved "
                "wrapper seeds remain explicitly reported as a coverage boundary."
            )
        else:
            canonical_message = (
                "Selected seeds retain provenance and are bound to canonical comparison bodies."
            )
    checks.append(
        _check(
            "canonical_implementation_resolution",
            canonical_status,
            canonical_message,
            details={
                "canonical_mapping_path": deep_summary.get(
                    "canonical_mapping_path"
                ),
                "canonical_seed_count": canonical_seed_count,
                "canonical_resolution_count": _safe_int(
                    deep_summary.get("canonical_resolution_count")
                ),
                "wrapper_seed_count": wrapper_seed_count,
                "resolved_wrapper_seed_count": resolved_wrapper_count,
                "unresolved_wrapper_seed_count": unresolved_wrapper_count,
                "claim_eligible_wrapper_seed_count": claim_eligible_wrapper_count,
                "unresolved_claim_eligible_wrapper_seed_count": (
                    unresolved_claim_eligible_wrapper_count
                ),
                "suppressed_unresolved_claim_lane_wrapper_seed_count": _safe_int(
                    deep_summary.get(
                        "suppressed_unresolved_claim_lane_wrapper_seed_count"
                    )
                ),
                "coverage_boundary": (
                    "An unresolved wrapper remains comparable only at its saved wrapper "
                    "body. It cannot support a substantive implementation claim without "
                    "additional reached-body evidence."
                ),
                "source_family_expansion_candidate_count": _safe_int(
                    deep_summary.get("source_family_expansion_candidate_count")
                ),
            },
            blocking=candidate_target_count > 0 and canonical_seed_count == 0,
        )
    )
    if candidate_target_count == 0:
        deep_check_status = "not_applicable"
        deep_message = "No selected native candidate required post-IDA comparison."
    elif deep_status == "completed" and deep_family_count > 0 and deep_metadata_ok:
        deep_check_status = "passed"
        deep_message = (
            "IDA pseudocode was reranked against candidate source families."
        )
    else:
        deep_check_status = "partial"
        deep_message = (
            "Selected native candidates did not produce a complete post-IDA "
            "source-family comparison."
        )
    checks.append(
        _check(
            "post_ida_deep_comparison",
            deep_check_status,
            deep_message,
            details={
                "status": deep_status,
                "selected_candidate_target_count": candidate_target_count,
                "successful_candidate_seed_result_count": _safe_int(
                    deep_summary.get("successful_candidate_seed_result_count")
                ),
                "comparison_pair_count": _safe_int(
                    deep_summary.get("comparison_pair_count")
                ),
                "source_family_comparison_count": deep_family_count,
                "collapsed_duplicate_source_count": _safe_int(
                    deep_summary.get("collapsed_duplicate_source_count")
                ),
                "usage_review_ready_count": _safe_int(
                    deep_summary.get("usage_review_ready_count")
                ),
                "adaptation_review_ready_count": _safe_int(
                    deep_summary.get("adaptation_review_ready_count")
                ),
                "metadata_integrity_status": deep_summary.get(
                    "metadata_integrity_status"
                ),
                "selected_seed_pair_id_count": _safe_int(
                    deep_summary.get("selected_seed_pair_id_count")
                ),
                "compared_seed_pair_id_count": _safe_int(
                    deep_summary.get("compared_seed_pair_id_count")
                ),
                "missing_seed_pair_ids": deep_summary.get(
                    "missing_seed_pair_ids"
                )
                or [],
                "lane_mismatch_pair_ids": deep_summary.get(
                    "lane_mismatch_pair_ids"
                )
                or [],
                "null_candidate_pair_id_count": _safe_int(
                    deep_summary.get("null_candidate_pair_id_count")
                ),
                "incomplete_source_metadata_count": _safe_int(
                    deep_summary.get("incomplete_source_metadata_count")
                ),
                "incomplete_commercial_metadata_count": _safe_int(
                    deep_summary.get("incomplete_commercial_metadata_count")
                ),
                "copying_conclusion_supported": False,
                "canonical_seed_count": canonical_seed_count,
                "canonical_resolution_count": _safe_int(
                    deep_summary.get("canonical_resolution_count")
                ),
                "source_family_expansion_candidate_count": _safe_int(
                    deep_summary.get("source_family_expansion_candidate_count")
                ),
            },
            blocking=candidate_target_count > 0 and not deep_metadata_ok,
        )
    )

    if require_evidence_packet:
        phase5_units = _load_jsonl(
            workspace / "phase5_evidence" / "evidence_units.jsonl"
        )
        phase5_candidate_count = sum(
            row.get("kind") == "open_source_retrieval_candidate"
            for row in phase5_units
        )
        phase5_deep_count = sum(
            row.get("kind") == "open_source_deep_comparison"
            for row in phase5_units
        )
        review_source = _reuse_review_source(workspace)
        review_candidate_count = len(
            _load_jsonl(review_source, limit=REUSE_EVIDENCE_UNIT_LIMIT)
        )
        expected_count = min(
            review_candidate_count,
            REUSE_EVIDENCE_UNIT_LIMIT,
        )
        phase5_ok = phase5_candidate_count == expected_count
        checks.append(
            _check(
                "phase5_reuse_candidate_integration",
                "passed" if phase5_ok else "failed",
                (
                    "The bounded reuse-candidate audit trail reached Phase 5."
                    if phase5_ok
                    else "Reuse-candidate evidence is missing from the Phase 5 audit trail."
                ),
                details={
                    "candidate_pair_count": candidate_pair_count,
                    "review_candidate_count": review_candidate_count,
                    "review_candidate_path": str(review_source),
                    "expected_phase5_candidate_count": expected_count,
                    "phase5_candidate_count": phase5_candidate_count,
                    "evidence_unit_limit": REUSE_EVIDENCE_UNIT_LIMIT,
                },
                blocking=not phase5_ok,
            )
        )
        expected_deep_count = min(
            deep_family_count,
            REUSE_EVIDENCE_UNIT_LIMIT,
        )
        phase5_deep_ok = phase5_deep_count == expected_deep_count
        checks.append(
            _check(
                "phase5_deep_comparison_integration",
                "passed" if phase5_deep_ok else "failed",
                (
                    "Post-IDA source-family comparisons reached Phase 5."
                    if phase5_deep_ok
                    else "Post-IDA comparison evidence is missing from Phase 5."
                ),
                details={
                    "expected_phase5_deep_comparison_count": expected_deep_count,
                    "phase5_deep_comparison_count": phase5_deep_count,
                },
                blocking=not phase5_deep_ok,
            )
        )
        traceability_violations: list[dict[str, Any]] = []
        for row in phase5_units:
            if row.get("kind") != "open_source_deep_comparison":
                continue
            trace = row.get("traceability") or {}
            commercial = row.get("commercial_function") or {}
            source = row.get("open_source_function") or {}
            missing_fields: list[str] = []
            if not row.get("candidate_pair_id"):
                missing_fields.append("candidate_pair_id")
            if row.get("analysis_lane") not in {"usage", "adaptation", "control"}:
                missing_fields.append("analysis_lane")
            if not commercial.get("function_id"):
                missing_fields.append("commercial_function_id")
            if not source.get("function_id"):
                missing_fields.append("source_function_id")
            if not trace.get("deep_comparison_id"):
                missing_fields.append("deep_comparison_id")
            if not trace.get("ida_pseudocode_available"):
                missing_fields.append("ida_pseudocode_available")
            if not trace.get("canonical_implementation_available"):
                missing_fields.append("canonical_implementation_available")
            if missing_fields:
                traceability_violations.append(
                    {
                        "unit_id": row.get("unit_id"),
                        "missing_or_invalid_fields": missing_fields,
                    }
                )
        phase5_trace_ok = not traceability_violations
        checks.append(
            _check(
                "phase5_reuse_traceability",
                "passed" if phase5_trace_ok else "failed",
                (
                    "Phase 5 preserves retrieval, IDA, pseudocode, comparison, and claim-review identities."
                    if phase5_trace_ok
                    else "Phase 5 contains reuse evidence with an incomplete provenance chain."
                ),
                details={
                    "deep_comparison_unit_count": phase5_deep_count,
                    "traceability_violations": traceability_violations[:100],
                },
                blocking=not phase5_trace_ok,
            )
        )
    return checks


def build_pipeline_validation(
    workspace: Path,
    phases: list[PhaseResult],
    *,
    expect_automated_ida: bool,
    require_evidence_packet: bool,
    expect_reuse_search: bool = False,
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
            **_readiness_fields(
                "failed",
                checks,
                reuse_required=expect_reuse_search,
            ),
            "automated_ida_required": True,
            "reuse_search_required": expect_reuse_search,
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
            **_readiness_fields(
                status,
                checks,
                reuse_required=expect_reuse_search,
            ),
            "automated_ida_required": False,
            "reuse_search_required": expect_reuse_search,
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
        if expect_reuse_search:
            checks.extend(
                _reuse_search_checks(
                    workspace,
                    native_library_count=0,
                    require_evidence_packet=require_evidence_packet,
                )
            )
        blocking_failures = [
            item
            for item in checks
            if item["blocking"] and item["status"] == "failed"
        ]
        incomplete = [item for item in checks if item["status"] == "partial"]
        status = (
            "failed"
            if failed_phases or blocking_failures
            else "partial"
            if partial_phases or incomplete
            else "passed"
        )
        return {
            "schema_version": VALIDATION_SCHEMA,
            "status": status,
            **_readiness_fields(
                status,
                checks,
                reuse_required=expect_reuse_search,
            ),
            "automated_ida_required": True,
            "automated_ida_applicable": False,
            "reuse_search_required": expect_reuse_search,
            "checks": checks,
        }

    reuse_candidate_target_count = 0
    if expect_reuse_search:
        reuse_targets = _load_json(
            workspace / "phase3_native" / "native_targets.json"
        )
        if isinstance(reuse_targets, dict):
            reuse_candidate_target_count = _safe_int(
                reuse_targets.get("reuse_candidate_target_count")
            )
        reuse_selection = _load_json(
            workspace
            / "phase3_native"
            / "reuse_candidate_selection_summary.json"
        )
        if not isinstance(reuse_selection, dict):
            reuse_summary = _load_json(
                workspace / "phase3_native" / "reuse_candidate_summary.json"
            )
            reuse_selection = (
                reuse_summary.get("candidate_selection")
                if isinstance(reuse_summary, dict)
                else {}
            )
        if not isinstance(reuse_selection, dict):
            reuse_selection = {}
    else:
        reuse_selection = {}
    if expect_reuse_search and reuse_candidate_target_count == 0:
        native_deep_eligible_count = _safe_int(
            reuse_selection.get("native_deep_eligible_count")
        )
        selection_starved = bool(reuse_selection.get("selection_starved")) or (
            native_deep_eligible_count > 0
        )
        checks.append(
            _check(
                "automated_ida",
                "partial" if selection_starved else "not_applicable",
                (
                    "Native open-source candidates were eligible, but none reached "
                    "candidate-driven Hex-Rays decompilation."
                    if selection_starved
                    else "No native open-source retrieval candidate was selected, so "
                    "candidate-driven Hex-Rays decompilation was not required."
                ),
                details={
                    "configured": True,
                    "selected_native_reuse_candidate_count": 0,
                    "native_deep_eligible_count": native_deep_eligible_count,
                    "selection_starved": selection_starved,
                },
            )
        )
        checks.extend(
            _reuse_search_checks(
                workspace,
                native_library_count=len(native_libraries),
                require_evidence_packet=require_evidence_packet,
            )
        )
        blocking_failures = [
            item
            for item in checks
            if item["blocking"] and item["status"] == "failed"
        ]
        incomplete = [item for item in checks if item["status"] == "partial"]
        status = (
            "failed"
            if failed_phases or blocking_failures
            else "partial"
            if partial_phases or incomplete
            else "passed"
        )
        return {
            "schema_version": VALIDATION_SCHEMA,
            "status": status,
            **_readiness_fields(
                status,
                checks,
                reuse_required=True,
            ),
            "automated_ida_required": selection_starved,
            "automated_ida_applicable": True,
            "reuse_search_required": True,
            "summary": {
                "successful_ida_functions": 0,
                "phase3_ida_evidence_units": 0,
                "blocking_failure_count": len(blocking_failures),
                "partial_check_count": len(incomplete),
            },
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
                "selected_function_count": _safe_int(
                    ida_summary.get("selected_target_count")
                ),
                "attempted_function_count": _safe_int(
                    ida_summary.get("attempted_targets")
                ),
                "unattempted_function_count": _safe_int(
                    ida_summary.get("unattempted_target_count")
                ),
            },
            blocking=backend_status in {"missing", "tool_missing"},
        )
    )
    requested_seeds = _safe_int(ida_summary.get("requested_seed_count"))
    resolved_seeds = _safe_int(ida_summary.get("resolved_seed_count"))
    selected_seeds = _safe_int(ida_summary.get("selected_seed_count"))
    unresolved_seeds = _safe_int(ida_summary.get("unresolved_seed_count"))
    unselected_resolved_seeds = _safe_int(
        ida_summary.get("unselected_resolved_seed_count")
    )
    seed_coverage_available = "requested_seed_count" in ida_summary
    seed_coverage_ok = bool(
        seed_coverage_available
        and unselected_resolved_seeds == 0
        and unresolved_seeds == 0
        and selected_seeds == requested_seeds
    )
    checks.append(
        _check(
            "ida_candidate_seed_coverage",
            "passed" if seed_coverage_ok else "partial",
            (
                "Every upstream-selected native candidate seed reached the IDA queue."
                if seed_coverage_ok
                else "One or more selected native candidate seeds were unresolved or not queued."
            ),
            details={
                "telemetry_available": seed_coverage_available,
                "requested_seed_count": requested_seeds,
                "resolved_seed_count": resolved_seeds,
                "selected_seed_count": selected_seeds,
                "unresolved_seed_count": unresolved_seeds,
                "unselected_resolved_seed_count": unselected_resolved_seeds,
                "selection_source_counts": ida_summary.get(
                    "selection_source_counts"
                )
                or {},
            },
            blocking=False,
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
        phase5_ida_units = [
            row
            for row in phase5_units
            if row.get("evidence_source") == "automated_ida"
        ]
        phase5_success_ids = {
            str(row.get("unit_id"))
            for row in phase5_ida_units
            if row.get("decompiler_success") is True
        }
        missing_from_phase5 = [
            str(unit.get("unit_id"))
            for unit in ida_units
            if str(unit.get("unit_id")) not in phase5_success_ids
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
                    "phase5_successful_ida_unit_count": len(
                        phase5_success_ids
                    ),
                    "phase5_failed_ida_audit_unit_count": sum(
                        row.get("decompiler_success") is False
                        for row in phase5_ida_units
                    ),
                    "phase5_automated_ida_audit_unit_count": len(
                        phase5_ida_units
                    ),
                    "missing_unit_ids": missing_from_phase5,
                },
                blocking=not phase5_ok,
            )
        )

    if expect_reuse_search:
        checks.extend(
            _reuse_search_checks(
                workspace,
                native_library_count=len(native_libraries),
                require_evidence_packet=require_evidence_packet,
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
        **_readiness_fields(
            status,
            checks,
            reuse_required=expect_reuse_search,
        ),
        "automated_ida_required": True,
        "automated_ida_applicable": True,
        "reuse_search_required": expect_reuse_search,
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
    expect_reuse_search: bool = False,
) -> dict[str, Any]:
    payload = build_pipeline_validation(
        workspace,
        phases,
        expect_automated_ida=expect_automated_ida,
        require_evidence_packet=require_evidence_packet,
        expect_reuse_search=expect_reuse_search,
    )
    path = workspace / "pipeline_validation.json"
    payload["path"] = str(path)
    safe_write_json(path, payload)
    return payload
