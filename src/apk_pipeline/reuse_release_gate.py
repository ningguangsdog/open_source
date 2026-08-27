"""Cross-APK release gate for frozen reuse-research workspaces."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Callable, Iterable

from .reuse_candidate_retrieval import iter_jsonl
from .utils import safe_write_json


RELEASE_GATE_SCHEMA = "2026-08-26.reuse-release-gate.v1"


def load_release_contract(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Release contract must contain one JSON object")
    cases = payload.get("cases") or []
    if not isinstance(cases, list) or not cases:
        raise ValueError("Release contract must contain at least one case")
    case_ids: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or not case.get("id"):
            raise ValueError(f"cases[{index}] must contain an id")
        case_id = str(case["id"])
        if case_id in case_ids:
            raise ValueError(f"Duplicate release case id: {case_id}")
        case_ids.add(case_id)
        for field in (
            "required_source_patterns",
            "required_native_component_patterns",
            "forbidden_managed_commercial_patterns",
            "forbidden_managed_method_patterns",
        ):
            values = case.get(field) or []
            if not isinstance(values, list):
                raise ValueError(f"cases[{index}].{field} must be a JSON list")
            for value in values:
                re.compile(str(value))
    return payload


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _pattern_check(
    check_id: str,
    patterns: Iterable[str],
    texts: Iterable[str],
    *,
    require_match: bool,
) -> dict[str, Any]:
    text_rows = list(texts)
    results = []
    for raw_pattern in patterns:
        pattern = re.compile(str(raw_pattern), re.IGNORECASE)
        match_count = sum(bool(pattern.search(text)) for text in text_rows)
        results.append(
            {
                "pattern": str(raw_pattern),
                "match_count": match_count,
                "passed": match_count > 0 if require_match else match_count == 0,
            }
        )
    passed = all(row["passed"] for row in results)
    return {
        "id": check_id,
        "status": "passed" if passed else "failed",
        "details": results,
    }


def _jsonl_pattern_checks(
    path: Path,
    specifications: Iterable[
        tuple[
            str,
            Iterable[str],
            bool,
            Callable[[dict[str, Any]], str],
        ]
    ],
) -> tuple[list[dict[str, Any]], int]:
    prepared = []
    for check_id, patterns, require_match, text_builder in specifications:
        prepared.append(
            {
                "id": check_id,
                "patterns": [
                    (str(pattern), re.compile(str(pattern), re.IGNORECASE))
                    for pattern in patterns
                ],
                "require_match": require_match,
                "text_builder": text_builder,
                "counts": [],
            }
        )
        prepared[-1]["counts"] = [0] * len(prepared[-1]["patterns"])

    row_count = 0
    for row in iter_jsonl(path):
        row_count += 1
        for specification in prepared:
            text = specification["text_builder"](row)
            for index, (_, pattern) in enumerate(specification["patterns"]):
                if pattern.search(text):
                    specification["counts"][index] += 1

    checks = []
    for specification in prepared:
        details = []
        require_match = bool(specification["require_match"])
        for (raw_pattern, _), match_count in zip(
            specification["patterns"],
            specification["counts"],
        ):
            details.append(
                {
                    "pattern": raw_pattern,
                    "match_count": match_count,
                    "passed": (
                        match_count > 0 if require_match else match_count == 0
                    ),
                }
            )
        passed = all(row["passed"] for row in details)
        checks.append(
            {
                "id": specification["id"],
                "status": "passed" if passed else "failed",
                "details": details,
            }
        )
    return checks, row_count


def _native_component_texts(payload: Any) -> list[str]:
    texts = [json.dumps(payload, ensure_ascii=False, sort_keys=True)]

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            vendor = str(value.get("vendor") or "").strip()
            component = str(value.get("component") or "").strip()
            if vendor or component:
                texts.append(" ".join(part for part in (vendor, component) if part))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(payload)
    return texts


def evaluate_release_case(
    workspace: Path,
    case: dict[str, Any],
) -> dict[str, Any]:
    validation = _load_json(workspace / "pipeline_validation.json")
    phase3 = workspace / "phase3_native"
    candidate_checks, candidate_pair_count = _jsonl_pattern_checks(
        phase3 / "reuse_candidates.jsonl",
        [
            (
                "required_source_patterns",
                case.get("required_source_patterns") or [],
                True,
                lambda row: json.dumps(
                    row.get("source") or {},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
        ],
    )
    native_analysis = _load_json(phase3 / "native_analysis.json")
    managed_checks, managed_deep_comparison_count = _jsonl_pattern_checks(
        phase3 / "managed_reuse_deep_comparisons.jsonl",
        [
            (
                "forbidden_managed_commercial_patterns",
                case.get("forbidden_managed_commercial_patterns") or [],
                False,
                lambda row: json.dumps(
                    row.get("commercial") or {},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            ),
            (
                "forbidden_managed_method_patterns",
                case.get("forbidden_managed_method_patterns") or [],
                False,
                lambda row: str(
                    (row.get("commercial") or {}).get("name") or ""
                ),
            ),
        ],
    )

    checks: list[dict[str, Any]] = []
    expected_validation = str(case.get("validation_status") or "passed")
    actual_validation = str(validation.get("status") or "missing")
    checks.append(
        {
            "id": "pipeline_validation_status",
            "status": (
                "passed" if actual_validation == expected_validation else "failed"
            ),
            "details": {
                "expected": expected_validation,
                "actual": actual_validation,
            },
        }
    )
    checks.extend(candidate_checks)
    checks.append(
        _pattern_check(
            "required_native_component_patterns",
            case.get("required_native_component_patterns") or [],
            _native_component_texts(native_analysis),
            require_match=True,
        )
    )
    checks.extend(managed_checks)

    maximum_ida = case.get("max_successful_ida_functions")
    if maximum_ida is not None:
        actual_ida = int(
            (validation.get("summary") or {}).get("successful_ida_functions") or 0
        )
        checks.append(
            {
                "id": "successful_ida_function_budget",
                "status": "passed" if actual_ida <= int(maximum_ida) else "failed",
                "details": {
                    "maximum": int(maximum_ida),
                    "actual": actual_ida,
                },
            }
        )

    expected_copying = case.get("copying_conclusion_supported")
    if expected_copying is not None:
        actual_copying = bool(validation.get("copying_conclusion_supported"))
        checks.append(
            {
                "id": "copying_conclusion_boundary",
                "status": (
                    "passed"
                    if actual_copying == bool(expected_copying)
                    else "failed"
                ),
                "details": {
                    "expected": bool(expected_copying),
                    "actual": actual_copying,
                },
            }
        )

    failed_checks = [row["id"] for row in checks if row["status"] != "passed"]
    return {
        "id": str(case["id"]),
        "workspace": str(workspace),
        "status": "passed" if not failed_checks else "failed",
        "failed_checks": failed_checks,
        "checks": checks,
        "candidate_pair_count": candidate_pair_count,
        "managed_deep_comparison_count": managed_deep_comparison_count,
    }


def build_release_gate_report(
    contract: dict[str, Any],
    workspaces: dict[str, Path],
) -> dict[str, Any]:
    case_results = []
    for case in contract.get("cases") or []:
        case_id = str(case["id"])
        workspace = workspaces.get(case_id)
        if workspace is None:
            case_results.append(
                {
                    "id": case_id,
                    "workspace": None,
                    "status": "failed",
                    "failed_checks": ["workspace_mapping"],
                    "checks": [],
                }
            )
            continue
        case_results.append(evaluate_release_case(workspace, case))
    failed_case_ids = [
        row["id"] for row in case_results if row.get("status") != "passed"
    ]
    return {
        "schema_version": RELEASE_GATE_SCHEMA,
        "status": "passed" if not failed_case_ids else "failed",
        "case_count": len(case_results),
        "passed_case_count": len(case_results) - len(failed_case_ids),
        "failed_case_ids": failed_case_ids,
        "cases": case_results,
        "freeze_policy": (
            "After all frozen cases pass, production selection rules change only "
            "for a hard failure, loss of a known positive, or a documented false "
            "positive reproduced by a frozen case."
        ),
    }


def run_release_gate(
    contract_path: Path,
    workspaces: dict[str, Path],
    output_path: Path,
) -> dict[str, Any]:
    report = build_release_gate_report(
        load_release_contract(contract_path),
        workspaces,
    )
    report["contract_path"] = str(contract_path)
    safe_write_json(output_path, report)
    return report
