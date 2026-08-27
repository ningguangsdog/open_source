"""External-label regression checks for open-source candidate retrieval."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Iterable

from .reuse_candidate_retrieval import iter_jsonl
from .utils import safe_write_json


REGRESSION_SCHEMA = "2026-08-26.reuse-retrieval-regression.v2"


def load_regression_labels(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Regression label file must contain one JSON object")
    for group in ("known_positives", "negative_controls"):
        rows = payload.get(group) or []
        if not isinstance(rows, list):
            raise ValueError(f"{group} must be a JSON list")
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ValueError(f"{group}[{index}] must be a JSON object")
            missing = [
                key
                for key in ("id", "commercial_pattern", "source_pattern")
                if not row.get(key)
            ]
            if missing:
                raise ValueError(
                    f"{group}[{index}] is missing: {', '.join(missing)}"
                )
            re.compile(str(row["commercial_pattern"]))
            re.compile(str(row["source_pattern"]))
    if not payload.get("known_positives"):
        raise ValueError(
            "Regression label file must contain at least one known positive"
        )
    return payload


def _search_text(value: Any) -> str:
    return json.dumps(value or {}, ensure_ascii=False, sort_keys=True)


def _evaluate_label(
    label: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    commercial_pattern = re.compile(
        str(label["commercial_pattern"]), re.IGNORECASE
    )
    source_pattern = re.compile(str(label["source_pattern"]), re.IGNORECASE)
    matches = [
        row
        for row in candidates
        if commercial_pattern.search(_search_text(row.get("commercial")))
        and source_pattern.search(_search_text(row.get("source")))
    ]
    matches.sort(
        key=lambda row: (
            int(row.get("rank") or 10**9),
            -float(row.get("retrieval_score") or 0),
        )
    )
    best = matches[0] if matches else None
    return {
        "id": str(label["id"]),
        "retrieved": bool(best),
        "match_count": len(matches),
        "best_rank": int(best.get("rank") or 0) if best else None,
        "best_score": float(best.get("retrieval_score") or 0) if best else None,
        "best_commercial": best.get("commercial") if best else None,
        "best_source": best.get("source") if best else None,
    }


def build_regression_report(
    candidates: Iterable[dict[str, Any]],
    labels: dict[str, Any],
) -> dict[str, Any]:
    candidate_rows = list(candidates)
    positives = [
        _evaluate_label(row, candidate_rows)
        for row in labels.get("known_positives") or []
    ]
    controls = [
        _evaluate_label(row, candidate_rows)
        for row in labels.get("negative_controls") or []
    ]
    positive_hits = sum(bool(row["retrieved"]) for row in positives)
    control_hits = sum(bool(row["retrieved"]) for row in controls)
    return {
        "schema_version": REGRESSION_SCHEMA,
        "status": "passed" if positive_hits == len(positives) else "failed",
        "candidate_pair_count": len(candidate_rows),
        "known_positive_count": len(positives),
        "known_positive_hit_count": positive_hits,
        "known_positive_recall": (
            positive_hits / len(positives) if positives else None
        ),
        "negative_control_count": len(controls),
        "negative_control_hit_count": control_hits,
        "negative_control_hit_rate": (
            control_hits / len(controls) if controls else None
        ),
        "known_positives": positives,
        "negative_controls": controls,
        "interpretation": (
            "This report tests retrieval coverage only. A retrieved pair still "
            "requires deep comparison and upstream attribution."
        ),
    }


def run_reuse_regression(
    candidates_path: Path,
    labels_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    if not candidates_path.is_file():
        raise FileNotFoundError(f"Candidate file not found: {candidates_path}")
    if not labels_path.is_file():
        raise FileNotFoundError(f"Regression label file not found: {labels_path}")
    report = build_regression_report(
        iter_jsonl(candidates_path),
        load_regression_labels(labels_path),
    )
    report["labels_path"] = str(labels_path)
    report["candidates_path"] = str(candidates_path)
    safe_write_json(output_path, report)
    return report
