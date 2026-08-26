#!/usr/bin/env python3
"""Evaluate reuse-search retrieval against external positive/control labels."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from apk_pipeline.reuse_candidate_retrieval import iter_jsonl
from apk_pipeline.utils import safe_write_json


EVALUATION_SCHEMA = "2026-08-24.reuse-retrieval-evaluation.v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure candidate-retrieval recall using an external JSON label file."
        )
    )
    parser.add_argument(
        "--candidates",
        type=Path,
        required=True,
        help="Path to phase3_native/reuse_candidates.jsonl.",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        required=True,
        help=(
            "JSON object with known_positives and optional negative_controls. "
            "Each row requires id, commercial_pattern, and source_pattern."
        ),
    )
    parser.add_argument("--output", type=Path, help="Optional JSON report path.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit nonzero when any known positive is not retrieved.",
    )
    return parser.parse_args()


def _load_labels(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Label file must contain one JSON object")
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


def build_report(
    candidates: list[dict[str, Any]],
    labels: dict[str, Any],
) -> dict[str, Any]:
    positives = [
        _evaluate_label(row, candidates)
        for row in labels.get("known_positives") or []
    ]
    controls = [
        _evaluate_label(row, candidates)
        for row in labels.get("negative_controls") or []
    ]
    positive_hits = sum(row["retrieved"] for row in positives)
    control_hits = sum(row["retrieved"] for row in controls)
    return {
        "schema_version": EVALUATION_SCHEMA,
        "candidate_pair_count": len(candidates),
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
            "This report evaluates retrieval coverage only. A retrieved pair still "
            "requires deep representation-aware comparison and third-party attribution."
        ),
    }


def main() -> int:
    args = parse_args()
    candidates_path = args.candidates.expanduser().resolve()
    labels_path = args.labels.expanduser().resolve()
    if not candidates_path.is_file():
        raise SystemExit(f"Candidate file not found: {candidates_path}")
    if not labels_path.is_file():
        raise SystemExit(f"Label file not found: {labels_path}")
    try:
        labels = _load_labels(labels_path)
    except (OSError, ValueError, json.JSONDecodeError, re.error) as error:
        raise SystemExit(f"Invalid label file: {error}") from error
    report = build_report(list(iter_jsonl(candidates_path)), labels)
    if args.output:
        safe_write_json(args.output.expanduser().resolve(), report)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.strict and report["known_positive_hit_count"] < report["known_positive_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
