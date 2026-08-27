#!/usr/bin/env python3
"""Evaluate reuse-search retrieval against external positive/control labels."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from apk_pipeline.reuse_regression import (
    build_regression_report,
    load_regression_labels,
)
from apk_pipeline.reuse_candidate_retrieval import iter_jsonl
from apk_pipeline.utils import safe_write_json


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


def main() -> int:
    args = parse_args()
    candidates_path = args.candidates.expanduser().resolve()
    labels_path = args.labels.expanduser().resolve()
    if not candidates_path.is_file():
        raise SystemExit(f"Candidate file not found: {candidates_path}")
    if not labels_path.is_file():
        raise SystemExit(f"Label file not found: {labels_path}")
    try:
        labels = load_regression_labels(labels_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"Invalid label file: {error}") from error
    report = build_regression_report(iter_jsonl(candidates_path), labels)
    if args.output:
        safe_write_json(args.output.expanduser().resolve(), report)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.strict and report["known_positive_hit_count"] < report["known_positive_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
