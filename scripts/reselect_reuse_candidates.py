#!/usr/bin/env python3
"""Replay cohort and native-target selection from an existing retrieval stream."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from apk_pipeline.evidence import write_jsonl
from apk_pipeline.reuse_candidate_retrieval import (
    iter_jsonl,
    native_decompile_targets,
    select_candidate_cohorts,
)
from apk_pipeline.utils import safe_write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild stratified review cohorts and native IDA targets without "
            "rerunning APK extraction, JADX, IDA inventory, or OSS retrieval."
        )
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        required=True,
        help="Pipeline run workspace or its phase3_native directory.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "Output directory. Defaults to phase3_native/reselection so canonical "
            "pipeline artifacts are not overwritten."
        ),
    )
    parser.add_argument("--review-limit", type=int, default=5000)
    parser.add_argument("--native-target-limit", type=int, default=140)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace = args.workspace.expanduser().resolve()
    phase3 = workspace if workspace.name == "phase3_native" else workspace / "phase3_native"
    candidates_path = phase3 / "reuse_candidates.jsonl"
    if not candidates_path.is_file():
        raise FileNotFoundError(f"Retrieval stream not found: {candidates_path}")
    output_dir = (
        args.output_dir.expanduser().resolve()
        if args.output_dir
        else phase3 / "reselection"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    selection, review, native_pool = select_candidate_cohorts(
        iter_jsonl(candidates_path),
        review_limit=args.review_limit,
        native_decompile_limit=args.native_target_limit,
    )
    targets = native_decompile_targets(
        native_pool,
        limit=args.native_target_limit,
    )
    target_lane_counts = Counter(
        str(target.get("analysis_lane") or "unknown") for target in targets
    )
    selection.update(
        {
            "source_candidate_path": str(candidates_path),
            "native_decompile_target_count": len(targets),
            "native_decompile_target_lane_counts": dict(
                sorted(target_lane_counts.items())
            ),
            "selection_starved": bool(
                selection.get("native_deep_eligible_count", 0) and not targets
            ),
        }
    )

    review_path = output_dir / "reuse_candidates_review.jsonl"
    summary_path = output_dir / "reuse_candidate_selection_summary.json"
    targets_path = output_dir / "reuse_candidate_targets.json"
    write_jsonl(review_path, review)
    safe_write_json(summary_path, selection)
    safe_write_json(
        targets_path,
        {
            "schema_version": selection["schema_version"],
            "target_count": len(targets),
            "target_lane_counts": dict(sorted(target_lane_counts.items())),
            "targets": targets,
        },
    )
    print(
        json.dumps(
            {
                "status": "completed",
                "selection_summary": selection,
                "review_path": str(review_path),
                "targets_path": str(targets_path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
