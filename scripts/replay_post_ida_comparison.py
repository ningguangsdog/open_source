#!/usr/bin/env python3
"""Replay post-IDA comparison and optionally rebuild final evidence packets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apk_pipeline.post_ida_reanalysis import replay_post_ida_analysis


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute source-family comparisons from saved IDA results without "
            "rerunning APK extraction, JADX, native indexing, retrieval, or IDA."
        )
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        required=True,
        help="Existing isolated APK workspace containing phase3_native.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Independent staging directory (default: WORKSPACE/reanalysis/post_ida).",
    )
    parser.add_argument(
        "--oss-function-index",
        type=Path,
        help="Override the source function index stored in run_context.json.",
    )
    parser.add_argument(
        "--oss-binary-function-index",
        type=Path,
        help="Optional compiled-source index override.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "After integrity checks pass, promote the new comparison artifacts and "
            "rerun Phase 5 plus pipeline validation."
        ),
    )
    args = parser.parse_args()
    result = replay_post_ida_analysis(
        args.workspace,
        output_dir=args.output_dir,
        apply=args.apply,
        oss_function_index=args.oss_function_index,
        oss_binary_function_index=args.oss_binary_function_index,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
