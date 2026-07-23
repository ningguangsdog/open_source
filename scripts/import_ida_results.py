#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from apk_pipeline.ida_integration import import_manual_ida_results
from apk_pipeline.logging_utils import configure_logging
from apk_pipeline.phase5_evidence import run_phase5_evidence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate manual IDA Classroom pseudocode against a completed APK "
            "pipeline workspace."
        )
    )
    parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Existing APK pipeline workspace.",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        help=(
            "Directory containing IDA result metadata. Defaults to "
            "<workspace>/phase3_native/manual_ida/results."
        ),
    )
    parser.add_argument(
        "--refresh-phase5",
        action="store_true",
        help="Regenerate Phase 5 packets after a successful or partial import.",
    )
    parser.add_argument("--log-level", default="INFO", help="Python logging level.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)
    try:
        summary = import_manual_ida_results(
            args.workspace.expanduser().resolve(),
            results_dir=(
                args.results_dir.expanduser().resolve()
                if args.results_dir
                else None
            ),
        )
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"IDA import error: {exc}", file=sys.stderr)
        return 2

    if args.refresh_phase5 and summary.get("status") in {"success", "partial"}:
        workspace = args.workspace.expanduser().resolve()
        phase5 = run_phase5_evidence(
            workspace,
            force=True,
            require_resources=(
                workspace
                / "phase4_resources"
                / "resource_inventory.json"
            ).is_file(),
        )
        summary["phase5_refresh"] = {
            "status": phase5.status,
            "success": phase5.success,
            "warnings": phase5.warnings,
        }

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if summary.get("status") == "no_results":
        return 1
    if summary.get("status") == "failed":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
