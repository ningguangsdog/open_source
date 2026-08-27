#!/usr/bin/env python3
"""Evaluate frozen APK workspaces before changing reuse-selection rules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from apk_pipeline.reuse_release_gate import run_release_gate


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument(
        "--workspace",
        action="append",
        default=[],
        metavar="CASE_ID=PATH",
        help="Map one frozen contract case to its completed pipeline workspace.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reuse_release_gate_report.json"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspaces: dict[str, Path] = {}
    for value in args.workspace:
        if "=" not in value:
            raise SystemExit("--workspace must use CASE_ID=PATH")
        case_id, raw_path = value.split("=", 1)
        workspaces[case_id] = Path(raw_path).expanduser().resolve()
    report = run_release_gate(
        args.contract.expanduser().resolve(),
        workspaces,
        args.output.expanduser().resolve(),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
