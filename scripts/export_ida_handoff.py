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

from apk_pipeline.ida_integration import export_ida_handoff


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a bounded, portable IDA Classroom handoff ZIP."
    )
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--max-libraries", type=int, default=12)
    args = parser.parse_args()
    if args.max_libraries < 1:
        parser.error("--max-libraries must be positive")
    workspace = args.workspace.expanduser().resolve()
    manifest_path = workspace / "phase3_native" / "ida_target_manifest.json"
    if not manifest_path.is_file():
        parser.error(f"IDA target manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    summary = export_ida_handoff(
        workspace,
        manifest,
        max_libraries=args.max_libraries,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
