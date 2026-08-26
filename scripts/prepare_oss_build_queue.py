#!/usr/bin/env python3
"""Create a bounded, auditable build queue from reuse candidates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apk_pipeline.evidence import write_jsonl
from apk_pipeline.oss_build_queue import build_oss_build_queue
from apk_pipeline.reuse_candidate_retrieval import iter_jsonl
from apk_pipeline.utils import safe_write_json


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return list(iter_jsonl(path))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rank frozen OSS snapshots for reviewed, reproducible native builds. "
            "This command detects build surfaces but does not execute repository code."
        )
    )
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--snapshot-manifest", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=15)
    args = parser.parse_args()

    candidate_path = args.candidates.expanduser().resolve()
    snapshot_manifest = args.snapshot_manifest.expanduser().resolve()
    snapshot_root = args.snapshot_root.expanduser().resolve()
    output_path = args.output.expanduser().resolve()
    if not candidate_path.is_file():
        raise FileNotFoundError(f"Candidate file not found: {candidate_path}")
    if not snapshot_manifest.is_file():
        raise FileNotFoundError(
            f"Snapshot manifest not found: {snapshot_manifest}"
        )
    if not snapshot_root.is_dir():
        raise NotADirectoryError(f"Snapshot root not found: {snapshot_root}")

    summary, rows = build_oss_build_queue(
        _read_jsonl(candidate_path),
        _read_jsonl(snapshot_manifest),
        snapshot_root=snapshot_root,
        limit=args.limit,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_path, rows)
    summary_path = output_path.with_suffix(".summary.json")
    summary.update(
        {
            "candidate_path": str(candidate_path),
            "snapshot_manifest": str(snapshot_manifest),
            "snapshot_root": str(snapshot_root),
            "output_path": str(output_path),
        }
    )
    safe_write_json(summary_path, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
