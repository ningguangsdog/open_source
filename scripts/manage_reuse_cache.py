#!/usr/bin/env python3
"""Inspect and bound a dedicated reuse-search cache directory."""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any


MARKER = ".apk_pipeline_reuse_cache"


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _tree_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def _entry(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path),
        "name": path.name,
        "size_bytes": _tree_size(path),
        "modified_epoch": stat.st_mtime,
    }


def _plan(cache_dir: Path, max_bytes: int) -> dict[str, Any]:
    entries = [
        _entry(path)
        for path in cache_dir.iterdir()
        if path.name != MARKER and not path.is_symlink()
    ]
    entries.sort(key=lambda row: (float(row["modified_epoch"]), row["name"]))
    total = sum(int(row["size_bytes"]) for row in entries)
    remaining = total
    removals: list[dict[str, Any]] = []
    for row in entries:
        if remaining <= max_bytes:
            break
        removals.append(row)
        remaining -= int(row["size_bytes"])
    return {
        "schema_version": "2026-08-24.reuse-cache-plan.v1",
        "cache_dir": str(cache_dir),
        "max_bytes": max_bytes,
        "total_bytes": total,
        "projected_bytes": max(0, remaining),
        "entry_count": len(entries),
        "removal_count": len(removals),
        "removals": removals,
        "generated_at_epoch": time.time(),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Preview or apply an oldest-first size limit to a dedicated "
            "reuse-search cache. Dry-run is the default."
        )
    )
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--max-gb", type=positive_float, required=True)
    parser.add_argument(
        "--initialize",
        action="store_true",
        help="Create the cache directory and its safety marker.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the printed removal plan. Requires the safety marker.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Optional path for the JSON plan and outcome manifest.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cache_dir = args.cache_dir.expanduser().resolve()
    if args.initialize:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / MARKER).touch(exist_ok=True)
    if not cache_dir.is_dir():
        raise SystemExit(f"Cache directory does not exist: {cache_dir}")
    marker = cache_dir / MARKER
    if args.apply and not marker.is_file():
        raise SystemExit(
            f"Refusing to delete without safety marker {marker}. "
            "Run once with --initialize."
        )

    plan = _plan(cache_dir, int(args.max_gb * 1024**3))
    plan["mode"] = "apply" if args.apply else "dry_run"
    removed: list[str] = []
    if args.apply:
        for row in plan["removals"]:
            path = Path(str(row["path"])).resolve()
            if path.parent != cache_dir or path.name == MARKER or path.is_symlink():
                raise SystemExit(f"Unsafe cache entry in removal plan: {path}")
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
            removed.append(str(path))
    plan["removed"] = removed
    plan["removed_count"] = len(removed)
    rendered = json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True)
    print(rendered)
    if args.manifest:
        manifest = args.manifest.expanduser().resolve()
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
