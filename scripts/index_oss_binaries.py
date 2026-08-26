#!/usr/bin/env python3
"""Index already-built OSS candidate binaries with IDA inventory-only mode."""

from __future__ import annotations

import argparse
from itertools import chain
import json
from pathlib import Path
import sys
from typing import Any
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apk_pipeline.ida_backend import run_ida_inventory
from apk_pipeline.evidence import write_jsonl
from apk_pipeline.oss_binary_index import (
    extract_apk_native_artifacts,
    materialize_oss_binary_index,
    materialize_oss_dex_index,
)
from apk_pipeline.reuse_candidate_retrieval import iter_jsonl
from apk_pipeline.utils import ensure_dir, safe_write_json, sha256_file


def _read_manifest(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="ignore").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid JSON at {path}:{line_number}: {error}") from error
        if not isinstance(row, dict):
            raise ValueError(f"Manifest row {line_number} must be an object")
        binary = Path(str(row.get("binary_path") or "")).expanduser().resolve()
        if not binary.is_file():
            raise FileNotFoundError(f"OSS binary not found: {binary}")
        if not row.get("repository_full_name") or not row.get("commit_sha"):
            raise ValueError(
                f"Manifest row {line_number} requires repository_full_name and commit_sha"
            )
        rows.append(
            {
                **row,
                "binary_path": str(binary),
                "sha256": sha256_file(binary),
                "extracted_path": str(binary),
                "ownership": {
                    "category": "first_party",
                    "confidence": 1.0,
                    "reason": "Fixed upstream-candidate build manifest.",
                },
            }
        )
    if not rows:
        raise ValueError("OSS binary manifest is empty")
    return rows


def _is_dex_archive(path: Path) -> bool:
    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            return any(
                info.filename.lower().endswith(".dex")
                for info in archive.infolist()
            )
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create a unified function index from prebuilt OSS candidate binaries. "
            "Compilation is intentionally separate because build recipes are project-specific."
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--ida-install-dir", type=Path)
    parser.add_argument("--ida-python-executable", type=Path)
    parser.add_argument("--timeout-per-binary", type=int, default=1200)
    parser.add_argument("--timeout-total", type=int, default=14_400)
    parser.add_argument("--max-instructions", type=int, default=512)
    args = parser.parse_args()

    manifest_path = args.manifest.expanduser().resolve()
    output_dir = ensure_dir(args.output_dir.expanduser().resolve())
    manifest_rows = _read_manifest(manifest_path)
    dex_rows = [
        row for row in manifest_rows if _is_dex_archive(Path(row["binary_path"]))
    ]
    standalone_native_rows = [row for row in manifest_rows if row not in dex_rows]
    apk_native_rows = extract_apk_native_artifacts(
        dex_rows,
        output_dir / "apk_native_artifacts",
    )
    native_rows = [*standalone_native_rows, *apk_native_rows]
    ida_jobs_dir = ensure_dir(output_dir / "ida_jobs")
    if native_rows:
        backend = run_ida_inventory(
            native_rows,
            ida_jobs_dir,
            install_dir=args.ida_install_dir,
            python_executable=args.ida_python_executable,
            timeout_per_library=args.timeout_per_binary,
            timeout_per_app=args.timeout_total,
            max_instructions_per_function=args.max_instructions,
        )
    else:
        backend = {
            "status": "completed",
            "library_summaries": [],
            "message": "No native binary artifact was supplied.",
        }
        safe_write_json(ida_jobs_dir / "ida_inventory_summary.json", backend)

    native_index_path = output_dir / "oss_binary_function_index.jsonl"
    native_summary = materialize_oss_binary_index(
        backend,
        native_rows,
        native_index_path,
    )
    dex_index_path = output_dir / "oss_dex_method_index.jsonl"
    dex_summary = materialize_oss_dex_index(dex_rows, dex_index_path)
    combined_index_path = output_dir / "oss_compiled_function_index.jsonl"
    write_jsonl(
        combined_index_path,
        chain(iter_jsonl(native_index_path), iter_jsonl(dex_index_path)),
    )
    requested_statuses = {
        native_summary.get("status"),
        dex_summary.get("status"),
    } - {"not_requested"}
    if requested_statuses == {"completed"}:
        status = "completed"
    elif requested_statuses and "failed" not in requested_statuses:
        status = "partial"
    else:
        status = "failed"
    summary = {
        "schema_version": "2026-08-24.oss-compiled-index.v2",
        "status": status,
        "native": native_summary,
        "dex": dex_summary,
        "combined_index_path": str(combined_index_path),
        "combined_function_count": sum(
            1 for _row in iter_jsonl(combined_index_path)
        ),
        "dex_archive_count": len(dex_rows),
        "standalone_native_artifact_count": len(standalone_native_rows),
        "apk_native_artifact_count": len(apk_native_rows),
    }
    summary.update(
        {
            "manifest_path": str(manifest_path),
            "backend_summary_path": str(
                ida_jobs_dir / "ida_inventory_summary.json"
            ),
            "compilation_boundary": (
                "This command indexes binaries named by the manifest. It does not "
                "guess or execute heterogeneous project build recipes."
            ),
        }
    )
    safe_write_json(output_dir / "oss_binary_index_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
