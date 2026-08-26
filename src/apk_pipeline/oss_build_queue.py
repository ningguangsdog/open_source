"""Deterministic staging for reproducible OSS candidate builds.

This module does not execute project build systems.  It converts retrieval
evidence plus the frozen snapshot manifest into a bounded queue whose rows can
receive reviewed, project-specific build recipes.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import os
from pathlib import Path
from typing import Any, Iterable


OSS_BUILD_QUEUE_SCHEMA = "2026-08-24.oss-build-queue.v2"
BUILD_CANDIDATE_ROLES = {None, "upstream_candidate", "method_control"}
_BUILD_FILENAMES = {
    "android.mk": "ndk_make",
    "application.mk": "ndk_make",
    "build.gradle": "android_gradle",
    "build.gradle.kts": "android_gradle",
    "cmakelists.txt": "cmake",
    "configure": "autotools",
    "configure.ac": "autotools",
    "gradlew": "android_gradle",
    "makefile": "make",
    "meson.build": "meson",
}
_NATIVE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".s", ".S"}
_IGNORED_DIRS = {
    ".git",
    ".gradle",
    ".idea",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}


def _snapshot_source_path(snapshot_root: Path, row: dict[str, Any]) -> Path:
    corpus_id = str(row.get("corpus_id") or "").strip()
    repository = str(row.get("repository_full_name") or "").strip()
    commit = str((row.get("selected_commit") or {}).get("sha") or "").strip()
    source_directory = str(row.get("source_directory") or "source").strip()
    return (
        snapshot_root
        / f"{corpus_id}_{repository.replace('/', '_')}"
        / commit
        / source_directory
    )


def inspect_build_surface(source_root: Path) -> dict[str, Any]:
    build_files: list[str] = []
    build_system_counts: Counter[str] = Counter()
    native_source_count = 0
    scanned_file_count = 0
    if not source_root.is_dir():
        return {
            "source_exists": False,
            "scanned_file_count": 0,
            "native_source_count": 0,
            "build_system_counts": {},
            "build_files": [],
            "eligible_for_recipe": False,
            "recipe_status": "snapshot_missing",
        }
    for directory, dirnames, filenames in os.walk(source_root):
        dirnames[:] = sorted(
            name for name in dirnames if name not in _IGNORED_DIRS
        )
        relative_dir = Path(directory).relative_to(source_root)
        for filename in sorted(filenames):
            scanned_file_count += 1
            path = Path(filename)
            if path.suffix in _NATIVE_SUFFIXES:
                native_source_count += 1
            build_system = _BUILD_FILENAMES.get(filename.lower())
            if build_system:
                build_system_counts[build_system] += 1
                if len(build_files) < 100:
                    build_files.append(str(relative_dir / filename))
    eligible = bool(native_source_count and build_system_counts)
    return {
        "source_exists": True,
        "scanned_file_count": scanned_file_count,
        "native_source_count": native_source_count,
        "build_system_counts": dict(sorted(build_system_counts.items())),
        "build_files": build_files,
        "eligible_for_recipe": eligible,
        "recipe_status": (
            "recipe_required"
            if eligible
            else "no_native_source"
            if not native_source_count
            else "no_detected_build_system"
        ),
    }


def build_oss_build_queue(
    candidate_rows: Iterable[dict[str, Any]],
    snapshot_rows: Iterable[dict[str, Any]],
    *,
    snapshot_root: Path,
    limit: int = 15,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if limit <= 0:
        raise ValueError("limit must be positive")
    snapshots: dict[tuple[str, str], dict[str, Any]] = {}
    for row in snapshot_rows:
        if not isinstance(row, dict):
            continue
        key = (
            str(row.get("corpus_id") or ""),
            str(row.get("repository_full_name") or ""),
        )
        if all(key):
            snapshots[key] = row

    aggregate: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "candidate_pair_count": 0,
            "commercial_function_ids": set(),
            "max_retrieval_score": 0.0,
            "capabilities": set(),
        }
    )
    skipped_role_count = 0
    skipped_low_information_count = 0
    for candidate in candidate_rows:
        if not isinstance(candidate, dict):
            continue
        source = candidate.get("source") or {}
        if source.get("candidate_role") not in BUILD_CANDIDATE_ROLES:
            skipped_role_count += 1
            continue
        if (candidate.get("evidence_sufficiency") or {}).get(
            "deep_comparison_eligible"
        ) is False:
            skipped_low_information_count += 1
            continue
        key = (
            str(source.get("corpus_id") or ""),
            str(source.get("repository_full_name") or ""),
        )
        if not all(key):
            continue
        item = aggregate[key]
        item["candidate_pair_count"] += 1
        item["max_retrieval_score"] = max(
            float(item["max_retrieval_score"]),
            float(candidate.get("retrieval_score") or 0),
        )
        commercial_id = str(
            (candidate.get("commercial") or {}).get("function_id") or ""
        )
        if commercial_id:
            item["commercial_function_ids"].add(commercial_id)
        item["capabilities"].update(source.get("capabilities") or [])

    staged: list[dict[str, Any]] = []
    missing_snapshot_count = 0
    for key, evidence in aggregate.items():
        snapshot = snapshots.get(key)
        if snapshot is None:
            missing_snapshot_count += 1
            continue
        source_root = _snapshot_source_path(snapshot_root, snapshot)
        surface = inspect_build_surface(source_root)
        commit = str((snapshot.get("selected_commit") or {}).get("sha") or "")
        staged.append(
            {
                "schema_version": OSS_BUILD_QUEUE_SCHEMA,
                "corpus_id": key[0],
                "repository_full_name": key[1],
                "commit_sha": commit,
                "candidate_role": snapshot.get("candidate_role"),
                "license_spdx": snapshot.get("license_spdx_from_retrieval_manifest"),
                "source_root": str(source_root),
                "candidate_pair_count": int(evidence["candidate_pair_count"]),
                "commercial_function_count": len(
                    evidence["commercial_function_ids"]
                ),
                "max_retrieval_score": round(
                    float(evidence["max_retrieval_score"]), 6
                ),
                "capabilities": sorted(
                    str(value) for value in evidence["capabilities"] if value
                ),
                **surface,
                "requested_build_variants": [
                    {
                        "abi": "arm64-v8a",
                        "optimization": "O2",
                        "purpose": "initial representation-compatible baseline",
                    }
                ],
                "build_boundary": (
                    "A reviewed recipe must pin toolchain versions and record all "
                    "produced binary hashes. This queue does not execute untrusted "
                    "repository build scripts."
                ),
            }
        )
    staged.sort(
        key=lambda row: (
            not bool(row.get("eligible_for_recipe")),
            -float(row.get("max_retrieval_score") or 0),
            -int(row.get("commercial_function_count") or 0),
            -int(row.get("candidate_pair_count") or 0),
            str(row.get("corpus_id") or ""),
        )
    )
    selected = staged[:limit]
    for rank, row in enumerate(selected, start=1):
        row["queue_rank"] = rank
    summary = {
        "schema_version": OSS_BUILD_QUEUE_SCHEMA,
        "status": "completed",
        "candidate_repository_count": len(aggregate),
        "snapshot_repository_count": len(snapshots),
        "matched_snapshot_count": len(staged),
        "missing_snapshot_count": missing_snapshot_count,
        "eligible_repository_count": sum(
            bool(row.get("eligible_for_recipe")) for row in staged
        ),
        "selected_repository_count": len(selected),
        "selected_eligible_repository_count": sum(
            bool(row.get("eligible_for_recipe")) for row in selected
        ),
        "skipped_non_build_candidate_role_count": skipped_role_count,
        "skipped_low_information_candidate_count": skipped_low_information_count,
        "selection_rule": (
            "Build-ready upstream and method candidates first, then maximum retrieval score, "
            "commercial-function coverage, candidate-pair coverage, and corpus ID."
        ),
        "initial_build_variant": "arm64-v8a + O2",
    }
    return summary, selected
