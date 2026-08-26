"""Materialize unified OSS binary fingerprints from IDA inventory jobs."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
from pathlib import Path
from typing import Any, Iterable
import zipfile

from .dex_method_index import build_dex_method_index
from .evidence import write_jsonl
from .function_fingerprint import stable_id
from .reuse_candidate_retrieval import iter_jsonl
from .utils import ensure_dir, safe_name


OSS_BINARY_INDEX_SCHEMA = "2026-08-24.oss-compiled-binary-index.v2"
OSS_DEX_INDEX_SCHEMA = "2026-08-24.oss-compiled-dex-index.v2"


def extract_apk_native_artifacts(
    manifest_rows: Iterable[dict[str, Any]],
    output_dir: Path,
) -> list[dict[str, Any]]:
    """Extract all packaged `.so` files while preserving build provenance."""

    output_dir = ensure_dir(output_dir)
    extracted: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for manifest in manifest_rows:
        if not isinstance(manifest, dict):
            continue
        archive_path = Path(str(manifest.get("binary_path") or ""))
        if not archive_path.is_file() or not zipfile.is_zipfile(archive_path):
            continue
        with zipfile.ZipFile(archive_path) as archive:
            infos = sorted(archive.infolist(), key=lambda item: item.filename)
            for info in infos:
                parts = Path(info.filename).parts
                if (
                    info.is_dir()
                    or len(parts) != 3
                    or parts[0] != "lib"
                    or not parts[2].lower().endswith(".so")
                ):
                    continue
                abi, library_name = parts[1], parts[2]
                data = archive.read(info)
                library_hash = hashlib.sha256(data).hexdigest()
                identity = (
                    str(manifest.get("repository_full_name") or ""),
                    str(manifest.get("commit_sha") or ""),
                    str(manifest.get("build_variant") or "unknown"),
                    f"{abi}:{library_hash}",
                )
                if identity in seen:
                    continue
                seen.add(identity)
                destination = ensure_dir(
                    output_dir / library_hash[:12] / safe_name(abi)
                ) / safe_name(library_name)
                if not destination.is_file() or hashlib.sha256(
                    destination.read_bytes()
                ).hexdigest() != library_hash:
                    destination.write_bytes(data)
                extracted.append(
                    {
                        **manifest,
                        "binary_path": str(destination),
                        "extracted_path": str(destination),
                        "source_archive_path": str(archive_path),
                        "source_archive_entry": info.filename,
                        "sha256": library_hash,
                        "library_sha256": library_hash,
                        "abi": abi,
                        "name": library_name,
                    }
                )
    extracted.sort(
        key=lambda row: (
            str(row.get("repository_full_name")),
            str(row.get("commit_sha")),
            str(row.get("build_variant")),
            str(row.get("abi")),
            str(row.get("name")),
            str(row.get("sha256")),
        )
    )
    return extracted


def materialize_oss_binary_index(
    backend_summary: dict[str, Any],
    manifest_rows: Iterable[dict[str, Any]],
    output_path: Path,
) -> dict[str, Any]:
    manifests_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    manifest_count = 0
    for manifest in manifest_rows:
        if not isinstance(manifest, dict):
            continue
        library_hash = str(
            manifest.get("sha256") or manifest.get("library_sha256") or ""
        )
        if not library_hash:
            continue
        manifests_by_hash[library_hash].append(manifest)
        manifest_count += 1
    output_rows: list[dict[str, Any]] = []
    missing_manifest_hashes: set[str] = set()
    repository_counts: Counter[str] = Counter()
    variant_counts: Counter[str] = Counter()
    for library_summary in backend_summary.get("library_summaries") or []:
        library_hash = str(library_summary.get("library_sha256") or "")
        manifests = manifests_by_hash.get(library_hash) or []
        if not manifests:
            missing_manifest_hashes.add(library_hash or "<missing>")
            continue
        inventory_path = Path(str(library_summary.get("inventory_path") or ""))
        for row in iter_jsonl(inventory_path):
            address = str(row.get("address") or "")
            if not address:
                continue
            for manifest in manifests:
                repository = str(manifest.get("repository_full_name") or "")
                build_variant = str(manifest.get("build_variant") or "unknown")
                function_id = stable_id(
                    "oss_compiled_binary",
                    repository,
                    manifest.get("commit_sha"),
                    library_hash,
                    address,
                    build_variant,
                )
                output_rows.append(
                    {
                        **row,
                        "index_schema_version": OSS_BINARY_INDEX_SCHEMA,
                        "schema_version": row.get("schema_version"),
                        "function_id": function_id,
                        "representation": "oss_compiled_binary_function",
                        "corpus_id": manifest.get("corpus_id"),
                        "repository_full_name": repository,
                        "commit_sha": manifest.get("commit_sha"),
                        "source_path": manifest.get("source_path"),
                        "candidate_role": manifest.get("candidate_role")
                        or "upstream_candidate",
                        "ownership_class": manifest.get("ownership_class")
                        or "project_owned_candidate",
                        "build_variant": build_variant,
                        "compiler": manifest.get("compiler"),
                        "compiler_version": manifest.get("compiler_version"),
                        "build_recipe_id": manifest.get("build_recipe_id"),
                        "abi": manifest.get("abi") or row.get("abi"),
                        "binary_path": manifest.get("binary_path"),
                        "source_archive_path": manifest.get(
                            "source_archive_path"
                        ),
                        "source_archive_entry": manifest.get(
                            "source_archive_entry"
                        ),
                        "binary_sha256": library_hash,
                        "provenance_note": (
                            "Function inventory from a fixed OSS commit and recorded build "
                            "variant. It is a retrieval representation, not proof that the "
                            "commercial binary copied this project."
                        ),
                    }
                )
                repository_counts[repository or "unknown"] += 1
                variant_counts[build_variant] += 1
    output_rows.sort(
        key=lambda row: (
            str(row.get("repository_full_name")),
            str(row.get("commit_sha")),
            str(row.get("build_variant")),
            str(row.get("binary_sha256")),
            str(row.get("address")),
        )
    )
    write_jsonl(output_path, output_rows)
    backend_status = str(backend_summary.get("status") or "missing")
    if not manifests_by_hash:
        status = "not_requested"
    else:
        status = "completed" if backend_status == "completed" else "partial"
        if missing_manifest_hashes or not output_rows:
            status = "partial" if output_rows else "failed"
    return {
        "schema_version": OSS_BINARY_INDEX_SCHEMA,
        "status": status,
        "backend_status": backend_status,
        "manifest_binary_count": manifest_count,
        "unique_binary_hash_count": len(manifests_by_hash),
        "indexed_function_count": len(output_rows),
        "repository_function_counts": dict(sorted(repository_counts.items())),
        "build_variant_function_counts": dict(sorted(variant_counts.items())),
        "missing_manifest_hashes": sorted(missing_manifest_hashes),
        "output_path": str(output_path),
    }


def materialize_oss_dex_index(
    manifest_rows: Iterable[dict[str, Any]],
    output_path: Path,
) -> dict[str, Any]:
    """Index DEX methods from reproducibly built OSS APK artifacts."""

    output_rows: list[dict[str, Any]] = []
    artifact_summaries: list[dict[str, Any]] = []
    repository_counts: Counter[str] = Counter()
    for manifest in manifest_rows:
        if not isinstance(manifest, dict):
            continue
        apk_path = Path(str(manifest.get("binary_path") or ""))
        summary, rows = build_dex_method_index(
            [apk_path],
            app_package=manifest.get("app_package"),
            first_party_prefixes=tuple(
                manifest.get("first_party_prefixes") or ()
            ),
        )
        artifact_summaries.append(
            {
                "binary_path": str(apk_path),
                "binary_sha256": manifest.get("sha256"),
                "status": summary.get("status"),
                "indexed_method_count": summary.get("indexed_method_count", 0),
                "error_count": summary.get("error_count", 0),
            }
        )
        for row in rows:
            repository = str(manifest.get("repository_full_name") or "")
            build_variant = str(manifest.get("build_variant") or "unknown")
            output_rows.append(
                {
                    **row,
                    "index_schema_version": OSS_DEX_INDEX_SCHEMA,
                    "function_id": stable_id(
                        "oss_compiled_dex",
                        manifest.get("commit_sha"),
                        manifest.get("sha256"),
                        row.get("function_id"),
                        build_variant,
                    ),
                    "representation": "oss_compiled_dex_method",
                    "corpus_id": manifest.get("corpus_id"),
                    "repository_full_name": repository,
                    "commit_sha": manifest.get("commit_sha"),
                    "candidate_role": manifest.get("candidate_role")
                    or "upstream_candidate",
                    "ownership_class": manifest.get("ownership_class")
                    or "project_owned_candidate",
                    "build_variant": build_variant,
                    "compiler": manifest.get("compiler"),
                    "compiler_version": manifest.get("compiler_version"),
                    "build_recipe_id": manifest.get("build_recipe_id"),
                    "binary_path": str(apk_path),
                    "binary_sha256": manifest.get("sha256"),
                    "provenance_note": (
                        "DEX method from a fixed OSS commit and recorded build "
                        "variant. It is a retrieval representation, not evidence "
                        "of copying by itself."
                    ),
                }
            )
            repository_counts[repository or "unknown"] += 1
    output_rows.sort(
        key=lambda row: (
            str(row.get("repository_full_name")),
            str(row.get("commit_sha")),
            str(row.get("build_variant")),
            str(row.get("binary_sha256")),
            str(row.get("class_descriptor")),
            str(row.get("method_name")),
        )
    )
    write_jsonl(output_path, output_rows)
    statuses = {str(row.get("status") or "missing") for row in artifact_summaries}
    if not artifact_summaries:
        status = "not_requested"
    elif statuses == {"completed"}:
        status = "completed"
    elif output_rows:
        status = "partial"
    else:
        status = "failed"
    return {
        "schema_version": OSS_DEX_INDEX_SCHEMA,
        "status": status,
        "manifest_artifact_count": len(artifact_summaries),
        "indexed_method_count": len(output_rows),
        "repository_method_counts": dict(sorted(repository_counts.items())),
        "artifact_summaries": artifact_summaries,
        "output_path": str(output_path),
    }
