from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .utils import (
    ensure_dir,
    reset_dir,
    safe_extract_zip,
    safe_name,
    safe_write_json,
    sha256_file,
    zip_contains,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ResolvedAPKInput:
    original_path: Path
    input_type: str
    primary_apk: Path
    all_apks: list[Path]
    phase3_apks: list[Path]
    extracted_dir: Path | None = None
    notes: list[str] | None = None


def _is_zip_with_nested_apks(path: Path) -> bool:
    return zip_contains(path, lambda n: n.lower().endswith(".apk"))


def _apk_contains(path: Path, predicate) -> bool:
    return zip_contains(path, predicate)


def _has_dex(path: Path) -> bool:
    return _apk_contains(path, lambda n: n.lower().endswith(".dex"))


def _has_native_libs(path: Path) -> bool:
    return _apk_contains(
        path,
        lambda n: n.lower().startswith("lib/") and n.lower().endswith(".so"),
    )


def _nested_apks(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() == ".apk"
    )


def _extracted_apk_records(root: Path) -> list[dict[str, object]]:
    return [
        {
            "relative_path": str(path.relative_to(root)),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in _nested_apks(root)
    ]


def _bundle_cache_valid(
    root: Path,
    cached: dict[str, object],
    current_source: dict[str, object],
) -> bool:
    if (
        cached.get("source_sha256") != current_source["source_sha256"]
        or cached.get("source_size_bytes") != current_source["source_size_bytes"]
    ):
        return False
    records = cached.get("extracted_apks")
    if not isinstance(records, list) or not records:
        return False
    for record in records:
        if not isinstance(record, dict):
            return False
        relative_path = record.get("relative_path")
        if not isinstance(relative_path, str):
            return False
        path = root / relative_path
        if not path.is_file():
            return False
        if (
            path.stat().st_size != record.get("size_bytes")
            or sha256_file(path) != record.get("sha256")
        ):
            return False
    return len(_nested_apks(root)) == len(records)


def _select_primary_apk(apk_files: list[Path]) -> Path:
    if not apk_files:
        raise FileNotFoundError("No nested APK files found in bundle.")

    for apk in apk_files:
        if apk.name.lower() == "base.apk":
            return apk

    dex_candidates = [apk for apk in apk_files if _has_dex(apk)]
    if dex_candidates:
        return max(dex_candidates, key=lambda p: p.stat().st_size)

    return max(apk_files, key=lambda p: p.stat().st_size)


def resolve_apk_input(
    input_path: Path,
    workspace: Path,
    force: bool = False,
) -> ResolvedAPKInput:
    """
    Resolve user input into concrete APK targets.

    Supported inputs:
    - .apk
    - .apkm / .apks / .xapk or any zip-like bundle containing nested APKs
    """
    input_path = input_path.expanduser().resolve()

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    notes: list[str] = []
    suffix = input_path.suffix.lower()
    looks_like_bundle = suffix in {".apkm", ".apks", ".xapk"} or (
        suffix != ".apk" and _is_zip_with_nested_apks(input_path)
    )

    if not looks_like_bundle:
        return ResolvedAPKInput(
            original_path=input_path,
            input_type="apk",
            primary_apk=input_path,
            all_apks=[input_path],
            phase3_apks=[input_path],
            extracted_dir=None,
            notes=["Input treated as a regular APK."],
        )

    if not zipfile.is_zipfile(input_path):
        raise ValueError(f"Input has bundle-like extension but is not a valid zip file: {input_path}")

    bundle_dir = ensure_dir(workspace / "input_bundle" / safe_name(input_path.stem))
    bundle_manifest_path = bundle_dir / ".bundle_source.json"
    current_bundle_identity = {
        "source_path": str(input_path),
        "source_size_bytes": input_path.stat().st_size,
        "source_sha256": sha256_file(input_path),
    }
    cached_bundle_identity: dict[str, object] = {}
    if bundle_manifest_path.exists():
        try:
            import json

            cached_bundle_identity = json.loads(bundle_manifest_path.read_text(encoding="utf-8"))
        except Exception:
            cached_bundle_identity = {}

    cache_matches = _bundle_cache_valid(
        bundle_dir,
        cached_bundle_identity,
        current_bundle_identity,
    )
    if force or not cache_matches:
        reset_dir(bundle_dir)

    if not _nested_apks(bundle_dir):
        logger.info("Extracting APK bundle: %s", input_path.name)
        safe_extract_zip(input_path, bundle_dir)
        safe_write_json(
            bundle_manifest_path,
            {
                **current_bundle_identity,
                "extracted_apks": _extracted_apk_records(bundle_dir),
            },
        )

    nested_apks = _nested_apks(bundle_dir)
    if not nested_apks:
        raise FileNotFoundError(f"No APK files found inside bundle: {input_path}")

    primary_apk = _select_primary_apk(nested_apks)
    native_apks = [apk for apk in nested_apks if _has_native_libs(apk)]

    if not native_apks:
        native_apks = [primary_apk]
        notes.append("No split APK with native libraries was found; Phase III will inspect the primary APK.")

    notes.append(f"Bundle input detected: {len(nested_apks)} nested APK file(s).")
    notes.append(f"Primary APK selected for Phase I/II: {primary_apk.name}.")
    notes.append(f"APK file(s) selected for native analysis: {len(native_apks)}.")

    return ResolvedAPKInput(
        original_path=input_path,
        input_type="apk_bundle",
        primary_apk=primary_apk,
        all_apks=nested_apks,
        phase3_apks=native_apks,
        extracted_dir=bundle_dir,
        notes=notes,
    )
