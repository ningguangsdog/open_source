from __future__ import annotations

import logging
import re
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .utils import ensure_dir

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ResolvedAPKInput:
    original_path: Path
    input_type: str
    primary_apk: Path
    phase3_apks: list[Path]
    extracted_dir: Path | None = None
    notes: list[str] | None = None


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def _is_zip_with_nested_apks(path: Path) -> bool:
    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return any(n.lower().endswith(".apk") for n in zf.namelist())
    except Exception:
        return False


def _apk_contains(path: Path, predicate) -> bool:
    try:
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path, "r") as zf:
            return any(predicate(n) for n in zf.namelist())
    except Exception:
        return False


def _has_dex(path: Path) -> bool:
    return _apk_contains(path, lambda n: n.lower().endswith(".dex"))


def _has_native_libs(path: Path) -> bool:
    return _apk_contains(
        path,
        lambda n: n.startswith("lib/") and n.endswith(".so"),
    )


def _select_primary_apk(apk_files: list[Path]) -> Path:
    """
    Select the APK that should be used for Phase I and Phase II.

    For APKM/APKS/XAPK bundles, base.apk is usually the correct target for
    manifest extraction and Java decompilation. If base.apk is not available,
    choose an APK containing dex files. If multiple candidates exist, choose
    the largest one.
    """
    if not apk_files:
        raise FileNotFoundError("No nested APK files found in bundle.")

    for apk in apk_files:
        if apk.name == "base.apk":
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
    - .apk  : processed directly
    - .apkm / .apks / .xapk or any zip-like bundle containing nested APKs:
              extracted first, then base.apk is used for Phase I/II, and
              APKs containing native libraries are used for Phase III.
    """
    input_path = input_path.expanduser().resolve()

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    notes: list[str] = []
    suffix = input_path.suffix.lower()

    looks_like_bundle = suffix in {".apkm", ".apks", ".xapk"} or _is_zip_with_nested_apks(input_path)

    if not looks_like_bundle:
        return ResolvedAPKInput(
            original_path=input_path,
            input_type="apk",
            primary_apk=input_path,
            phase3_apks=[input_path],
            extracted_dir=None,
            notes=["Input treated as a regular APK."],
        )

    bundle_dir = ensure_dir(workspace / "input_bundle" / _safe_name(input_path.stem))

    if force and bundle_dir.exists():
        shutil.rmtree(bundle_dir)
        bundle_dir.mkdir(parents=True, exist_ok=True)

    if not any(bundle_dir.rglob("*.apk")):
        logger.info("Extracting APK bundle: %s", input_path.name)
        with zipfile.ZipFile(input_path, "r") as zf:
            zf.extractall(bundle_dir)

    nested_apks = sorted(bundle_dir.rglob("*.apk"))

    if not nested_apks:
        raise FileNotFoundError(f"No APK files found inside bundle: {input_path}")

    primary_apk = _select_primary_apk(nested_apks)
    native_apks = [apk for apk in nested_apks if _has_native_libs(apk)]

    if not native_apks:
        native_apks = [primary_apk]
        notes.append("No split APK with native libraries was found; Phase III will inspect the primary APK.")

    notes.append(f"Bundle input detected: {len(nested_apks)} nested APK file(s).")
    notes.append(f"Primary APK selected for Phase I/II: {primary_apk.name}.")
    notes.append(f"APK file(s) selected for Phase III: {len(native_apks)}.")

    return ResolvedAPKInput(
        original_path=input_path,
        input_type="apk_bundle",
        primary_apk=primary_apk,
        phase3_apks=native_apks,
        extracted_dir=bundle_dir,
        notes=notes,
    )
