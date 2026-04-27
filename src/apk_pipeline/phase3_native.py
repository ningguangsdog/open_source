from __future__ import annotations

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from .models import PhaseResult
from .utils import ensure_dir, reset_dir, run_cmd, safe_write_json

logger = logging.getLogger(__name__)

KEYWORDS = {
    "crypto": ["AES", "RSA", "SHA", "MD5", "DES"],
    "network": ["http", "https", "socket", "connect", "ssl"],
    "image": ["opencv", "cv::", "jpeg", "png", "filter"],
    "android": ["JNI", "Java_", "android", "asset", "logcat"],
    "anti_analysis": ["frida", "xposed", "debug", "ptrace", "anti"],
}


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def _extract_so_files(apk_path: Path, out_dir: Path) -> list[Path]:
    """
    Extract native .so files from a single APK into out_dir.

    For split APK bundles, this function is called once for each APK that may
    contain native libraries.
    """
    extracted: list[Path] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                zf.extract(name, out_dir)
                extracted.append(out_dir / name)
    return sorted(p for p in extracted if p.exists())


def _strings(file_path: Path) -> list[str]:
    result = run_cmd(["strings", str(file_path)])
    if result.returncode != 0:
        return []
    return result.stdout.splitlines()


def _analyze_so_file(so_path: Path) -> dict[str, Any]:
    strings = _strings(so_path)
    hits = {k: [] for k in KEYWORDS}

    for line in strings:
        for category, kws in KEYWORDS.items():
            for kw in kws:
                if kw.lower() in line.lower():
                    hits[category].append(line.strip())

    for key in hits:
        hits[key] = sorted(set(hits[key]))[:20]

    return {
        "total_strings": len(strings),
        "keyword_hits": hits,
    }


def run_phase3_multi(
    apk_paths: list[Path],
    workspace: Path,
    force: bool = False,
    logical_apk_name: str | None = None,
) -> PhaseResult:
    """
    Phase III: Native-level lightweight auditing.

    Supports both regular APKs and split APK bundle workflows. For .apkm/.apks
    inputs, the pipeline can pass multiple nested APKs here, because native
    libraries often live in ABI split APKs rather than base.apk.
    """
    phase_dir = ensure_dir(workspace / "phase3_native")
    so_dir = phase_dir / "native_libs"
    summary_path = phase_dir / "native_analysis.json"

    apk_paths = [Path(p) for p in apk_paths]
    apk_name = logical_apk_name or (apk_paths[0].name if apk_paths else "unknown.apk")

    if summary_path.exists() and so_dir.exists() and not force:
        return PhaseResult(
            phase="phase3_native",
            success=True,
            apk_filename=apk_name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message="Phase III skipped because outputs already exist.",
        )

    try:
        reset_dir(so_dir)

        analysis_results: dict[str, Any] = {}
        extracted_so_files: list[Path] = []
        source_apks: list[str] = []

        for apk_path in apk_paths:
            if not apk_path.exists():
                logger.warning("Phase III source APK does not exist: %s", apk_path)
                continue

            source_apks.append(str(apk_path))
            apk_so_dir = ensure_dir(so_dir / _safe_name(apk_path.stem))
            so_files = _extract_so_files(apk_path, apk_so_dir)
            extracted_so_files.extend(so_files)

            for so in so_files:
                result_key = str(so.relative_to(phase_dir))
                analysis_results[result_key] = {
                    "source_apk": str(apk_path),
                    **_analyze_so_file(so),
                }

        payload = {
            "logical_apk_name": apk_name,
            "source_apks": source_apks,
            "native_lib_count": len(extracted_so_files),
            "analyzed_libs": len(analysis_results),
            "libraries": analysis_results,
        }

        safe_write_json(summary_path, payload)

        success = len(extracted_so_files) > 0

        return PhaseResult(
            phase="phase3_native",
            success=success,
            apk_filename=apk_name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message="Phase III completed." if success else "No native libraries found in selected APK file(s).",
            details={
                "source_apk_count": len(source_apks),
                "native_lib_count": len(extracted_so_files),
                "analyzed_libs": len(analysis_results),
            },
        )

    except Exception as exc:
        logger.exception("Phase III failed")
        return PhaseResult(
            phase="phase3_native",
            success=False,
            apk_filename=apk_name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path) if summary_path.exists() else None,
            message=f"Phase III failed: {exc}",
        )


def run_phase3(apk_path: Path, workspace: Path, force: bool = False) -> PhaseResult:
    """
    Backward-compatible wrapper for regular single-APK analysis.
    """
    return run_phase3_multi(
        apk_paths=[apk_path],
        workspace=workspace,
        force=force,
        logical_apk_name=apk_path.name,
    )
