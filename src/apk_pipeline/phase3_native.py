from __future__ import annotations

import logging
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


def _extract_so_files(apk_path: Path, out_dir: Path) -> list[Path]:
    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                zf.extract(name, out_dir)
    return sorted(out_dir.rglob("*.so"))


def _strings(file_path: Path) -> list[str]:
    result = run_cmd(["strings", str(file_path)])
    if result.returncode != 0:
        return []
    return result.stdout.splitlines()


def run_phase3(apk_path: Path, workspace: Path, force: bool = False) -> PhaseResult:
    phase_dir = ensure_dir(workspace / "phase3_native")
    so_dir = phase_dir / "native_libs"
    summary_path = phase_dir / "native_analysis.json"

    if summary_path.exists() and so_dir.exists() and not force:
        return PhaseResult(
            phase="phase3_native",
            success=True,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message="Phase III skipped because outputs already exist.",
        )

    try:
        reset_dir(so_dir)
        so_files = _extract_so_files(apk_path, so_dir)
        analysis_results: dict[str, Any] = {}

        for so in so_files:
            strings = _strings(so)
            hits = {k: [] for k in KEYWORDS}
            for line in strings:
                for category, kws in KEYWORDS.items():
                    for kw in kws:
                        if kw.lower() in line.lower():
                            hits[category].append(line.strip())
            for key in hits:
                hits[key] = sorted(set(hits[key]))[:20]
            analysis_results[str(so)] = {
                "total_strings": len(strings),
                "keyword_hits": hits,
            }

        safe_write_json(summary_path, analysis_results)
        success = len(so_files) > 0
        return PhaseResult(
            phase="phase3_native",
            success=success,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message="Phase III completed." if success else "No native libraries found in APK.",
            details={
                "native_lib_count": len(so_files),
                "analyzed_libs": len(analysis_results),
            },
        )
    except Exception as exc:
        logger.exception("Phase III failed")
        return PhaseResult(
            phase="phase3_native",
            success=False,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path) if summary_path.exists() else None,
            message=f"Phase III failed: {exc}",
        )
