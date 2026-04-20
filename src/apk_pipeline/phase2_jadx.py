from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from .models import PhaseResult
from .utils import ensure_dir, reset_dir, run_cmd, safe_read_text, safe_write_json

logger = logging.getLogger(__name__)

KEYWORDS = [
    "Cipher", "AES", "RSA", "HttpURLConnection", "OkHttp", "Retrofit",
    "WebView", "SQLite", "Room", "Camera", "MediaRecorder",
    "LocationManager", "Firebase", "onCreate", "Intent", "Socket",
]


def _find_built_jadx_binary(jadx_dir: Path) -> Path:
    return jadx_dir / "bin" / "jadx"


def _ensure_jadx(jadx_dir: Path, version: str, allow_download: bool = True) -> Path:
    jadx_bin = _find_built_jadx_binary(jadx_dir)
    if jadx_bin.exists():
        try:
            jadx_bin.chmod(0o755)
        except Exception:
            pass
        return jadx_bin

    if not allow_download:
        raise FileNotFoundError("jadx binary not found and automatic download disabled.")

    zip_path = jadx_dir.parent / f"jadx-{version}.zip"
    if not zip_path.exists():
        result = run_cmd([
            "wget", "-O", str(zip_path),
            f"https://github.com/skylot/jadx/releases/download/v{version}/jadx-{version}.zip",
        ])
        if result.returncode != 0:
            raise RuntimeError(f"Failed to download JADX: {result.stderr}")

    shutil.unpack_archive(str(zip_path), str(jadx_dir))
    jadx_bin = _find_built_jadx_binary(jadx_dir)
    if not jadx_bin.exists():
        raise FileNotFoundError("JADX extracted but binary not found.")
    try:
        jadx_bin.chmod(0o755)
    except Exception:
        pass
    return jadx_bin


def run_phase2(
    apk_path: Path,
    workspace: Path,
    force: bool = False,
    jadx_version: str = "1.5.0",
    threads: int = 4,
    allow_download: bool = True,
) -> PhaseResult:
    phase_dir = ensure_dir(workspace / "phase2_jadx")
    summary_path = phase_dir / "jadx_summary.json"
    decompile_out = phase_dir / "decompiled"
    stdout_log = phase_dir / "jadx_stdout.txt"
    stderr_log = phase_dir / "jadx_stderr.txt"
    jadx_dir = ensure_dir(workspace / "jadx_bin")

    if summary_path.exists() and decompile_out.exists() and not force:
        return PhaseResult(
            phase="phase2_jadx",
            success=True,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message="Phase II skipped because outputs already exist.",
        )

    try:
        jadx_bin = _ensure_jadx(jadx_dir, jadx_version, allow_download=allow_download)
        reset_dir(decompile_out)

        cmd = [
            str(jadx_bin),
            "--show-bad-code",
            "--deobf",
            "--deobf-min", "3",
            "--deobf-max", "64",
            "-j", str(threads),
            "-d", str(decompile_out),
            str(apk_path),
        ]
        result = run_cmd(cmd)
        stdout_log.write_text(result.stdout or "", encoding="utf-8")
        stderr_log.write_text(result.stderr or "", encoding="utf-8")

        java_files = sorted(decompile_out.rglob("*.java"))
        kt_files = sorted(decompile_out.rglob("*.kt"))
        xml_files = sorted(decompile_out.rglob("*.xml"))

        keyword_hits: dict[str, list[str]] = {}
        for jf in java_files[:300]:
            text = safe_read_text(jf, limit=20000)
            for kw in KEYWORDS:
                if kw in text:
                    keyword_hits.setdefault(kw, []).append(str(jf.relative_to(decompile_out)))

        summary: dict[str, Any] = {
            "apk_filename": apk_path.name,
            "decompile_output_dir": str(decompile_out.resolve()),
            "java_file_count": len(java_files),
            "kt_file_count": len(kt_files),
            "xml_file_count": len(xml_files),
            "sample_java_files": [str(p.relative_to(decompile_out)) for p in java_files[:15]],
            "keyword_hits": keyword_hits,
            "stdout_log": str(stdout_log.resolve()),
            "stderr_log": str(stderr_log.resolve()),
            "jadx_return_code": result.returncode,
        }
        safe_write_json(summary_path, summary)

        # success detection: either JADX exit code 0 or meaningful Java output exists
        success = (result.returncode == 0 and len(java_files) > 0) or (len(java_files) >= 10)
        message = "Phase II completed successfully." if success else "Phase II finished but decompilation output looks incomplete."
        return PhaseResult(
            phase="phase2_jadx",
            success=success,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message=message,
            details={
                "java_file_count": len(java_files),
                "kt_file_count": len(kt_files),
                "xml_file_count": len(xml_files),
                "jadx_return_code": result.returncode,
            },
        )
    except Exception as exc:
        logger.exception("Phase II failed")
        return PhaseResult(
            phase="phase2_jadx",
            success=False,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path) if summary_path.exists() else None,
            message=f"Phase II failed: {exc}",
        )
