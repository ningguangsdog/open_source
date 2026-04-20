from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from androguard.core.apk import APK

from .models import PhaseResult
from .utils import ensure_dir, safe_write_json

logger = logging.getLogger(__name__)


def run_phase1(apk_path: Path, workspace: Path, force: bool = False) -> PhaseResult:
    phase_dir = ensure_dir(workspace / "phase1_manifest")
    summary_path = phase_dir / "manifest_summary.json"
    decoded_manifest_path = phase_dir / "AndroidManifest_decoded.xml"

    if summary_path.exists() and not force:
        return PhaseResult(
            phase="phase1_manifest",
            success=True,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message="Phase I skipped because outputs already exist.",
        )

    try:
        apk = APK(str(apk_path))
        file_list = sorted(apk.get_files())
        native_libs = [f for f in file_list if f.startswith("lib/") and f.endswith(".so")]

        manifest_summary: dict[str, Any] = {
            "apk_filename": apk_path.name,
            "package_name": apk.get_package(),
            "app_name": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "max_sdk": apk.get_max_sdk_version(),
            "main_activity": apk.get_main_activity(),
            "permissions": sorted(set(apk.get_permissions())),
            "activities": sorted(set(apk.get_activities())),
            "services": sorted(set(apk.get_services())),
            "receivers": sorted(set(apk.get_receivers())),
            "providers": sorted(set(apk.get_providers())),
            "libraries": sorted(set(apk.get_libraries())),
            "features": sorted(set(apk.get_features())),
            "native_libs": native_libs,
            "file_count": len(file_list),
            "native_lib_count": len(native_libs),
        }

        # best-effort decoded manifest export
        try:
            xml_obj = apk.get_android_manifest_xml()
            from lxml import etree  # optional runtime dependency via androguard stack
            xml_bytes = etree.tostring(xml_obj, pretty_print=True, encoding="utf-8", xml_declaration=True)
            decoded_manifest_path.write_bytes(xml_bytes)
        except Exception as exc:
            logger.warning("Failed to export decoded manifest: %s", exc)
            decoded_manifest_path.write_text(
                "<!-- Decoded manifest export failed; structured summary was still extracted successfully. -->",
                encoding="utf-8",
            )

        safe_write_json(summary_path, manifest_summary)
        success = bool(manifest_summary.get("package_name"))

        return PhaseResult(
            phase="phase1_manifest",
            success=success,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message="Phase I completed." if success else "Phase I completed with incomplete manifest metadata.",
            details={
                "package_name": manifest_summary.get("package_name"),
                "permissions": len(manifest_summary.get("permissions", [])),
                "activities": len(manifest_summary.get("activities", [])),
                "native_lib_count": manifest_summary.get("native_lib_count", 0),
            },
        )
    except Exception as exc:
        logger.exception("Phase I failed")
        return PhaseResult(
            phase="phase1_manifest",
            success=False,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path) if summary_path.exists() else None,
            message=f"Phase I failed: {exc}",
        )
