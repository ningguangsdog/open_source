from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, TypeVar

from androguard.core.apk import APK

from .models import PhaseResult
from .utils import ensure_dir, safe_write_json

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _safe_call(
    fn: Callable[[], T],
    default: T,
    field_name: str,
    warnings: list[str],
) -> T:
    """
    Run an APK metadata extraction call safely.

    Some APKs, especially large commercial apps or bundle-derived APKs,
    may contain resource table formats that are not fully compatible with
    Androguard's ARSC parser. We treat such failures as field-level warnings
    rather than phase-level failures.
    """
    try:
        return fn()
    except Exception as exc:
        msg = f"Failed to extract {field_name}: {exc}"
        logger.warning(msg)
        warnings.append(msg)
        return default


def _as_sorted_unique_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return sorted(set(str(x) for x in value if x is not None))
    return [str(value)]


def run_phase1(apk_path: Path, workspace: Path, force: bool = False) -> PhaseResult:
    """
    Phase I: Manifest-level semantic extraction.

    This phase is intentionally implemented as a best-effort parser.
    A failure to resolve resource-dependent fields such as app_name should
    not prevent extraction of package name, permissions, components, or
    native library metadata.
    """
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

    warnings: list[str] = []

    try:
        apk = APK(str(apk_path))

        file_list = _safe_call(
            apk.get_files,
            [],
            "file list",
            warnings,
        )
        file_list = sorted(str(x) for x in file_list)

        native_libs = [
            f for f in file_list
            if f.startswith("lib/") and f.endswith(".so")
        ]

        # Important:
        # apk.get_app_name() may trigger resources.arsc parsing.
        # For some APKs, this may fail even when manifest/dex/native analysis works.
        app_name = _safe_call(
            apk.get_app_name,
            None,
            "app_name",
            warnings,
        )

        package_name = _safe_call(
            apk.get_package,
            None,
            "package_name",
            warnings,
        )

        manifest_summary: dict[str, Any] = {
            "apk_filename": apk_path.name,
            "package_name": package_name,
            "app_name": app_name,
            "version_name": _safe_call(
                apk.get_androidversion_name,
                None,
                "version_name",
                warnings,
            ),
            "version_code": _safe_call(
                apk.get_androidversion_code,
                None,
                "version_code",
                warnings,
            ),
            "min_sdk": _safe_call(
                apk.get_min_sdk_version,
                None,
                "min_sdk",
                warnings,
            ),
            "target_sdk": _safe_call(
                apk.get_target_sdk_version,
                None,
                "target_sdk",
                warnings,
            ),
            "max_sdk": _safe_call(
                apk.get_max_sdk_version,
                None,
                "max_sdk",
                warnings,
            ),
            "main_activity": _safe_call(
                apk.get_main_activity,
                None,
                "main_activity",
                warnings,
            ),
            "permissions": _as_sorted_unique_list(
                _safe_call(apk.get_permissions, [], "permissions", warnings)
            ),
            "activities": _as_sorted_unique_list(
                _safe_call(apk.get_activities, [], "activities", warnings)
            ),
            "services": _as_sorted_unique_list(
                _safe_call(apk.get_services, [], "services", warnings)
            ),
            "receivers": _as_sorted_unique_list(
                _safe_call(apk.get_receivers, [], "receivers", warnings)
            ),
            "providers": _as_sorted_unique_list(
                _safe_call(apk.get_providers, [], "providers", warnings)
            ),
            "libraries": _as_sorted_unique_list(
                _safe_call(apk.get_libraries, [], "libraries", warnings)
            ),
            "features": _as_sorted_unique_list(
                _safe_call(apk.get_features, [], "features", warnings)
            ),
            "native_libs": native_libs,
            "file_count": len(file_list),
            "native_lib_count": len(native_libs),
            "warnings": warnings,
            "partial": bool(warnings),
            "parser": "androguard_best_effort",
        }

        # Best-effort decoded manifest export.
        try:
            xml_obj = apk.get_android_manifest_xml()
            from lxml import etree

            xml_bytes = etree.tostring(
                xml_obj,
                pretty_print=True,
                encoding="utf-8",
                xml_declaration=True,
            )
            decoded_manifest_path.write_bytes(xml_bytes)
        except Exception as exc:
            msg = f"Failed to export decoded manifest XML: {exc}"
            logger.warning(msg)
            warnings.append(msg)
            decoded_manifest_path.write_text(
                "<!-- Decoded manifest export failed. "
                "Structured manifest metadata was extracted on a best-effort basis. -->",
                encoding="utf-8",
            )
            manifest_summary["warnings"] = warnings
            manifest_summary["partial"] = True

        safe_write_json(summary_path, manifest_summary)

        # Define Phase I success as whether we extracted any useful manifest-level signal.
        # This prevents optional resource-resolution failures from invalidating the phase.
        success = bool(
            manifest_summary.get("package_name")
            or manifest_summary.get("permissions")
            or manifest_summary.get("activities")
            or manifest_summary.get("native_libs")
        )

        return PhaseResult(
            phase="phase1_manifest",
            success=success,
            apk_filename=apk_path.name,
            output_dir=str(phase_dir),
            summary_path=str(summary_path),
            message=(
                "Phase I completed."
                if success and not warnings
                else "Phase I completed with warnings."
                if success
                else "Phase I completed but extracted limited metadata."
            ),
            details={
                "package_name": manifest_summary.get("package_name"),
                "app_name": manifest_summary.get("app_name"),
                "permissions": len(manifest_summary.get("permissions", [])),
                "activities": len(manifest_summary.get("activities", [])),
                "native_lib_count": manifest_summary.get("native_lib_count", 0),
                "partial": manifest_summary.get("partial", False),
                "warning_count": len(warnings),
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
