"""Phase 1: manifest and package metadata extraction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import PhaseResult
from .utils import ensure_dir, safe_write_json


DANGEROUS_PERMISSION_MARKERS = (
    "CAMERA",
    "RECORD_AUDIO",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_CALENDAR",
    "WRITE_CALENDAR",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "READ_PHONE_STATE",
    "CALL_PHONE",
    "READ_SMS",
    "SEND_SMS",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO",
    "POST_NOTIFICATIONS",
)


def _call(apk_obj: Any, method: str, default: Any = None) -> Any:
    value = getattr(apk_obj, method, None)
    if not callable(value):
        return default
    try:
        return value()
    except Exception:
        return default


def _stringify_list(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (list, tuple, set)):
        return sorted({str(item) for item in values if item is not None})
    return [str(values)]


def _build_apk_parser(apk_path: Path) -> Any:
    try:
        from androguard.core.apk import APK
    except Exception:
        from androguard.core.bytecodes.apk import APK  # type: ignore

    return APK(str(apk_path))


def _component_summary(apk_obj: Any) -> dict[str, list[str]]:
    components = {
        "activities": _stringify_list(_call(apk_obj, "get_activities", [])),
        "services": _stringify_list(_call(apk_obj, "get_services", [])),
        "receivers": _stringify_list(_call(apk_obj, "get_receivers", [])),
        "providers": _stringify_list(_call(apk_obj, "get_providers", [])),
    }
    return components


def _sdk_summary(apk_obj: Any) -> dict[str, Any]:
    return {
        "min_sdk": _call(apk_obj, "get_min_sdk_version"),
        "target_sdk": _call(apk_obj, "get_target_sdk_version"),
        "max_sdk": _call(apk_obj, "get_max_sdk_version"),
    }


def _extract_manifest_summary(apk_path: Path) -> dict[str, Any]:
    try:
        apk_obj = _build_apk_parser(apk_path)
    except Exception as exc:
        return {
            "apk": str(apk_path),
            "success": False,
            "error": repr(exc),
        }

    package = _call(apk_obj, "get_package")
    app_name = _call(apk_obj, "get_app_name")
    permissions = _stringify_list(_call(apk_obj, "get_permissions", []))
    dangerous_permissions = [
        permission
        for permission in permissions
        if any(marker in permission.upper() for marker in DANGEROUS_PERMISSION_MARKERS)
    ]

    payload: dict[str, Any] = {
        "apk": str(apk_path),
        "success": True,
        "package": package,
        "app_name": app_name,
        "version_name": _call(apk_obj, "get_androidversion_name"),
        "version_code": _call(apk_obj, "get_androidversion_code"),
        "sdk": _sdk_summary(apk_obj),
        "permissions": permissions,
        "dangerous_permissions": dangerous_permissions,
        "components": _component_summary(apk_obj),
        "libraries": _stringify_list(_call(apk_obj, "get_libraries", [])),
        "features": _stringify_list(_call(apk_obj, "get_features", [])),
    }

    manifest_xml = _call(apk_obj, "get_android_manifest_xml")
    if manifest_xml is not None:
        try:
            payload["manifest_xml"] = manifest_xml.toxml()
        except Exception:
            payload["manifest_xml"] = ""

    return payload


def _brief_manifest(summary: dict[str, Any]) -> dict[str, Any]:
    components = summary.get("components") or {}
    return {
        "apk": summary.get("apk"),
        "success": summary.get("success"),
        "package": summary.get("package"),
        "app_name": summary.get("app_name"),
        "version_name": summary.get("version_name"),
        "version_code": summary.get("version_code"),
        "permissions_count": len(summary.get("permissions") or []),
        "dangerous_permissions": summary.get("dangerous_permissions") or [],
        "component_counts": {
            key: len(value or [])
            for key, value in components.items()
        },
    }


def run_phase1_multi(
    primary_apk: Path,
    all_apks: list[Path],
    workspace: Path,
    *,
    force: bool = False,
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase1_manifest")
    base_output_path = output_dir / "manifest_summary.json"
    split_output_path = output_dir / "split_manifest_summary.json"

    if base_output_path.exists() and split_output_path.exists() and not force:
        return PhaseResult(
            name="phase1_manifest",
            success=True,
            output_paths=[base_output_path, split_output_path],
            details={"cached": True},
        )

    base_summary = _extract_manifest_summary(primary_apk)
    split_summaries = [_extract_manifest_summary(path) for path in all_apks]

    safe_write_json(base_output_path, base_summary)
    safe_write_json(
        split_output_path,
        {
            "primary_apk": str(primary_apk),
            "apk_count": len(all_apks),
            "splits": split_summaries,
            "brief": [_brief_manifest(item) for item in split_summaries],
        },
    )

    return PhaseResult(
        name="phase1_manifest",
        success=bool(base_summary.get("success")),
        output_paths=[base_output_path, split_output_path],
        details={
            "package": base_summary.get("package"),
            "app_name": base_summary.get("app_name"),
            "permission_count": len(base_summary.get("permissions") or []),
            "dangerous_permission_count": len(base_summary.get("dangerous_permissions") or []),
            "split_manifest_count": sum(1 for item in split_summaries if item.get("success")),
        },
        error=base_summary.get("error"),
    )


def run_phase1(apk_path: Path, workspace: Path, *, force: bool = False) -> PhaseResult:
    return run_phase1_multi(apk_path, [apk_path], workspace, force=force)
