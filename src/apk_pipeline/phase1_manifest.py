"""Phase 1: manifest and package metadata extraction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import PhaseResult
from .run_context import (
    build_phase_cache_spec,
    cached_phase_result,
    load_valid_phase_cache,
    write_phase_cache,
)
from .utils import ensure_dir, safe_write_json


PHASE_SCHEMA = "2026-07-24.phase1.v4"
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
FIELD_WEIGHTS = {
    "package": 0.18,
    "app_name": 0.04,
    "version_name": 0.08,
    "version_code": 0.08,
    "manifest_xml": 0.18,
    "sdk.min_sdk": 0.06,
    "sdk.target_sdk": 0.08,
    "components.activities": 0.05,
    "components.services": 0.05,
    "components.receivers": 0.05,
    "components.providers": 0.05,
    "permissions": 0.05,
    "libraries": 0.025,
    "features": 0.025,
}
BASE_REQUIRED_FIELDS = {
    "package",
    "version_name",
    "version_code",
    "manifest_xml",
    "sdk.min_sdk",
    "sdk.target_sdk",
    "components.activities",
    "components.services",
    "components.receivers",
    "components.providers",
}
CRITICAL_FIELDS = {"package", "manifest_xml"}


def _call_tracked(
    apk_obj: Any,
    method: str,
    field: str,
    field_status: dict[str, dict[str, Any]],
    field_warnings: list[dict[str, Any]],
    *,
    default: Any = None,
    empty_is_valid: bool = False,
    required: bool = False,
) -> Any:
    value = getattr(apk_obj, method, None)
    if not callable(value):
        field_status[field] = {
            "status": "unsupported",
            "method": method,
            "required": required,
        }
        field_warnings.append(
            {
                "field": field,
                "status": "unsupported",
                "method": method,
                "message": "Androguard parser does not expose this field.",
            }
        )
        return default
    try:
        result = value()
    except Exception as exc:
        field_status[field] = {
            "status": "error",
            "method": method,
            "required": required,
            "error": f"{type(exc).__name__}: {exc}",
        }
        field_warnings.append(
            {
                "field": field,
                "status": "error",
                "method": method,
                "message": f"{type(exc).__name__}: {exc}",
            }
        )
        return default
    missing = result is None or (
        not empty_is_valid and isinstance(result, str) and not result.strip()
    )
    if missing:
        field_status[field] = {
            "status": "missing",
            "method": method,
            "required": required,
        }
        field_warnings.append(
            {
                "field": field,
                "status": "missing",
                "method": method,
                "required": required,
                "message": (
                    "Required manifest field is empty."
                    if required
                    else "Optional manifest field is empty."
                ),
            }
        )
        return default
    field_status[field] = {
        "status": "success",
        "method": method,
        "required": required,
    }
    return result


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


def _component_summary(
    apk_obj: Any,
    field_status: dict[str, dict[str, Any]],
    field_warnings: list[dict[str, Any]],
) -> dict[str, list[str]]:
    components: dict[str, list[str]] = {}
    for component, method in (
        ("activities", "get_activities"),
        ("services", "get_services"),
        ("receivers", "get_receivers"),
        ("providers", "get_providers"),
    ):
        value = _call_tracked(
            apk_obj,
            method,
            f"components.{component}",
            field_status,
            field_warnings,
            default=[],
            empty_is_valid=True,
            required=True,
        )
        components[component] = _stringify_list(value)
    return components


def _sdk_summary(
    apk_obj: Any,
    field_status: dict[str, dict[str, Any]],
    field_warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    sdk: dict[str, Any] = {}
    for field, method, required in (
        ("min_sdk", "get_min_sdk_version", True),
        ("target_sdk", "get_target_sdk_version", True),
        ("max_sdk", "get_max_sdk_version", False),
    ):
        sdk[field] = _call_tracked(
            apk_obj,
            method,
            f"sdk.{field}",
            field_status,
            field_warnings,
            required=required,
        )
    return sdk


def _manifest_xml(
    apk_obj: Any,
    field_status: dict[str, dict[str, Any]],
    field_warnings: list[dict[str, Any]],
) -> str:
    manifest = _call_tracked(
        apk_obj,
        "get_android_manifest_xml",
        "manifest_xml",
        field_status,
        field_warnings,
        required=True,
    )
    if manifest is None:
        return ""
    try:
        xml, serializer = _serialize_manifest_xml(manifest)
    except Exception as exc:
        field_status["manifest_xml"] = {
            "status": "error",
            "method": "get_android_manifest_xml.serialize",
            "required": True,
            "error": f"{type(exc).__name__}: {exc}",
        }
        field_warnings.append(
            {
                "field": "manifest_xml",
                "status": "error",
                "method": "get_android_manifest_xml.serialize",
                "message": f"{type(exc).__name__}: {exc}",
            }
        )
        return ""
    if not xml:
        field_status["manifest_xml"] = {
            "status": "missing",
            "method": serializer,
            "required": True,
        }
        field_warnings.append(
            {
                "field": "manifest_xml",
                "status": "missing",
                "method": serializer,
                "message": "Decoded AndroidManifest.xml is empty.",
            }
        )
        return ""
    field_status["manifest_xml"] = {
        "status": "success",
        "method": serializer,
        "required": True,
    }
    return xml


def _serialize_manifest_xml(manifest: Any) -> tuple[str, str]:
    """Serialize manifest nodes returned by supported Androguard versions."""

    if isinstance(manifest, str):
        return manifest, "get_android_manifest_xml"
    if isinstance(manifest, bytes):
        return (
            manifest.decode("utf-8", errors="replace"),
            "get_android_manifest_xml.decode",
        )

    toxml = getattr(manifest, "toxml", None)
    if callable(toxml):
        value = toxml()
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if not isinstance(value, str):
            raise TypeError(
                "get_android_manifest_xml().toxml() returned "
                f"{type(value).__name__}, expected str or bytes"
            )
        return value, "get_android_manifest_xml.toxml"

    try:
        from lxml import etree

        if etree.iselement(manifest):
            return (
                etree.tostring(manifest, encoding="unicode"),
                "get_android_manifest_xml/lxml.etree.tostring",
            )
    except ImportError:
        pass

    try:
        from xml.etree import ElementTree

        return (
            ElementTree.tostring(manifest, encoding="unicode"),
            "get_android_manifest_xml/xml.etree.ElementTree.tostring",
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise TypeError(
            "Unsupported Android manifest XML object: "
            f"{type(manifest).__module__}.{type(manifest).__name__}"
        ) from exc


def _completeness_score(field_status: dict[str, dict[str, Any]]) -> float:
    score = sum(
        weight
        for field, weight in FIELD_WEIGHTS.items()
        if (field_status.get(field) or {}).get("status") == "success"
    )
    return round(score, 4)


def _extract_manifest_summary(apk_path: Path) -> dict[str, Any]:
    try:
        apk_obj = _build_apk_parser(apk_path)
    except Exception as exc:
        return {
            "apk": str(apk_path),
            "success": False,
            "status": "failed",
            "parser_success": False,
            "completeness_score": 0.0,
            "field_status": {},
            "field_warnings": [
                {
                    "field": "parser",
                    "status": "error",
                    "method": "APK",
                    "message": f"{type(exc).__name__}: {exc}",
                }
            ],
            "error": repr(exc),
        }

    field_status: dict[str, dict[str, Any]] = {}
    field_warnings: list[dict[str, Any]] = []
    package = _call_tracked(
        apk_obj,
        "get_package",
        "package",
        field_status,
        field_warnings,
        required=True,
    )
    app_name = _call_tracked(
        apk_obj,
        "get_app_name",
        "app_name",
        field_status,
        field_warnings,
    )
    version_name = _call_tracked(
        apk_obj,
        "get_androidversion_name",
        "version_name",
        field_status,
        field_warnings,
        required=True,
    )
    version_code = _call_tracked(
        apk_obj,
        "get_androidversion_code",
        "version_code",
        field_status,
        field_warnings,
        required=True,
    )
    permissions = _stringify_list(
        _call_tracked(
            apk_obj,
            "get_permissions",
            "permissions",
            field_status,
            field_warnings,
            default=[],
            empty_is_valid=True,
        )
    )
    dangerous_permissions = [
        permission
        for permission in permissions
        if any(marker in permission.upper() for marker in DANGEROUS_PERMISSION_MARKERS)
    ]

    manifest_xml = _manifest_xml(apk_obj, field_status, field_warnings)
    components = _component_summary(apk_obj, field_status, field_warnings)
    sdk = _sdk_summary(apk_obj, field_status, field_warnings)
    libraries = _stringify_list(
        _call_tracked(
            apk_obj,
            "get_libraries",
            "libraries",
            field_status,
            field_warnings,
            default=[],
            empty_is_valid=True,
        )
    )
    features = _stringify_list(
        _call_tracked(
            apk_obj,
            "get_features",
            "features",
            field_status,
            field_warnings,
            default=[],
            empty_is_valid=True,
        )
    )
    critical_failures = [
        field
        for field in CRITICAL_FIELDS
        if (field_status.get(field) or {}).get("status") != "success"
    ]
    required_failures = [
        field
        for field in BASE_REQUIRED_FIELDS
        if (field_status.get(field) or {}).get("status") != "success"
    ]
    if critical_failures:
        status = "failed"
    elif required_failures:
        status = "partial"
    else:
        status = "success"
    failure_reason = None
    if critical_failures:
        failure_reason = (
            "Critical manifest fields unavailable: "
            + ", ".join(sorted(critical_failures))
        )

    payload: dict[str, Any] = {
        "apk": str(apk_path),
        "success": status == "success",
        "status": status,
        "parser_success": True,
        "package": package,
        "app_name": app_name,
        "version_name": version_name,
        "version_code": version_code,
        "sdk": sdk,
        "permissions": permissions,
        "dangerous_permissions": dangerous_permissions,
        "components": components,
        "libraries": libraries,
        "features": features,
        "manifest_xml": manifest_xml,
        "field_status": field_status,
        "field_warnings": field_warnings,
        "critical_field_failures": critical_failures,
        "required_field_failures": required_failures,
        "completeness_score": _completeness_score(field_status),
        "error": failure_reason,
    }
    return payload


def _brief_manifest(summary: dict[str, Any]) -> dict[str, Any]:
    components = summary.get("components") or {}
    return {
        "apk": summary.get("apk"),
        "success": summary.get("success"),
        "status": summary.get("status"),
        "completeness_score": summary.get("completeness_score"),
        "field_warning_count": len(summary.get("field_warnings") or []),
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
    run_context: dict[str, Any] | None = None,
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase1_manifest")
    base_output_path = output_dir / "manifest_summary.json"
    split_output_path = output_dir / "split_manifest_summary.json"
    cache_path = output_dir / "cache_manifest.json"
    package_versions = ((run_context or {}).get("runtime") or {}).get("packages") or {}
    cache_spec = build_phase_cache_spec(
        phase="phase1_manifest",
        phase_schema=PHASE_SCHEMA,
        phase_config={"androguard_version": package_versions.get("androguard")},
        input_paths=all_apks,
        run_context=run_context,
    )

    output_paths = [base_output_path, split_output_path]
    if not force:
        cached = load_valid_phase_cache(cache_path, cache_spec, output_paths)
        if cached:
            return cached_phase_result("phase1_manifest", output_paths, cached)

    split_summaries = [_extract_manifest_summary(path) for path in all_apks]
    base_summary = next(
        (
            item
            for item in split_summaries
            if Path(str(item.get("apk"))).resolve() == primary_apk.resolve()
        ),
        None,
    )
    if base_summary is None:
        base_summary = _extract_manifest_summary(primary_apk)

    safe_write_json(base_output_path, base_summary)
    safe_write_json(
        split_output_path,
        {
            "primary_apk": str(primary_apk),
            "apk_count": len(all_apks),
            "splits": split_summaries,
            "brief": [_brief_manifest(item) for item in split_summaries],
            "completeness": {
                "average_score": round(
                    sum(
                        float(item.get("completeness_score") or 0.0)
                        for item in split_summaries
                    )
                    / len(split_summaries),
                    4,
                )
                if split_summaries
                else 0.0,
                "minimum_score": min(
                    (
                        float(item.get("completeness_score") or 0.0)
                        for item in split_summaries
                    ),
                    default=0.0,
                ),
                "success_count": sum(
                    1 for item in split_summaries if item.get("status") == "success"
                ),
                "partial_count": sum(
                    1 for item in split_summaries if item.get("status") == "partial"
                ),
                "failed_count": sum(
                    1 for item in split_summaries if item.get("status") == "failed"
                ),
            },
        },
    )

    failed_splits = [
        item for item in split_summaries if item.get("status") == "failed"
    ]
    partial_splits = [
        item for item in split_summaries if item.get("status") == "partial"
    ]
    if base_summary.get("status") == "failed":
        status = "failed"
    elif base_summary.get("status") == "partial" or failed_splits:
        status = "partial"
    else:
        status = "success"
    result = PhaseResult(
        name="phase1_manifest",
        success=status == "success",
        status=status,
        output_paths=output_paths,
        details={
            "package": base_summary.get("package"),
            "app_name": base_summary.get("app_name"),
            "permission_count": len(base_summary.get("permissions") or []),
            "dangerous_permission_count": len(base_summary.get("dangerous_permissions") or []),
            "completeness_score": base_summary.get("completeness_score", 0.0),
            "field_warning_count": len(base_summary.get("field_warnings") or []),
            "split_manifest_count": sum(
                1 for item in split_summaries if item.get("parser_success")
            ),
            "failed_split_manifest_count": len(failed_splits),
            "partial_split_manifest_count": len(partial_splits),
        },
        error=base_summary.get("error"),
        warnings=[
            f"{item.get('apk')}: {item.get('error') or ', '.join(item.get('critical_field_failures') or ['manifest_parse_failed'])}"
            for item in failed_splits
        ]
        + [
            f"{primary_apk}: {warning.get('field')}: {warning.get('message')}"
            for warning in (base_summary.get("field_warnings") or [])
            if warning.get("status") in {"error", "missing", "unsupported"}
        ],
    )
    write_phase_cache(cache_path, cache_spec, output_paths, result)
    return result


def run_phase1(apk_path: Path, workspace: Path, *, force: bool = False) -> PhaseResult:
    return run_phase1_multi(apk_path, [apk_path], workspace, force=force)
