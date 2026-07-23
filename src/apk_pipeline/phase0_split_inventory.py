"""Phase 0: inventory APK splits before deeper analysis."""

from __future__ import annotations

import zipfile
from pathlib import Path
import re
from typing import Any

from .capability_taxonomy import classify_path, capability_names
from .models import PhaseResult
from .run_context import (
    build_phase_cache_spec,
    cached_phase_result,
    load_valid_phase_cache,
    write_phase_cache,
)
from .utils import ensure_dir, safe_write_json, sha256_file, validate_zip


PHASE_SCHEMA = "2026-07-23.phase0.v3"
DENSITY_MARKERS = (
    "ldpi",
    "mdpi",
    "hdpi",
    "xhdpi",
    "xxhdpi",
    "xxxhdpi",
    "tvdpi",
    "nodpi",
)
ABI_MARKERS = ("arm64", "armeabi", "x86", "mips", "riscv")
MODEL_EXTENSIONS = (".tflite", ".lite", ".onnx", ".pb", ".pt", ".pth", ".mlmodel")
RESOURCE_EXTENSIONS = (
    ".json",
    ".xml",
    ".proto",
    ".bin",
    ".dat",
    ".txt",
    ".traineddata",
    ".dic",
    ".dict",
)
LANGUAGE_CONFIG_RE = re.compile(
    r"^(?:split_)?config[._-](?:b[+])?[a-z]{2,3}"
    r"(?:[._+-](?:r)?[a-z0-9]{2,8})*$",
    re.IGNORECASE,
)


def classify_split_type(apk_path: Path) -> str:
    name = apk_path.name.lower()
    stem = apk_path.stem.lower()

    if name == "base.apk" or stem == "base":
        return "base"
    if stem.startswith(("split_config.", "split_config_", "config.", "config_")):
        if any(marker in stem for marker in ABI_MARKERS):
            return "config_abi"
        if any(marker in stem for marker in DENSITY_MARKERS):
            return "config_density"
        if LANGUAGE_CONFIG_RE.fullmatch(stem):
            return "config_language"
        return "config_other"
    if stem.startswith("split_") or stem.startswith("feature_"):
        return "dynamic_feature"
    if re.fullmatch(r"[a-z]{2,3}(?:[-_]r?[a-z]{2})?", stem, re.IGNORECASE):
        return "config_language"
    return "single_or_unknown"


def _classify_entries(entries: list[str]) -> list[str]:
    capabilities: set[str] = set()
    for entry in entries:
        capabilities.update(classify_path(entry).keys())
    return capability_names(capabilities)


def _summarize_apk(apk_path: Path, primary_apk: Path) -> dict[str, Any]:
    record: dict[str, Any] = {
        "file": str(apk_path),
        "name": apk_path.name,
        "is_primary": apk_path.resolve() == primary_apk.resolve(),
        "split_type": classify_split_type(apk_path),
        "exists": apk_path.is_file(),
        "zip_valid": False,
        "manifest_present": False,
        "manifest_readable": False,
        "dex_files": [],
        "native_libraries": [],
        "model_files": [],
        "resource_candidates": [],
        "capabilities": [],
        "validation_errors": [],
        "success": False,
    }

    entries: list[str] = []
    try:
        record["sha256"] = sha256_file(apk_path)
        record["size_bytes"] = apk_path.stat().st_size
        infos = validate_zip(apk_path)
        if not infos:
            record["validation_errors"].append("empty_apk_archive")
        else:
            zf = zipfile.ZipFile(apk_path)
        if infos:
            with zf:
                bad_entry = zf.testzip()
                if bad_entry:
                    record["validation_errors"].append(f"crc_error:{bad_entry}")
                else:
                    record["zip_valid"] = True
                for info in infos:
                    if info.is_dir():
                        continue
                    name = info.filename
                    lower_name = name.lower()
                    entries.append(name)

                    if lower_name == "androidmanifest.xml":
                        record["manifest_present"] = True
                        try:
                            record["manifest_readable"] = bool(zf.read(info))
                        except Exception as exc:
                            record["validation_errors"].append(
                                f"manifest_read_error:{type(exc).__name__}:{exc}"
                            )
                    elif lower_name.endswith(".dex"):
                        record["dex_files"].append(name)
                    elif lower_name.startswith("lib/") and lower_name.endswith(".so"):
                        record["native_libraries"].append(
                            {
                                "path": name,
                                "size_bytes": info.file_size,
                            }
                        )
                    elif lower_name.endswith(MODEL_EXTENSIONS):
                        record["model_files"].append(
                            {
                                "path": name,
                                "size_bytes": info.file_size,
                            }
                        )
                    elif lower_name.endswith(RESOURCE_EXTENSIONS):
                        hits = classify_path(name)
                        for capability, hit in hits.items():
                            record["resource_candidates"].append(
                                {
                                    "path": name,
                                    "size_bytes": info.file_size,
                                    "capability": capability,
                                    "hits": hit.get("hits", []),
                                }
                            )
    except FileNotFoundError:
        record["validation_errors"].append("apk_file_missing")
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        record["validation_errors"].append(
            f"invalid_zip:{type(exc).__name__}:{exc}"
        )
    except Exception as exc:
        record["validation_errors"].append(
            f"inventory_error:{type(exc).__name__}:{exc}"
        )

    record["dex_count"] = len(record["dex_files"])
    record["native_library_count"] = len(record["native_libraries"])
    record["model_file_count"] = len(record["model_files"])
    record["resource_candidate_count"] = len(record["resource_candidates"])
    record["capabilities"] = _classify_entries(entries)
    if not record["manifest_present"]:
        record["validation_errors"].append("android_manifest_missing")
    elif not record["manifest_readable"]:
        record["validation_errors"].append("android_manifest_empty_or_unreadable")
    record["success"] = bool(
        record["zip_valid"]
        and record["manifest_present"]
        and record["manifest_readable"]
        and not record["validation_errors"]
    )
    return record


def run_phase0(
    all_apks: list[Path],
    primary_apk: Path,
    workspace: Path,
    *,
    force: bool = False,
    run_context: dict[str, Any] | None = None,
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase0_split_inventory")
    output_path = output_dir / "split_inventory.json"
    cache_path = output_dir / "cache_manifest.json"
    cache_spec = build_phase_cache_spec(
        phase="phase0_split_inventory",
        phase_schema=PHASE_SCHEMA,
        phase_config={},
        input_paths=all_apks,
        run_context=run_context,
    )

    if not force:
        cached = load_valid_phase_cache(cache_path, cache_spec, [output_path])
        if cached:
            return cached_phase_result("phase0_split_inventory", [output_path], cached)

    records = [_summarize_apk(path, primary_apk) for path in all_apks]
    payload: dict[str, Any] = {
        "primary_apk": str(primary_apk),
        "apk_count": len(records),
        "splits": records,
        "summary": {
            "has_splits": len(records) > 1,
            "dex_apk_count": sum(1 for item in records if item["dex_count"] > 0),
            "native_apk_count": sum(1 for item in records if item["native_library_count"] > 0),
            "model_apk_count": sum(1 for item in records if item["model_file_count"] > 0),
            "manifest_missing_count": sum(
                1 for item in records if not item.get("manifest_present")
            ),
            "invalid_apk_count": sum(
                1 for item in records if not item.get("success")
            ),
            "split_types": sorted({item["split_type"] for item in records}),
            "capabilities": capability_names(
                capability
                for item in records
                for capability in item.get("capabilities", [])
            ),
        },
    }
    safe_write_json(output_path, payload)

    failed_records = [item for item in records if not item.get("success")]
    primary_record = next((item for item in records if item.get("is_primary")), None)
    if not records:
        status = "failed"
        error = "No APK files were provided for inventory."
    elif primary_record is None:
        status = "failed"
        error = "The selected primary APK is not present in the resolved input."
    elif not primary_record.get("manifest_present"):
        status = "failed"
        error = "The primary APK does not contain AndroidManifest.xml."
    elif not primary_record.get("success"):
        status = "failed"
        error = "The primary APK failed archive or manifest validation."
    elif failed_records:
        status = "partial"
        error = None
    else:
        status = "success"
        error = None
    result = PhaseResult(
        name="phase0_split_inventory",
        success=status == "success",
        status=status,
        output_paths=[output_path],
        details={
            **payload["summary"],
            "successful_apk_count": len(records) - len(failed_records),
            "failed_apk_count": len(failed_records),
        },
        error=error,
        warnings=[
            f"{item.get('file')}: {', '.join(item.get('validation_errors') or ['inventory_failed'])}"
            for item in failed_records
        ],
    )
    write_phase_cache(cache_path, cache_spec, [output_path], result)
    return result
