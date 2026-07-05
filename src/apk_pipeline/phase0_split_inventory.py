"""Phase 0: inventory APK splits before deeper analysis."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

from .capability_taxonomy import classify_path, capability_names
from .models import PhaseResult
from .utils import ensure_dir, safe_write_json, sha256_file


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


def classify_split_type(apk_path: Path) -> str:
    name = apk_path.name.lower()
    stem = apk_path.stem.lower()

    if name == "base.apk" or stem == "base":
        return "base"
    if "config." in stem:
        if any(marker in stem for marker in ABI_MARKERS):
            return "config_abi"
        if any(marker in stem for marker in DENSITY_MARKERS):
            return "config_density"
        return "config_other"
    if stem.startswith("split_config."):
        return "config_other"
    if stem.startswith("split_") or stem.startswith("feature_"):
        return "dynamic_feature"
    if len(stem) in (2, 3) or stem.startswith("config."):
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
        "sha256": sha256_file(apk_path),
        "size_bytes": apk_path.stat().st_size,
        "is_primary": apk_path.resolve() == primary_apk.resolve(),
        "split_type": classify_split_type(apk_path),
        "manifest_present": False,
        "dex_files": [],
        "native_libraries": [],
        "model_files": [],
        "resource_candidates": [],
        "capabilities": [],
    }

    entries: list[str] = []
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                lower_name = name.lower()
                entries.append(name)

                if lower_name == "androidmanifest.xml":
                    record["manifest_present"] = True
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
                        break
    except zipfile.BadZipFile:
        record["zip_error"] = "bad_zip_file"

    record["dex_count"] = len(record["dex_files"])
    record["native_library_count"] = len(record["native_libraries"])
    record["model_file_count"] = len(record["model_files"])
    record["resource_candidate_count"] = len(record["resource_candidates"])
    record["capabilities"] = _classify_entries(entries)
    return record


def run_phase0(
    all_apks: list[Path],
    primary_apk: Path,
    workspace: Path,
    *,
    force: bool = False,
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase0_split_inventory")
    output_path = output_dir / "split_inventory.json"

    if output_path.exists() and not force:
        return PhaseResult(
            name="phase0_split_inventory",
            success=True,
            output_paths=[output_path],
            details={"cached": True},
        )

    records = [_summarize_apk(path, primary_apk) for path in all_apks]
    payload = {
        "primary_apk": str(primary_apk),
        "apk_count": len(records),
        "splits": records,
        "summary": {
            "has_splits": len(records) > 1,
            "dex_apk_count": sum(1 for item in records if item["dex_count"] > 0),
            "native_apk_count": sum(1 for item in records if item["native_library_count"] > 0),
            "model_apk_count": sum(1 for item in records if item["model_file_count"] > 0),
            "split_types": sorted({item["split_type"] for item in records}),
            "capabilities": capability_names(
                capability
                for item in records
                for capability in item.get("capabilities", [])
            ),
        },
    }
    safe_write_json(output_path, payload)

    return PhaseResult(
        name="phase0_split_inventory",
        success=True,
        output_paths=[output_path],
        details=payload["summary"],
    )
