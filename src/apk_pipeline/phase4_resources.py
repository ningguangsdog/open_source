"""Phase 4: raw resource, model, and asset inventory."""

from __future__ import annotations

import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from .capability_taxonomy import capability_names, classify_path, classify_text
from .models import PhaseResult
from .tflite_parser import MODEL_EXTENSIONS, parse_model_metadata
from .utils import ensure_dir, read_zip_entry_prefix, safe_write_json, zip_entry_sha256


RESOURCE_EXTENSIONS = (
    ".json",
    ".xml",
    ".proto",
    ".bin",
    ".dat",
    ".txt",
    ".csv",
    ".dict",
    ".dic",
    ".traineddata",
    ".model",
    ".labels",
    ".conf",
)
MAX_RESOURCE_CANDIDATES_PER_APK = 800
MODEL_READ_LIMIT = 8_000_000
RESOURCE_READ_LIMIT = 500_000


def _entry_record(apk_path: Path, info: zipfile.ZipInfo, *, kind: str) -> dict[str, Any]:
    path_hits = classify_path(info.filename)
    record: dict[str, Any] = {
        "apk": str(apk_path),
        "path": info.filename,
        "kind": kind,
        "size_bytes": info.file_size,
        "sha256": zip_entry_sha256(apk_path, info.filename),
        "path_capabilities": path_hits,
    }

    if kind == "model":
        data = read_zip_entry_prefix(apk_path, info.filename, limit=MODEL_READ_LIMIT)
        record["model_metadata"] = parse_model_metadata(info.filename, data)
    else:
        data = read_zip_entry_prefix(apk_path, info.filename, limit=RESOURCE_READ_LIMIT)
        if data:
            text_sample = data.decode("utf-8", errors="ignore")
            text_hits = classify_text(text_sample[:100_000])
            if text_hits:
                record["text_capabilities"] = text_hits
            if text_sample:
                record["text_sample"] = text_sample[:2000]

    return record


def _is_model(path: str) -> bool:
    return Path(path).suffix.lower() in MODEL_EXTENSIONS


def _is_resource_candidate(path: str) -> bool:
    lower = path.lower()
    if lower.endswith(RESOURCE_EXTENSIONS):
        return bool(classify_path(path)) or any(
            marker in lower
            for marker in (
                "model",
                "label",
                "ocr",
                "scan",
                "pdf",
                "crypto",
                "rule",
                "dict",
                "language",
                "classifier",
            )
        )
    return False


def _scan_apk(apk_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    counters: Counter[str] = Counter()
    capability_counts: Counter[str] = Counter()

    with zipfile.ZipFile(apk_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            lower_name = info.filename.lower()
            if _is_model(lower_name):
                kind = "model"
            elif _is_resource_candidate(lower_name):
                kind = "resource_candidate"
            else:
                continue

            if kind == "resource_candidate" and counters[kind] >= MAX_RESOURCE_CANDIDATES_PER_APK:
                continue
            record = _entry_record(apk_path, info, kind=kind)
            records.append(record)
            counters[kind] += 1

            capability_sources = [record.get("path_capabilities") or {}]
            if record.get("model_metadata"):
                capability_sources.append(record["model_metadata"].get("capabilities") or {})
            if record.get("text_capabilities"):
                capability_sources.append(record.get("text_capabilities") or {})
            for source in capability_sources:
                capability_counts.update(source.keys())

    summary = {
        "apk": str(apk_path),
        "model_count": counters["model"],
        "resource_candidate_count": counters["resource_candidate"],
        "capability_counts": dict(sorted(capability_counts.items())),
    }
    return records, summary


def run_phase4_resources(
    all_apks: list[Path],
    workspace: Path,
    *,
    force: bool = False,
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase4_resources")
    output_path = output_dir / "resource_inventory.json"

    if output_path.exists() and not force:
        return PhaseResult(
            name="phase4_resources",
            success=True,
            output_paths=[output_path],
            details={"cached": True},
        )

    all_records: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    warnings: list[str] = []
    aggregate_capabilities: Counter[str] = Counter()

    for apk_path in all_apks:
        try:
            records, summary = _scan_apk(apk_path)
        except Exception as exc:
            warnings.append(f"{apk_path}: {exc!r}")
            continue
        all_records.extend(records)
        summaries.append(summary)
        aggregate_capabilities.update(summary["capability_counts"])

    payload = {
        "apk_count": len(all_apks),
        "records_count": len(all_records),
        "summary_by_apk": summaries,
        "aggregate_capability_counts": dict(sorted(aggregate_capabilities.items())),
        "aggregate_capabilities": capability_names(aggregate_capabilities.keys()),
        "records": all_records,
        "warnings": warnings,
    }
    safe_write_json(output_path, payload)

    return PhaseResult(
        name="phase4_resources",
        success=True,
        output_paths=[output_path],
        details={
            "records_count": len(all_records),
            "model_count": sum(item["model_count"] for item in summaries),
            "resource_candidate_count": sum(item["resource_candidate_count"] for item in summaries),
            "aggregate_capabilities": payload["aggregate_capabilities"],
        },
        warnings=warnings,
    )
