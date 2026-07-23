"""Phase 4: raw resource, model, and asset inventory."""

from __future__ import annotations

import zipfile
import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from .capability_taxonomy import capability_names, classify_path, classify_text
from .evidence import capability_confidence, compact_list, token_fingerprint, unit_id
from .models import PhaseResult
from .run_context import (
    build_phase_cache_spec,
    cached_phase_result,
    load_valid_phase_cache,
    write_phase_cache,
)
from .tflite_parser import MODEL_EXTENSIONS, parse_model_metadata
from .utils import ensure_dir, safe_write_json, validate_zip


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
MODEL_READ_LIMIT = 128_000_000
RESOURCE_READ_LIMIT = 500_000
PHASE_SCHEMA = "2026-07-23.phase4.v3"


def _read_entry(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    prefix_limit: int,
) -> tuple[str, bytes]:
    digest = hashlib.sha256()
    prefix = bytearray()
    with archive.open(info, "r") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
            if len(prefix) < prefix_limit:
                remaining = prefix_limit - len(prefix)
                prefix.extend(chunk[:remaining])
    return digest.hexdigest(), bytes(prefix)


def _entry_record(
    archive: zipfile.ZipFile,
    apk_path: Path,
    info: zipfile.ZipInfo,
    *,
    kind: str,
) -> dict[str, Any]:
    path_hits = classify_path(info.filename)
    read_limit = MODEL_READ_LIMIT if kind == "model" else RESOURCE_READ_LIMIT
    entry_sha256, data = _read_entry(
        archive,
        info,
        prefix_limit=read_limit,
    )
    record: dict[str, Any] = {
        "apk": str(apk_path),
        "path": info.filename,
        "kind": kind,
        "size_bytes": info.file_size,
        "sha256": entry_sha256,
        "path_capabilities": path_hits,
        "content_bytes_read": len(data),
        "content_truncated": info.file_size > len(data),
    }

    if kind == "model":
        record["model_metadata"] = parse_model_metadata(
            info.filename,
            data,
            complete=info.file_size <= len(data),
        )
    else:
        if data:
            text_sample = data.decode("utf-8", errors="ignore")
            text_hits = classify_text(text_sample[:100_000])
            if text_hits:
                record["text_capabilities"] = text_hits
            if text_sample:
                record["text_sample"] = text_sample[:2000]

    return record


def _is_model(path: str) -> bool:
    lower = path.lower()
    suffix = Path(path).suffix.lower()
    if suffix in MODEL_EXTENSIONS:
        return True
    return suffix in {".bin", ".dat", ".weights"} and any(
        marker in lower
        for marker in (
            "model",
            "weight",
            "tensor",
            "network",
            "classifier",
            "segment",
            "detect",
            "recogn",
            "ocr",
        )
    )


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

    infos = validate_zip(apk_path)
    candidates: list[tuple[int, str, zipfile.ZipInfo, str]] = []
    for info in infos:
        if info.is_dir():
            continue
        lower_name = info.filename.lower()
        if _is_model(lower_name):
            kind = "model"
        elif _is_resource_candidate(lower_name):
            kind = "resource_candidate"
        else:
            continue
        path_hits = classify_path(info.filename)
        capability_score = 0
        for details in path_hits.values():
            if not isinstance(details, dict):
                continue
            raw_score = details.get("score")
            try:
                capability_score += int(str(raw_score or 0))
            except ValueError:
                continue
        marker_bonus = 20 if kind == "model" else 0
        candidates.append(
            (
                -(marker_bonus + capability_score),
                info.filename,
                info,
                kind,
            )
        )
    candidates.sort(key=lambda item: (item[0], item[1]))
    model_candidates = [item for item in candidates if item[3] == "model"]
    resource_candidates = [
        item for item in candidates if item[3] == "resource_candidate"
    ]
    selected = [
        *model_candidates,
        *resource_candidates[:MAX_RESOURCE_CANDIDATES_PER_APK],
    ]

    with zipfile.ZipFile(apk_path, "r") as zf:
        for _, _, info, kind in selected:
            record = _entry_record(zf, apk_path, info, kind=kind)
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
        "model_candidate_discovered_count": len(model_candidates),
        "resource_candidate_discovered_count": len(resource_candidates),
        "resource_candidate_excluded_count": max(
            0,
            len(resource_candidates) - MAX_RESOURCE_CANDIDATES_PER_APK,
        ),
        "resource_selection_rule": (
            "capability_and_model_path_score_then_path_name"
        ),
        "capability_counts": dict(sorted(capability_counts.items())),
    }
    return records, summary


def _record_capabilities(record: dict[str, Any]) -> list[str]:
    values: set[str] = set((record.get("path_capabilities") or {}).keys())
    values.update((record.get("text_capabilities") or {}).keys())
    metadata = record.get("model_metadata") or {}
    values.update((metadata.get("capabilities") or {}).keys())
    return capability_names(values)


def build_model_evidence_units(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    for record in records:
        if record.get("kind") != "model":
            continue
        metadata = record.get("model_metadata") or {}
        structured_graph = metadata.get("structured_graph") or {}
        capabilities = _record_capabilities(record)
        strings_sample = metadata.get("strings_sample") or []
        operator_hints = metadata.get("operator_hints") or []
        fingerprint_text = "\n".join(
            [
                str(record.get("path") or ""),
                str(metadata.get("format") or ""),
                " ".join(operator_hints),
                " ".join(strings_sample[:100]),
            ]
        )
        units.append(
            {
                "unit_id": unit_id("model", record.get("apk"), record.get("path"), record.get("sha256")),
                "phase": "phase4_resources",
                "kind": "model",
                "apk": record.get("apk"),
                "path": record.get("path"),
                "format": metadata.get("format"),
                "size_bytes": record.get("size_bytes"),
                "sha256": record.get("sha256"),
                "tflite_magic_present": metadata.get("tflite_magic_present"),
                "tflite_magic_offsets": metadata.get("tflite_magic_offsets") or [],
                "embedded_tflite_magic_present": metadata.get("embedded_tflite_magic_present"),
                "likely_wrapped_or_encrypted": metadata.get("likely_wrapped_or_encrypted"),
                "header_hex": metadata.get("header_hex"),
                "entropy_first_mb": metadata.get("entropy_first_mb"),
                "operator_hints": compact_list(operator_hints, 80),
                "structured_parser_status": structured_graph.get("status"),
                "graph_fingerprint": structured_graph.get("graph_fingerprint"),
                "subgraph_count": structured_graph.get("subgraph_count"),
                "operator_count": structured_graph.get("operator_count"),
                "tensor_count": structured_graph.get("tensor_count"),
                "operator_counts": structured_graph.get("operator_counts") or {},
                "subgraphs": structured_graph.get("subgraphs") or [],
                "metadata_strings": compact_list(strings_sample, 80),
                "capabilities": capabilities,
                "token_fingerprint": token_fingerprint(fingerprint_text),
                "confidence": capability_confidence(capabilities, len(operator_hints) + len(strings_sample)),
            }
        )
    return units


def build_resource_evidence_units(records: list[dict[str, Any]], *, max_units: int = 2000) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    for record in records:
        if record.get("kind") != "resource_candidate":
            continue
        capabilities = _record_capabilities(record)
        text_sample = str(record.get("text_sample") or "")
        fingerprint_text = "\n".join(
            [
                str(record.get("path") or ""),
                " ".join(capabilities),
                text_sample[:5000],
            ]
        )
        units.append(
            {
                "unit_id": unit_id("resource", record.get("apk"), record.get("path"), record.get("sha256")),
                "phase": "phase4_resources",
                "kind": "resource",
                "apk": record.get("apk"),
                "path": record.get("path"),
                "size_bytes": record.get("size_bytes"),
                "sha256": record.get("sha256"),
                "capabilities": capabilities,
                "text_sample": text_sample[:2000],
                "token_fingerprint": token_fingerprint(fingerprint_text),
                "confidence": capability_confidence(capabilities, 1 if text_sample else 0),
            }
        )
    units.sort(
        key=lambda item: (
            -float(item.get("confidence") or 0),
            item.get("path") or "",
        )
    )
    return units[:max_units]


def run_phase4_resources(
    all_apks: list[Path],
    workspace: Path,
    *,
    force: bool = False,
    run_context: dict[str, Any] | None = None,
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase4_resources")
    output_path = output_dir / "resource_inventory.json"
    model_units_path = output_dir / "model_evidence_units.json"
    resource_units_path = output_dir / "resource_evidence_units.json"
    cache_path = output_dir / "cache_manifest.json"

    output_paths = [output_path, model_units_path, resource_units_path]
    cache_spec = build_phase_cache_spec(
        phase="phase4_resources",
        phase_schema=PHASE_SCHEMA,
        phase_config={
            "model_read_limit": MODEL_READ_LIMIT,
            "resource_read_limit": RESOURCE_READ_LIMIT,
            "max_resource_candidates_per_apk": MAX_RESOURCE_CANDIDATES_PER_APK,
        },
        input_paths=all_apks,
        run_context=run_context,
    )
    if not force:
        cached = load_valid_phase_cache(cache_path, cache_spec, output_paths)
        if cached:
            return cached_phase_result("phase4_resources", output_paths, cached)

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
        "selection_telemetry": {
            "resource_candidate_discovered_count": sum(
                item["resource_candidate_discovered_count"] for item in summaries
            ),
            "resource_candidate_selected_count": sum(
                item["resource_candidate_count"] for item in summaries
            ),
            "resource_candidate_excluded_count": sum(
                item["resource_candidate_excluded_count"] for item in summaries
            ),
            "selection_rule": "capability_and_model_path_score_then_path_name",
        },
        "records": all_records,
        "warnings": warnings,
    }
    model_units = build_model_evidence_units(all_records)
    resource_units = build_resource_evidence_units(all_records)
    payload["model_evidence_units_path"] = str(model_units_path)
    payload["resource_evidence_units_path"] = str(resource_units_path)
    payload["model_evidence_unit_count"] = len(model_units)
    payload["resource_evidence_unit_count"] = len(resource_units)
    safe_write_json(output_path, payload)
    safe_write_json(model_units_path, model_units)
    safe_write_json(resource_units_path, resource_units)

    successful_apk_count = len(summaries)
    failed_apk_count = len(all_apks) - successful_apk_count
    if all_apks and successful_apk_count == 0:
        status = "failed"
    elif failed_apk_count:
        status = "partial"
    else:
        status = "success"
    result = PhaseResult(
        name="phase4_resources",
        success=status == "success",
        status=status,
        output_paths=output_paths,
        details={
            "successful_apk_count": successful_apk_count,
            "failed_apk_count": failed_apk_count,
            "records_count": len(all_records),
            "model_count": sum(item["model_count"] for item in summaries),
            "resource_candidate_count": sum(item["resource_candidate_count"] for item in summaries),
            "model_evidence_unit_count": len(model_units),
            "resource_evidence_unit_count": len(resource_units),
            "aggregate_capabilities": payload["aggregate_capabilities"],
        },
        warnings=warnings,
    )
    write_phase_cache(cache_path, cache_spec, output_paths, result)
    return result
