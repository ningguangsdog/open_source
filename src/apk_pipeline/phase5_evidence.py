"""Phase 5: compact research evidence packet for downstream review."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .capability_taxonomy import CAPABILITY_PATTERNS, capability_names
from .evidence import unit_id, write_jsonl
from .models import PhaseResult
from .utils import ensure_dir, safe_write_json, safe_write_text


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _capability_label(name: str) -> str:
    for pattern in CAPABILITY_PATTERNS:
        if pattern.name == name:
            return pattern.label
    return name


def _counter_from_dict(payload: dict[str, Any] | None) -> Counter[str]:
    counter: Counter[str] = Counter()
    for key, value in (payload or {}).items():
        try:
            counter[str(key)] += int(value)
        except Exception:
            counter[str(key)] += 1
    return counter


def _collect_capabilities(
    code_index: dict[str, Any],
    native_analysis: dict[str, Any],
    resource_inventory: dict[str, Any],
    split_inventory: dict[str, Any],
) -> dict[str, int]:
    counter: Counter[str] = Counter()
    counter.update(_counter_from_dict(code_index.get("capability_counts")))
    counter.update(_counter_from_dict(native_analysis.get("capability_counts")))
    counter.update(_counter_from_dict(resource_inventory.get("aggregate_capability_counts")))
    for split in split_inventory.get("splits") or []:
        counter.update(split.get("capabilities") or [])
    return dict(sorted(counter.items()))


def _extract_code_snippets(code_index: dict[str, Any], max_per_capability: int = 12) -> dict[str, list[dict[str, Any]]]:
    snippets: dict[str, list[dict[str, Any]]] = {}
    for capability, rows in (code_index.get("snippets_by_capability") or {}).items():
        snippets[capability] = rows[:max_per_capability]
    return snippets


def _extract_models(resource_inventory: dict[str, Any], max_models: int = 40) -> list[dict[str, Any]]:
    models: list[dict[str, Any]] = []
    for record in resource_inventory.get("records") or []:
        if record.get("kind") != "model":
            continue
        metadata = record.get("model_metadata") or {}
        models.append(
            {
                "apk": record.get("apk"),
                "path": record.get("path"),
                "size_bytes": record.get("size_bytes"),
                "sha256": record.get("sha256"),
                "format": metadata.get("format"),
                "tflite_magic_present": metadata.get("tflite_magic_present"),
                "operator_hints": metadata.get("operator_hints") or [],
                "capabilities": capability_names((metadata.get("capabilities") or {}).keys()),
                "strings_sample": (metadata.get("strings_sample") or [])[:20],
            }
        )
    return models[:max_models]


def _extract_native_targets(native_targets: dict[str, Any], max_targets: int = 50) -> list[dict[str, Any]]:
    return (native_targets.get("targets") or [])[:max_targets]


def _extract_urls(code_index: dict[str, Any], native_analysis: dict[str, Any]) -> dict[str, list[str]]:
    code_urls = list((code_index.get("urls") or {}).keys())[:100]
    native_urls: list[str] = []
    for record in native_analysis.get("libraries") or []:
        native_urls.extend(record.get("urls") or [])
    return {
        "code_urls": sorted(set(code_urls))[:100],
        "native_urls": sorted(set(native_urls))[:100],
    }


def _collect_evidence_units(workspace: Path) -> list[dict[str, Any]]:
    sources = [
        workspace / "phase2_jadx" / "java_evidence_units.json",
        workspace / "phase3_native" / "native_evidence_units.json",
        workspace / "phase4_resources" / "model_evidence_units.json",
        workspace / "phase4_resources" / "resource_evidence_units.json",
    ]
    units: list[dict[str, Any]] = []
    for source in sources:
        for row in _load_list(source):
            enriched = dict(row)
            enriched.setdefault("source_file", str(source))
            enriched.setdefault("unit_id", unit_id(source.name, len(units), row.get("kind"), row.get("file") or row.get("path")))
            units.append(enriched)
    units.sort(
        key=lambda item: (
            -float(item.get("confidence") or 0),
            item.get("phase") or "",
            item.get("kind") or "",
            item.get("unit_id") or "",
        )
    )
    return units


def _build_evidence_graph(units: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
    app_id = unit_id("app", manifest.get("package"), manifest.get("version_code"), manifest.get("version_name"))
    nodes: list[dict[str, Any]] = [
        {
            "id": app_id,
            "kind": "app",
            "label": manifest.get("package") or manifest.get("app_name") or "app",
        }
    ]
    edges: list[dict[str, Any]] = []
    native_libraries: dict[str, str] = {}

    for unit in units:
        uid = str(unit.get("unit_id"))
        nodes.append(
            {
                "id": uid,
                "kind": unit.get("kind"),
                "phase": unit.get("phase"),
                "label": unit.get("normalized_signature") or unit.get("name") or unit.get("path") or unit.get("file") or uid,
                "capabilities": unit.get("capabilities") or [],
                "confidence": unit.get("confidence"),
            }
        )
        edges.append({"source": app_id, "target": uid, "type": "contains"})
        if unit.get("kind") == "native_library":
            for key in [unit.get("name"), Path(str(unit.get("library") or "")).name]:
                if key:
                    native_libraries[str(key)] = uid

    for unit in units:
        if unit.get("kind") == "native_bridge":
            for library in unit.get("native_libraries") or []:
                candidates = [str(library), f"lib{library}.so", f"{library}.so"]
                for candidate in candidates:
                    target = native_libraries.get(candidate)
                    if target:
                        edges.append({"source": unit["unit_id"], "target": target, "type": "loads_native_library"})
                        break
        if unit.get("kind") == "native_target":
            target_library = native_libraries.get(Path(str(unit.get("library") or "")).name)
            if target_library:
                edges.append({"source": target_library, "target": unit["unit_id"], "type": "has_native_target"})

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


def _build_similarity_packet(
    manifest: dict[str, Any],
    split_inventory: dict[str, Any],
    capability_counts: dict[str, int],
    evidence_units: list[dict[str, Any]],
    graph_path: Path,
) -> dict[str, Any]:
    kind_counts: Counter[str] = Counter(str(unit.get("kind") or "unknown") for unit in evidence_units)
    high_value = [
        {
            "unit_id": unit.get("unit_id"),
            "kind": unit.get("kind"),
            "phase": unit.get("phase"),
            "label": unit.get("normalized_signature") or unit.get("name") or unit.get("path") or unit.get("file"),
            "capabilities": unit.get("capabilities") or [],
            "confidence": unit.get("confidence"),
            "token_fingerprint": unit.get("token_fingerprint"),
        }
        for unit in evidence_units[:250]
    ]
    return {
        "schema_version": "2026-07-05.similarity-ready.v1",
        "app": {
            "package": manifest.get("package"),
            "app_name": manifest.get("app_name"),
            "version_name": manifest.get("version_name"),
            "version_code": manifest.get("version_code"),
        },
        "input": {
            "apk_count": split_inventory.get("apk_count"),
            "split_types": ((split_inventory.get("summary") or {}).get("split_types") or []),
        },
        "capability_counts": capability_counts,
        "evidence_unit_count": len(evidence_units),
        "evidence_units_by_kind": dict(sorted(kind_counts.items())),
        "high_value_units": high_value,
        "graph_path": str(graph_path),
        "notes": [
            "This packet is intended for downstream review and similarity preparation.",
            "Hashes identify exact artifacts; token_fingerprint is a normalized static signal, not a similarity score.",
            "Native pseudocode appears when auto/deep native analysis selects targets and an automated adapter is available.",
        ],
    }


def _render_markdown(packet: dict[str, Any]) -> str:
    manifest = packet.get("manifest") or {}
    capabilities = packet.get("capability_counts") or {}
    lines: list[str] = []

    lines.append("# Mobile App Research Evidence Packet")
    lines.append("")
    lines.append("## App Identity")
    lines.append(f"- App name: {manifest.get('app_name') or 'unknown'}")
    lines.append(f"- Package: {manifest.get('package') or 'unknown'}")
    lines.append(f"- Version: {manifest.get('version_name') or 'unknown'} ({manifest.get('version_code') or 'unknown'})")
    sdk = manifest.get("sdk") or {}
    lines.append(f"- SDK: min={sdk.get('min_sdk')}, target={sdk.get('target_sdk')}")
    lines.append("")

    lines.append("## Input Structure")
    split_summary = (packet.get("split_inventory") or {}).get("summary") or {}
    lines.append(f"- APK count: {(packet.get('split_inventory') or {}).get('apk_count', 0)}")
    lines.append(f"- Split types: {', '.join(split_summary.get('split_types') or []) or 'none'}")
    lines.append(f"- Native APK count: {split_summary.get('native_apk_count', 0)}")
    lines.append(f"- Model APK count: {split_summary.get('model_apk_count', 0)}")
    lines.append("")

    lines.append("## Capability Signals")
    if capabilities:
        for capability in capability_names(capabilities.keys()):
            lines.append(f"- {_capability_label(capability)} (`{capability}`): {capabilities[capability]}")
    else:
        lines.append("- No capability-specific evidence was indexed.")
    lines.append("")

    evidence_summary = packet.get("evidence_units_summary") or {}
    lines.append("## Structured Evidence Units")
    if evidence_summary.get("total"):
        lines.append(f"- Total units: {evidence_summary.get('total')}")
        for kind, count in sorted((evidence_summary.get("by_kind") or {}).items()):
            lines.append(f"- {kind}: {count}")
        lines.append(f"- JSONL: {evidence_summary.get('jsonl_path')}")
        lines.append(f"- Similarity-ready packet: {evidence_summary.get('similarity_packet_path')}")
    else:
        lines.append("- No structured evidence units were available.")
    lines.append("")

    permissions = manifest.get("permissions") or []
    dangerous_permissions = manifest.get("dangerous_permissions") or []
    lines.append("## Permissions")
    lines.append(f"- Total permissions: {len(permissions)}")
    lines.append(f"- Sensitive permissions: {', '.join(dangerous_permissions) if dangerous_permissions else 'none detected'}")
    lines.append("")

    models = packet.get("models") or []
    lines.append("## Local Models and High-Value Assets")
    if models:
        for model in models[:25]:
            hints = ", ".join(model.get("operator_hints") or [])
            caps = ", ".join(model.get("capabilities") or [])
            lines.append(
                f"- `{model.get('path')}` ({model.get('format')}, {model.get('size_bytes')} bytes)"
                f"; capabilities={caps or 'unknown'}; hints={hints or 'none'}"
            )
    else:
        lines.append("- No model files were identified.")
    lines.append("")

    native_targets = packet.get("native_targets") or []
    lines.append("## Native Targets")
    if native_targets:
        for target in native_targets[:30]:
            caps = ", ".join(target.get("capabilities") or [])
            reasons = ", ".join(target.get("reasons") or [])
            lines.append(
                f"- `{target.get('name')}` in `{target.get('library')}` "
                f"(score={target.get('score')}, kind={target.get('kind')}, capabilities={caps or 'unknown'}, reasons={reasons})"
            )
    else:
        lines.append("- No high-value native targets were selected.")
    lines.append("")

    snippets_by_capability = packet.get("code_snippets") or {}
    lines.append("## Code Evidence")
    if snippets_by_capability:
        for capability in capability_names(snippets_by_capability.keys()):
            lines.append(f"### {_capability_label(capability)}")
            for snippet in snippets_by_capability[capability][:10]:
                text = str(snippet.get("text") or "").replace("\n", " ")
                lines.append(f"- `{snippet.get('file')}:{snippet.get('line')}` {text}")
    else:
        lines.append("- No code snippets were indexed.")
    lines.append("")

    urls = packet.get("urls") or {}
    lines.append("## Network and Cloud Clues")
    code_urls = urls.get("code_urls") or []
    native_urls = urls.get("native_urls") or []
    if code_urls or native_urls:
        for url in (code_urls + native_urls)[:80]:
            lines.append(f"- {url}")
    else:
        lines.append("- No explicit URLs were indexed.")
    lines.append("")

    lines.append("## Review Notes")
    lines.append("- Treat obfuscated names, native binaries, and dynamic downloads as uncertainty sources.")
    lines.append("- This packet is evidence for research triage; it is not a legal or security determination.")
    lines.append("- Similarity scoring against open-source projects is intentionally out of scope for this pipeline stage.")
    lines.append("")
    return "\n".join(lines)


def _render_prompt(packet_path: Path) -> str:
    return "\n".join(
        [
            "Use the attached evidence packet to assess the app's local/offline capabilities.",
            "",
            "Tasks:",
            "1. Identify which capabilities appear to run locally on-device.",
            "2. Separate local implementation evidence from cloud/service/dependency evidence.",
            "3. Flag native libraries, model files, and resource files that deserve manual follow-up.",
            "4. State what cannot be concluded from the available decompiled evidence.",
            "5. Do not perform open-source similarity scoring unless separate comparison material is provided.",
            "",
            f"Evidence packet: {packet_path}",
        ]
    )


def run_phase5_evidence(workspace: Path, *, force: bool = False) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase5_evidence")
    packet_json_path = output_dir / "review_packet.json"
    packet_md_path = output_dir / "review_packet.md"
    prompt_path = output_dir / "review_prompt.md"
    evidence_jsonl_path = output_dir / "evidence_units.jsonl"
    graph_path = output_dir / "evidence_graph.json"
    similarity_packet_path = output_dir / "similarity_ready_packet.json"

    output_paths = [
        packet_json_path,
        packet_md_path,
        prompt_path,
        evidence_jsonl_path,
        graph_path,
        similarity_packet_path,
    ]
    if all(path.exists() for path in output_paths) and not force:
        return PhaseResult(
            name="phase5_evidence",
            success=True,
            output_paths=output_paths,
            details={"cached": True},
        )

    split_inventory = _load_json(workspace / "phase0_split_inventory" / "split_inventory.json")
    manifest = _load_json(workspace / "phase1_manifest" / "manifest_summary.json")
    code_index = _load_json(workspace / "phase2_jadx" / "code_index.json")
    native_analysis = _load_json(workspace / "phase3_native" / "native_analysis.json")
    native_targets = _load_json(workspace / "phase3_native" / "native_targets.json")
    resource_inventory = _load_json(workspace / "phase4_resources" / "resource_inventory.json")
    capability_counts = _collect_capabilities(
        code_index,
        native_analysis,
        resource_inventory,
        split_inventory,
    )
    evidence_units = _collect_evidence_units(workspace)
    evidence_kind_counts = Counter(str(unit.get("kind") or "unknown") for unit in evidence_units)
    evidence_graph = _build_evidence_graph(evidence_units, manifest)
    similarity_packet = _build_similarity_packet(
        manifest,
        split_inventory,
        capability_counts,
        evidence_units,
        graph_path,
    )

    packet = {
        "manifest": manifest,
        "split_inventory": split_inventory,
        "capability_counts": capability_counts,
        "models": _extract_models(resource_inventory),
        "native_targets": _extract_native_targets(native_targets),
        "code_snippets": _extract_code_snippets(code_index),
        "urls": _extract_urls(code_index, native_analysis),
        "evidence_units_summary": {
            "total": len(evidence_units),
            "by_kind": dict(sorted(evidence_kind_counts.items())),
            "jsonl_path": str(evidence_jsonl_path),
            "graph_path": str(graph_path),
            "similarity_packet_path": str(similarity_packet_path),
        },
        "source_files": {
            "split_inventory": str(workspace / "phase0_split_inventory" / "split_inventory.json"),
            "manifest": str(workspace / "phase1_manifest" / "manifest_summary.json"),
            "code_index": str(workspace / "phase2_jadx" / "code_index.json"),
            "java_evidence_units": str(workspace / "phase2_jadx" / "java_evidence_units.json"),
            "native_analysis": str(workspace / "phase3_native" / "native_analysis.json"),
            "native_targets": str(workspace / "phase3_native" / "native_targets.json"),
            "native_evidence_units": str(workspace / "phase3_native" / "native_evidence_units.json"),
            "resource_inventory": str(workspace / "phase4_resources" / "resource_inventory.json"),
            "model_evidence_units": str(workspace / "phase4_resources" / "model_evidence_units.json"),
            "resource_evidence_units": str(workspace / "phase4_resources" / "resource_evidence_units.json"),
        },
    }

    write_jsonl(evidence_jsonl_path, evidence_units)
    safe_write_json(graph_path, evidence_graph)
    safe_write_json(similarity_packet_path, similarity_packet)
    safe_write_json(packet_json_path, packet)
    safe_write_text(packet_md_path, _render_markdown(packet))
    safe_write_text(prompt_path, _render_prompt(packet_md_path))

    return PhaseResult(
        name="phase5_evidence",
        success=True,
        output_paths=output_paths,
        details={
            "capabilities": capability_names(packet["capability_counts"].keys()),
            "model_count": len(packet["models"]),
            "native_target_count": len(packet["native_targets"]),
            "evidence_unit_count": len(evidence_units),
            "similarity_packet": str(similarity_packet_path),
            "packet_md": str(packet_md_path),
            "prompt": str(prompt_path),
        },
    )
