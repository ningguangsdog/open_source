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


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


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
                "tflite_magic_offsets": metadata.get("tflite_magic_offsets") or [],
                "embedded_tflite_magic_present": metadata.get("embedded_tflite_magic_present"),
                "likely_wrapped_or_encrypted": metadata.get("likely_wrapped_or_encrypted"),
                "entropy_first_mb": metadata.get("entropy_first_mb"),
                "operator_hints": metadata.get("operator_hints") or [],
                "capabilities": capability_names((metadata.get("capabilities") or {}).keys()),
                "strings_sample": (metadata.get("strings_sample") or [])[:20],
            }
        )
    return models[:max_models]


def _extract_native_targets(native_targets: dict[str, Any], max_targets: int = 50) -> list[dict[str, Any]]:
    return (native_targets.get("targets") or [])[:max_targets]


def _extract_native_deep_summary(workspace: Path) -> dict[str, Any]:
    return {
        "toolchain": _load_json(workspace / "phase3_native" / "native_toolchain.json"),
        "decompile_plan": _load_json(workspace / "phase3_native" / "native_decompile_plan.json"),
        "deep_summary": _load_json(workspace / "phase3_native" / "native_deep_summary.json"),
        "function_features": _load_jsonl(workspace / "phase3_native" / "native_function_features.jsonl")[:100],
        "string_xrefs": _load_list(workspace / "phase3_native" / "native_string_xrefs.json")[:100],
        "callgraph": _load_json(workspace / "phase3_native" / "native_callgraph.json"),
    }


def _collect_native_probe_summaries(workspace: Path) -> list[dict[str, Any]]:
    probe_root = workspace / "phase3_native" / "probes"
    summaries: list[dict[str, Any]] = []
    if not probe_root.exists():
        return summaries
    for summary_path in sorted(probe_root.glob("*/native_probe_summary.json")):
        summary = _load_json(summary_path)
        if not summary:
            continue
        enriched = dict(summary)
        enriched.setdefault("summary_path", str(summary_path))
        summaries.append(enriched)
    return summaries


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
    probe_root = workspace / "phase3_native" / "probes"
    if probe_root.exists():
        for source in sorted(probe_root.glob("*/native_probe_review_units.jsonl")):
            for row in _load_jsonl(source):
                enriched = dict(row)
                enriched.setdefault("source_file", str(source))
                enriched.setdefault("unit_id", unit_id(source.name, len(units), row.get("library"), row.get("name")))
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


def _lib_stems(values: list[str]) -> set[str]:
    stems: set[str] = set()
    for value in values:
        text = str(value or "")
        name = Path(text).name
        if name.startswith("lib") and name.endswith(".so"):
            stems.add(name[3:-3])
        elif name.endswith(".so"):
            stems.add(name[:-3])
        else:
            stems.add(name)
    return {item for item in stems if item}


def _jni_prefix(package: str | None, class_name: str | None, method: str) -> str:
    package_part = str(package or "").replace(".", "_")
    class_part = str(class_name or "").replace(".", "_").replace("$", "_")
    base = "_".join(part for part in [package_part, class_part, method] if part)
    return f"Java_{base}" if base else method


def _build_java_native_bridge_map(
    code_index: dict[str, Any],
    native_analysis: dict[str, Any],
    evidence_units: list[dict[str, Any]],
) -> dict[str, Any]:
    native_libraries: dict[str, list[dict[str, Any]]] = defaultdict(list)
    native_targets: list[dict[str, Any]] = []
    for unit in evidence_units:
        if unit.get("kind") == "native_library":
            for stem in _lib_stems([str(unit.get("name") or ""), str(unit.get("library") or "")]):
                native_libraries[stem].append(unit)
        elif unit.get("kind") == "native_target":
            native_targets.append(unit)

    symbol_rows: list[dict[str, Any]] = []
    for library in native_analysis.get("libraries") or []:
        names = []
        names.extend(library.get("jni_symbols") or [])
        names.extend(library.get("exported_symbols") or [])
        for name in names:
            symbol_rows.append(
                {
                    "library": library.get("extracted_path") or library.get("entry"),
                    "library_name": library.get("name"),
                    "abi": library.get("abi"),
                    "symbol": str(name),
                }
            )

    mappings: list[dict[str, Any]] = []
    for record in code_index.get("files") or []:
        native_methods = record.get("native_methods") or []
        load_libraries = record.get("load_libraries") or []
        if not native_methods and not load_libraries:
            continue
        loaded_stems = _lib_stems([str(item) for item in load_libraries])
        loaded_libraries = []
        for stem in sorted(loaded_stems):
            loaded_libraries.extend(native_libraries.get(stem) or [])

        for method in native_methods or [None]:
            expected = _jni_prefix(record.get("package"), record.get("class_name"), str(method or ""))
            candidate_symbols = []
            for row in symbol_rows:
                row_stems = _lib_stems([str(row.get("library_name") or ""), str(row.get("library") or "")])
                if loaded_stems and not loaded_stems.intersection(row_stems):
                    continue
                symbol = str(row.get("symbol") or "")
                if method and (expected in symbol or symbol.endswith(f"_{method}") or f"_{method}__" in symbol):
                    candidate_symbols.append(row)
                elif not method and loaded_stems.intersection(row_stems):
                    candidate_symbols.append(row)
                if len(candidate_symbols) >= 40:
                    break

            candidate_targets = []
            for target in native_targets:
                target_stems = _lib_stems([str(target.get("library") or "")])
                if loaded_stems and not loaded_stems.intersection(target_stems):
                    continue
                name = str(target.get("name") or "")
                if method and not (
                    expected in name or name.endswith(f"_{method}") or f"_{method}__" in name
                ):
                    continue
                candidate_targets.append(
                    {
                        "unit_id": target.get("unit_id"),
                        "library": target.get("library"),
                        "name": target.get("name"),
                        "score": target.get("score"),
                        "feature_hash": target.get("feature_hash"),
                        "pseudocode_path": target.get("pseudocode_path"),
                    }
                )
                if len(candidate_targets) >= 40:
                    break

            mappings.append(
                {
                    "java_file": record.get("file"),
                    "package": record.get("package"),
                    "class_name": record.get("class_name"),
                    "native_method": method,
                    "expected_jni_prefix": expected if method else None,
                    "load_libraries": load_libraries,
                    "matched_native_libraries": [
                        {
                            "unit_id": item.get("unit_id"),
                            "name": item.get("name"),
                            "library": item.get("library"),
                            "abi": item.get("abi"),
                        }
                        for item in loaded_libraries[:40]
                    ],
                    "candidate_symbols": candidate_symbols,
                    "candidate_native_targets": candidate_targets,
                    "confidence": "candidate" if candidate_symbols or candidate_targets else "library_only",
                }
            )

    return {
        "schema_version": "2026-07-05.java-native-bridge-map.v1",
        "mapping_count": len(mappings),
        "mappings": mappings,
        "notes": [
            "JNI matching is conservative and may miss obfuscated, dynamically registered, or overloaded methods.",
            "Use candidate_symbols and candidate_native_targets as review links, not final attribution claims.",
        ],
    }


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
    *,
    native_deep_summary: dict[str, Any] | None = None,
    native_probe_summaries: list[dict[str, Any]] | None = None,
    bridge_map_path: Path | None = None,
) -> dict[str, Any]:
    kind_counts: Counter[str] = Counter(str(unit.get("kind") or "unknown") for unit in evidence_units)
    high_value = [
        {
            "unit_id": unit.get("unit_id"),
            "kind": unit.get("kind"),
            "phase": unit.get("phase"),
            "label": unit.get("normalized_signature") or unit.get("name") or unit.get("path") or unit.get("file"),
            "file": unit.get("file"),
            "path": unit.get("path"),
            "line": unit.get("line"),
            "apk": unit.get("apk"),
            "entry": unit.get("entry"),
            "split": unit.get("split"),
            "package": unit.get("package"),
            "class_name": unit.get("class_name"),
            "method_names": unit.get("method_names"),
            "native_methods": unit.get("native_methods"),
            "native_libraries": unit.get("native_libraries"),
            "library": unit.get("library"),
            "target_kind": unit.get("target_kind"),
            "name": unit.get("name"),
            "model_path": unit.get("model_path") or unit.get("path"),
            "sha256": unit.get("sha256"),
            "size_bytes": unit.get("size_bytes"),
            "capabilities": unit.get("capabilities") or [],
            "confidence": unit.get("confidence"),
            "score": unit.get("score"),
            "reasons": unit.get("reasons"),
            "feature_hash": unit.get("feature_hash"),
            "pseudocode_path": unit.get("pseudocode_path"),
            "pseudocode_fingerprint": unit.get("pseudocode_fingerprint"),
            "instruction_count": unit.get("instruction_count"),
            "basic_block_count": unit.get("basic_block_count"),
            "cfg_edge_count": unit.get("cfg_edge_count"),
            "call_targets": unit.get("call_targets"),
            "string_refs": unit.get("string_refs"),
            "token_fingerprint": unit.get("token_fingerprint"),
            "source_file": unit.get("source_file"),
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
        "native_deep": {
            "decompiler_status": ((native_deep_summary or {}).get("deep_summary") or {}).get("decompiler_status"),
            "attempted_targets": ((native_deep_summary or {}).get("deep_summary") or {}).get("attempted_targets"),
            "successful_decompilations": ((native_deep_summary or {}).get("deep_summary") or {}).get(
                "successful_decompilations"
            ),
            "selected_decompiler": ((native_deep_summary or {}).get("toolchain") or {}).get("selected_decompiler"),
            "decompile_plan_status": ((native_deep_summary or {}).get("decompile_plan") or {}).get("status"),
            "function_feature_count": len((native_deep_summary or {}).get("function_features") or []),
            "string_xref_function_count": len((native_deep_summary or {}).get("string_xrefs") or []),
            "callgraph_node_count": ((native_deep_summary or {}).get("callgraph") or {}).get("node_count"),
            "callgraph_edge_count": ((native_deep_summary or {}).get("callgraph") or {}).get("edge_count"),
        },
        "native_probes": native_probe_summaries or [],
        "graph_path": str(graph_path),
        "java_native_bridge_map_path": str(bridge_map_path) if bridge_map_path else None,
        "notes": [
            "This packet is intended for downstream review and similarity preparation.",
            "Hashes identify exact artifacts; token_fingerprint is a normalized static signal, not a similarity score.",
            "Native pseudocode and function features appear when auto/deep native analysis selects targets and an automated adapter is available.",
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

    native_deep = packet.get("native_deep") or {}
    deep_summary = native_deep.get("deep_summary") or {}
    toolchain = native_deep.get("toolchain") or {}
    decompile_plan = native_deep.get("decompile_plan") or {}
    lines.append("## Native Deep Evidence")
    lines.append(f"- Selected decompiler: {toolchain.get('selected_decompiler') or 'none'}")
    lines.append(f"- Decompile plan status: {decompile_plan.get('status') or 'unknown'}")
    lines.append(f"- Decompiler status: {deep_summary.get('decompiler_status') or 'unknown'}")
    lines.append(f"- Attempted targets: {deep_summary.get('attempted_targets') or 0}")
    lines.append(f"- Successful decompilations: {deep_summary.get('successful_decompilations') or 0}")
    lines.append(f"- Function feature rows: {len(native_deep.get('function_features') or [])}")
    callgraph = native_deep.get("callgraph") or {}
    lines.append(f"- Callgraph: {callgraph.get('node_count') or 0} nodes, {callgraph.get('edge_count') or 0} edges")
    if (decompile_plan.get("status") or "") == "tool_missing":
        lines.append("- Native pseudocode was not generated because no automated native decompiler was available.")
    lines.append("")

    native_probes = packet.get("native_probes") or []
    lines.append("## Native Deep Probes")
    if native_probes:
        for probe in native_probes:
            profile = probe.get("profile") or {}
            paths = probe.get("paths") or {}
            lines.append(f"- Profile: `{profile.get('name') or 'unknown'}`")
            lines.append(f"  - Seed targets: {probe.get('seed_target_count', 0)}")
            lines.append(f"  - Expanded targets: {probe.get('expanded_target_count', 0)}")
            lines.append(f"  - Attempted targets: {probe.get('attempted_targets', 0)}")
            lines.append(f"  - Successful decompilations: {probe.get('successful_decompilations', 0)}")
            lines.append(f"  - Function features: {probe.get('function_feature_count', 0)}")
            lines.append(f"  - Outcome counts: {probe.get('outcome_counts') or {}}")
            if paths.get("review_units"):
                lines.append(f"  - Review units: {paths.get('review_units')}")
    else:
        lines.append("- No native deep probe outputs were found.")
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
    bridge_map_path = output_dir / "java_native_bridge_map.json"

    output_paths = [
        packet_json_path,
        packet_md_path,
        prompt_path,
        evidence_jsonl_path,
        graph_path,
        similarity_packet_path,
        bridge_map_path,
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
    native_deep_summary = _extract_native_deep_summary(workspace)
    native_probe_summaries = _collect_native_probe_summaries(workspace)
    bridge_map = _build_java_native_bridge_map(code_index, native_analysis, evidence_units)
    similarity_packet = _build_similarity_packet(
        manifest,
        split_inventory,
        capability_counts,
        evidence_units,
        graph_path,
        native_deep_summary=native_deep_summary,
        native_probe_summaries=native_probe_summaries,
        bridge_map_path=bridge_map_path,
    )

    packet = {
        "manifest": manifest,
        "split_inventory": split_inventory,
        "capability_counts": capability_counts,
        "models": _extract_models(resource_inventory),
        "native_targets": _extract_native_targets(native_targets),
        "native_deep": native_deep_summary,
        "native_probes": native_probe_summaries,
        "java_native_bridge_map": {
            "mapping_count": bridge_map.get("mapping_count"),
            "path": str(bridge_map_path),
        },
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
            "native_toolchain": str(workspace / "phase3_native" / "native_toolchain.json"),
            "native_decompile_plan": str(workspace / "phase3_native" / "native_decompile_plan.json"),
            "native_decompilation": str(workspace / "phase3_native" / "native_decompilation.json"),
            "native_function_features": str(workspace / "phase3_native" / "native_function_features.jsonl"),
            "native_string_xrefs": str(workspace / "phase3_native" / "native_string_xrefs.json"),
            "native_callgraph": str(workspace / "phase3_native" / "native_callgraph.json"),
            "native_deep_summary": str(workspace / "phase3_native" / "native_deep_summary.json"),
            "native_evidence_units": str(workspace / "phase3_native" / "native_evidence_units.json"),
            "resource_inventory": str(workspace / "phase4_resources" / "resource_inventory.json"),
            "model_evidence_units": str(workspace / "phase4_resources" / "model_evidence_units.json"),
            "resource_evidence_units": str(workspace / "phase4_resources" / "resource_evidence_units.json"),
            "native_probes": str(workspace / "phase3_native" / "probes"),
        },
    }

    write_jsonl(evidence_jsonl_path, evidence_units)
    safe_write_json(graph_path, evidence_graph)
    safe_write_json(bridge_map_path, bridge_map)
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
            "native_probe_count": len(native_probe_summaries),
            "evidence_unit_count": len(evidence_units),
            "java_native_bridge_mapping_count": bridge_map.get("mapping_count"),
            "similarity_packet": str(similarity_packet_path),
            "packet_md": str(packet_md_path),
            "prompt": str(prompt_path),
        },
    )
