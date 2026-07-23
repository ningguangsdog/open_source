"""Target selection and optional native decompiler adapters."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Callable

from .capability_taxonomy import capability_names, classify_text
from .evidence import token_fingerprint
from .ida_integration import normalize_address
from .native_semantics import abi_analysis_role, classify_native_semantics
from .utils import ensure_dir, run_cmd, safe_name, safe_write_json, safe_write_text, tool_exists


HIGH_VALUE_NAME_MARKERS = (
    "jni",
    "ocr",
    "detect",
    "recogn",
    "segment",
    "infer",
    "predict",
    "classif",
    "encrypt",
    "decrypt",
    "cipher",
    "compress",
    "render",
    "parse",
    "pdf",
    "scan",
    "image",
    "model",
)
AUTOMATED_DECOMPILER_TOOLS = {"rizin", "radare2"}
MAX_COMMAND_OUTPUT = 3_000_000
ProgressCallback = Callable[[dict[str, Any]], None]


def _emit_progress(callback: ProgressCallback | None, payload: dict[str, Any]) -> None:
    if callback is not None:
        callback(payload)


def score_native_text(text: str) -> tuple[int, list[str], list[str]]:
    classified = classify_text(text)
    score = 0
    capabilities: list[str] = []
    reasons: list[str] = []
    lowered = text.lower()

    for capability, details in classified.items():
        if not isinstance(details, dict):
            continue
        capabilities.append(capability)
        raw_score = details.get("score")
        try:
            score += int(raw_score) if isinstance(raw_score, (int, float, str)) else 0
        except (TypeError, ValueError):
            pass
        raw_strong_hits = details.get("strong_hits")
        strong_hits = (
            [str(item) for item in raw_strong_hits]
            if isinstance(raw_strong_hits, (list, tuple, set))
            else []
        )
        if strong_hits:
            reasons.append(f"strong:{','.join(strong_hits[:5])}")

    for marker in HIGH_VALUE_NAME_MARKERS:
        if marker in lowered:
            score += 4
            reasons.append(f"name:{marker}")

    return score, capability_names(capabilities), sorted(set(reasons))[:12]


def select_native_targets(
    library_records: list[dict[str, Any]],
    *,
    max_targets: int = 300,
    max_libraries: int | None = None,
    per_library_limit: int = 80,
    target_capabilities: tuple[str, ...] | list[str] | set[str] = (),
    java_native_hints: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Rank callable native functions using identity, ABI, and cross-layer evidence."""

    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    desired_capabilities = {str(item) for item in target_capabilities if item}
    java_native_hints = java_native_hints or []
    hints_by_target: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    hints_by_symbol: dict[tuple[str, str], list[dict[str, Any]]] = {}
    hints_by_library: dict[str, list[dict[str, Any]]] = {}
    for hint in java_native_hints:
        hint_library = str(hint.get("library") or "")
        symbol = str(hint.get("symbol") or "")
        address = str(normalize_address(hint.get("address")) or "")
        hints_by_target.setdefault((hint_library, symbol, address), []).append(
            hint
        )
        hints_by_library.setdefault(hint_library, []).append(hint)
        if symbol:
            hints_by_symbol.setdefault((hint_library, symbol), []).append(hint)
    arm64_available = any(
        str(library.get("abi") or "").lower() == "arm64-v8a"
        for library in library_records
    )
    if max_libraries is not None:
        max_libraries = max(1, max_libraries)
    per_library_limit = max(1, per_library_limit)

    for library in library_records:
        lib_path = library.get("extracted_path") or library.get("path") or library.get("entry")
        if not lib_path:
            continue
        library_path = str(lib_path)
        abi = str(library.get("abi") or "")
        abi_role = abi_analysis_role(abi, arm64_available=arm64_available)
        model_signal_text = " ".join(
            str(item.get("value") if isinstance(item, dict) else item)
            for item in library.get("interesting_strings") or []
        )
        model_capabilities = capability_names(
            (library.get("capability_counts") or {}).keys()
        )
        model_dependency_signal = (
            "local_ml" in model_capabilities
            or any(
                marker in model_signal_text.lower()
                for marker in (
                    "tflite",
                    "tensorflow",
                    "onnx",
                    "mediapipe",
                    "interpreter",
                    "tensor",
                )
            )
        )

        candidates: list[dict[str, Any]] = []
        symbol_records = [
            item
            for item in library.get("symbol_records") or []
            if isinstance(item, dict) and item.get("name")
        ]
        if symbol_records:
            for symbol_record in symbol_records:
                name = str(symbol_record.get("name") or "")
                candidates.append(
                    {
                        "kind": (
                            "jni_symbol"
                            if symbol_record.get("is_jni")
                            or name in (library.get("jni_symbols") or [])
                            else "exported_symbol"
                        ),
                        "name": name,
                        "address": normalize_address(symbol_record.get("address")),
                        "size_bytes": symbol_record.get("size_bytes"),
                        "symbol_source": symbol_record.get("symbol_source"),
                    }
                )
        else:
            for kind, symbols in (
                ("jni_symbol", library.get("jni_symbols") or []),
                ("exported_symbol", library.get("exported_symbols") or []),
            ):
                for symbol in symbols:
                    candidates.append(
                        {
                            "kind": kind,
                            "name": str(symbol),
                            "address": None,
                            "size_bytes": None,
                            "symbol_source": "legacy_name_list",
                        }
                    )

        if not candidates:
            library_score, capabilities, reasons = score_native_text(
                f"{library_path} {model_signal_text[:100000]}"
            )
            if abi_role == "primary_production":
                library_score += 16
                reasons.append("primary_production_abi")
            if model_dependency_signal:
                library_score += 10
                reasons.append("model_dependency_signal")
            if library_score > 0:
                if desired_capabilities and desired_capabilities.intersection(capabilities):
                    library_score += 8
                    reasons.append("target_capability")
                targets.append(
                    {
                        "library": library_path,
                        "kind": "library",
                        "name": Path(library_path).name,
                        "address": None,
                        "score": library_score,
                        "capabilities": capabilities,
                        "reasons": sorted(set(reasons)),
                        "ownership": library.get("ownership") or {},
                        "library_sha256": library.get("sha256"),
                        "abi": abi,
                        "abi_analysis_role": abi_role,
                        "model_dependency_signal": model_dependency_signal,
                        "semantic_role_prior": {
                            "role": "uncertain",
                            "confidence": "low",
                            "reasons": ["library_level_discovery_required"],
                        },
                        "associated_java_methods": [
                            hint
                            for hint in java_native_hints
                            if str(hint.get("library") or "") == library_path
                        ],
                    }
                )
            continue

        for candidate in candidates:
            kind = str(candidate.get("kind") or "")
            name = str(candidate.get("name") or "")
            address = str(normalize_address(candidate.get("address")) or "")
            key = (library_path, name, address)
            if key in seen:
                continue
            seen.add(key)

            score, capabilities, reasons = score_native_text(
                f"{library_path} {name}"
            )
            score_components: dict[str, int] = {"native_text_score": score}
            if kind == "jni_symbol":
                score += 10
                score_components["jni_symbol_bonus"] = 10
                reasons.append("jni_symbol")
            elif kind == "exported_symbol":
                score += 4
                score_components["exported_symbol_bonus"] = 4
                reasons.append("exported_symbol")
            if desired_capabilities and desired_capabilities.intersection(capabilities):
                score += 8
                score_components["target_capability_bonus"] = 8
                reasons.append("target_capability")
            if abi_role == "primary_production":
                score += 16
                score_components["primary_abi_bonus"] = 16
                reasons.append("primary_production_abi")
            elif abi_role == "secondary_production":
                score += 6
                score_components["secondary_abi_bonus"] = 6
                reasons.append("secondary_production_abi")
            if model_dependency_signal:
                score += 10
                score_components["model_dependency_bonus"] = 10
                reasons.append("model_dependency_signal")

            exact_java = (
                hints_by_target.get(key)
                or hints_by_symbol.get((library_path, name))
                or []
            )
            associated_java = exact_java or [
                hint
                for hint in hints_by_library.get(library_path) or []
                if hint.get("match_type") == "load_library"
            ]
            if associated_java:
                java_bonus = (
                    min(24, 12 * len(associated_java))
                    if exact_java
                    else min(8, 4 * len(associated_java))
                )
                score += java_bonus
                score_components["java_jni_bridge_bonus"] = java_bonus
                reasons.append(
                    "java_jni_bridge" if exact_java else "java_load_library"
                )

            semantic_prior = classify_native_semantics(name)
            if semantic_prior.get("role") == "wrapper":
                score -= 18
                score_components["wrapper_penalty"] = -18
                reasons.append("wrapper_or_trampoline_penalty")
            ownership = library.get("ownership") or {}
            if ownership.get("category") in {"third_party", "platform"}:
                score -= 6
                score_components["dependency_penalty"] = -6
                reasons.append("dependency_or_platform_penalty")

            if score <= 0:
                continue

            targets.append(
                {
                    "library": library_path,
                    "kind": kind,
                    "name": name,
                    "address": normalize_address(candidate.get("address")),
                    "size_bytes": candidate.get("size_bytes"),
                    "symbol_source": candidate.get("symbol_source"),
                    "score": score,
                    "capabilities": capability_names(capabilities),
                    "reasons": sorted(set(reasons))[:12],
                    "score_components": score_components,
                    "ownership": ownership,
                    "library_sha256": library.get("sha256"),
                    "abi": abi,
                    "abi_analysis_role": abi_role,
                    "model_dependency_signal": model_dependency_signal,
                    "semantic_role_prior": semantic_prior,
                    "associated_java_methods": associated_java,
                }
            )

    targets.sort(
        key=lambda item: (
            -int(item["score"]),
            0 if item.get("abi_analysis_role") == "primary_production" else 1,
            item["library"],
            item.get("address") or "",
            item["name"],
        )
    )
    if max_libraries:
        best_by_library: dict[str, int] = {}
        for target in targets:
            target_library = str(target.get("library") or "")
            best_by_library[target_library] = max(
                best_by_library.get(target_library, 0),
                int(target.get("score") or 0),
            )
        allowed_libraries = {
            library_name
            for library_name, _ in sorted(
                best_by_library.items(),
                key=lambda item: (-item[1], item[0]),
            )[:max_libraries]
        }
        targets = [target for target in targets if str(target.get("library") or "") in allowed_libraries]

    grouped: Counter[str] = Counter()
    budgeted: list[dict[str, Any]] = []
    for target in targets:
        target_library = str(target.get("library") or "")
        if grouped[target_library] >= per_library_limit:
            continue
        grouped[target_library] += 1
        budgeted.append(target)
        if len(budgeted) >= max_targets:
            break
    return budgeted


def available_decompiler(preferred: str = "auto") -> str | None:
    if preferred == "none":
        return None
    if preferred == "rizin" and tool_exists("rizin"):
        return "rizin"
    if preferred == "radare2" and tool_exists("r2"):
        return "radare2"
    if preferred == "retdec" and tool_exists("retdec-decompiler.py"):
        return "retdec"
    if preferred == "ghidra" and tool_exists("analyzeHeadless"):
        return "ghidra"
    if preferred not in {"auto", "none"}:
        return None
    if tool_exists("rizin"):
        return "rizin"
    if tool_exists("r2"):
        return "radare2"
    if tool_exists("retdec-decompiler.py"):
        return "retdec"
    if tool_exists("analyzeHeadless"):
        return "ghidra"
    return None


def _tool_version(command: list[str], timeout: int = 10) -> str | None:
    try:
        completed = run_cmd(command, check=False, timeout=timeout)
    except Exception:
        return None
    if completed.returncode != 0:
        return None
    text = (completed.stdout or completed.stderr or "").strip()
    if not text:
        return None
    return text.splitlines()[0][:300]


def detect_native_toolchain(preferred: str = "auto") -> dict[str, Any]:
    """Return a machine-readable native analysis tool preflight."""

    tools = {
        "strings": {
            "available": tool_exists("strings"),
            "version": _tool_version(["strings", "--version"]) if tool_exists("strings") else None,
        },
        "readelf": {
            "available": tool_exists("readelf"),
            "version": _tool_version(["readelf", "--version"]) if tool_exists("readelf") else None,
        },
        "llvm-readelf": {
            "available": tool_exists("llvm-readelf"),
            "version": _tool_version(["llvm-readelf", "--version"]) if tool_exists("llvm-readelf") else None,
        },
        "nm": {
            "available": tool_exists("nm"),
            "version": _tool_version(["nm", "--version"]) if tool_exists("nm") else None,
        },
        "rizin": {
            "available": tool_exists("rizin"),
            "version": _tool_version(["rizin", "-v"]) if tool_exists("rizin") else None,
            "automated_adapter": True,
        },
        "radare2": {
            "available": tool_exists("r2"),
            "version": _tool_version(["r2", "-v"]) if tool_exists("r2") else None,
            "automated_adapter": True,
        },
        "retdec": {
            "available": tool_exists("retdec-decompiler.py"),
            "version": _tool_version(["retdec-decompiler.py", "--version"])
            if tool_exists("retdec-decompiler.py")
            else None,
            "automated_adapter": False,
        },
        "ghidra": {
            "available": tool_exists("analyzeHeadless"),
            "version": _tool_version(["analyzeHeadless"]) if tool_exists("analyzeHeadless") else None,
            "automated_adapter": False,
        },
    }
    selected = available_decompiler(preferred)
    return {
        "preferred": preferred,
        "selected_decompiler": selected,
        "selected_adapter_automated": selected in AUTOMATED_DECOMPILER_TOOLS if selected else False,
        "tools": tools,
        "notes": [
            "JADX handles Dalvik bytecode only; native .so files require a binary decompiler/disassembler.",
            "The automated native-deep adapter currently uses rizin or radare2 when available.",
        ],
    }


def _target_is_callable(target: dict[str, Any]) -> bool:
    return target.get("kind") in {
        "jni_symbol",
        "exported_symbol",
        "profile_seed",
        "internal_callee",
        "address",
    }


def build_decompile_plan(
    targets: list[dict[str, Any]],
    *,
    decompiler: str = "auto",
    max_targets: int = 40,
    max_libraries: int = 8,
    target_capabilities: tuple[str, ...] | list[str] | set[str] = (),
) -> dict[str, Any]:
    """Select deterministic native targets for automated deep analysis."""

    max_targets = max(1, max_targets)
    max_libraries = max(1, max_libraries)
    toolchain = detect_native_toolchain(decompiler)
    selected_tool = toolchain.get("selected_decompiler")
    desired_capabilities = {str(item) for item in target_capabilities if item}
    callable_targets = [target for target in targets if _target_is_callable(target)]

    if decompiler == "none":
        status = "disabled"
        reason = "Native decompilation was disabled by configuration."
    elif not selected_tool:
        status = "tool_missing"
        reason = "Install rizin or radare2 to emit automated native function evidence."
    elif selected_tool not in AUTOMATED_DECOMPILER_TOOLS:
        status = "tool_present_not_automated"
        reason = f"{selected_tool} is available, but this pipeline automates rizin/radare2 only."
    else:
        status = "ready"
        reason = "Automated native decompiler adapter is available."

    preferred_targets = [
        target
        for target in callable_targets
        if not desired_capabilities or desired_capabilities.intersection(target.get("capabilities") or [])
    ]
    if not preferred_targets and desired_capabilities:
        preferred_targets = callable_targets

    budgeted: list[dict[str, Any]] = []
    selection_counts: Counter[str] = Counter()
    per_library_budget = max(1, (max_targets + max_libraries - 1) // max_libraries)
    for target in preferred_targets:
        library = str(target.get("library") or "")
        if not library:
            continue
        if len(selection_counts) >= max_libraries and selection_counts[library] == 0:
            continue
        if selection_counts[library] >= per_library_budget:
            continue
        selection_counts[library] += 1
        budgeted.append(target)
        if len(budgeted) >= max_targets:
            break

    return {
        "schema_version": "2026-07-05.native-deep-plan.v1",
        "status": status,
        "reason": reason,
        "toolchain": toolchain,
        "candidate_count": len(callable_targets),
        "selected_target_count": len(budgeted),
        "selected_libraries": dict(selection_counts),
        "budgets": {
            "max_targets": max_targets,
            "max_libraries": max_libraries,
            "per_library_budget": per_library_budget,
        },
        "target_capabilities": sorted(desired_capabilities),
        "targets": budgeted,
    }


def _run_rizin_command(
    tool: str,
    library_path: Path,
    commands: list[str],
    timeout: int,
) -> dict[str, Any]:
    command: list[str] = [tool, "-2", "-q", "-A"]
    for item in commands:
        command.extend(["-c", item])
    command.extend(["-c", "q", str(library_path)])
    completed = run_cmd(command, check=False, timeout=timeout)
    stdout = (completed.stdout or "")[-MAX_COMMAND_OUTPUT:]
    stderr = (completed.stderr or "")[-20_000:]
    return {
        "returncode": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def _run_rizin_json(tool: str, library_path: Path, command: str, timeout: int) -> Any:
    result = _run_rizin_command(tool, library_path, [command], timeout)
    text = (result.get("stdout") or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _load_function_inventory(tool: str, library_path: Path, timeout: int) -> list[dict[str, Any]]:
    payload = _run_rizin_json(tool, library_path, "aflj", timeout)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _safe_seek_name(value: str) -> str:
    if re.match(r"^[A-Za-z0-9_.$:@+-]+$", value):
        return value
    return safe_name(value)


def _resolve_function_seek(
    target_name: str,
    target_address: Any,
    functions: list[dict[str, Any]],
) -> tuple[str, dict[str, Any] | None]:
    normalized_address = normalize_address(target_address)
    if normalized_address:
        expected_offset = int(normalized_address, 16)
        for function in functions:
            if function.get("offset") == expected_offset:
                return normalized_address, function
        return normalized_address, None
    for function in functions:
        name = str(function.get("name") or "")
        realname = str(function.get("realname") or "")
        if target_name in {name, realname}:
            offset = function.get("offset")
            if isinstance(offset, int):
                return hex(offset), function
            return _safe_seek_name(name or target_name), function
    for function in functions:
        name = str(function.get("name") or "")
        realname = str(function.get("realname") or "")
        if target_name and (target_name in name or target_name in realname):
            offset = function.get("offset")
            if isinstance(offset, int):
                return hex(offset), function
            return _safe_seek_name(name or target_name), function
    return _safe_seek_name(target_name), None


def _jsonish_len(payload: Any, key: str) -> int:
    if isinstance(payload, dict):
        value = payload.get(key)
        if isinstance(value, list):
            return len(value)
    if isinstance(payload, list):
        return len(payload)
    return 0


def _ops_from_disasm(disasm_json: Any) -> list[dict[str, Any]]:
    if isinstance(disasm_json, dict):
        ops = disasm_json.get("ops")
        if isinstance(ops, list):
            return [op for op in ops if isinstance(op, dict)]
    return []


def _blocks_from_cfg(cfg_json: Any) -> list[dict[str, Any]]:
    if isinstance(cfg_json, list) and cfg_json:
        first = cfg_json[0]
        if isinstance(first, dict) and isinstance(first.get("blocks"), list):
            return [block for block in first["blocks"] if isinstance(block, dict)]
    if isinstance(cfg_json, dict) and isinstance(cfg_json.get("blocks"), list):
        return [block for block in cfg_json["blocks"] if isinstance(block, dict)]
    return []


def _extract_string_refs(ops: list[dict[str, Any]], pseudocode: str) -> list[str]:
    refs: set[str] = set()
    ref_re = re.compile(r"(?:str|aav|obj)\.[A-Za-z0-9_.$-]{3,}")
    quoted_re = re.compile(r'"([^"\n]{4,160})"')
    for op in ops:
        text = " ".join(str(op.get(key) or "") for key in ("opcode", "disasm", "comment"))
        for match in ref_re.findall(text):
            refs.add(match)
        for match in quoted_re.findall(text):
            refs.add(match)
    for match in quoted_re.findall(pseudocode):
        refs.add(match)
    return sorted(refs)[:100]


def _extract_call_targets(ops: list[dict[str, Any]], xrefs_json: Any) -> list[str]:
    calls: set[str] = set()
    for op in ops:
        op_type = str(op.get("type") or "")
        opcode = str(op.get("opcode") or op.get("disasm") or "")
        if op_type == "call" or opcode.startswith("bl ") or " call " in f" {opcode} ":
            calls.add(opcode[:240])
        refs = op.get("refs")
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict) and str(ref.get("type") or "").lower() in {"call", "code"}:
                    calls.add(str(ref.get("name") or ref.get("addr") or ref)[:240])
    if isinstance(xrefs_json, list):
        for ref in xrefs_json:
            if not isinstance(ref, dict):
                continue
            ref_type = str(ref.get("type") or ref.get("perm") or "")
            if "CALL" in ref_type.upper() or "code" in ref_type.lower():
                calls.add(str(ref.get("name") or ref.get("from") or ref)[:240])
    return sorted(calls)[:200]


def _feature_hash(tokens: list[str]) -> str:
    joined = "\n".join(tokens)
    return hashlib.sha256(joined.encode("utf-8", errors="ignore")).hexdigest()


def _build_function_features(
    *,
    target: dict[str, Any],
    seek: str,
    resolved_function: dict[str, Any] | None,
    pseudocode: str,
    function_info_json: Any,
    disasm_json: Any,
    cfg_json: Any,
    xrefs_json: Any,
) -> dict[str, Any]:
    ops = _ops_from_disasm(disasm_json)
    blocks = _blocks_from_cfg(cfg_json)
    pseudocode_lines = [line for line in pseudocode.splitlines() if line.strip()]
    mnemonics = [
        str(op.get("type") or str(op.get("opcode") or "").split(" ", 1)[0])
        for op in ops
        if op.get("type") or op.get("opcode")
    ][:3000]
    block_edges = 0
    for block in blocks:
        if block.get("jump") is not None:
            block_edges += 1
        if block.get("fail") is not None:
            block_edges += 1
    string_refs = _extract_string_refs(ops, pseudocode)
    call_targets = _extract_call_targets(ops, xrefs_json)
    normalized_tokens = [
        str(target.get("library") or ""),
        str(target.get("name") or ""),
        *mnemonics,
        *call_targets,
        *string_refs,
        token_fingerprint(pseudocode),
    ]
    return {
        "schema_version": "2026-07-05.native-function-features.v1",
        "library": target.get("library"),
        "library_sha256": target.get("library_sha256"),
        "abi": target.get("abi"),
        "target_kind": target.get("kind"),
        "name": target.get("name"),
        "address": target.get("address"),
        "seek": seek,
        "resolved_name": (resolved_function or {}).get("name"),
        "resolved_offset": (resolved_function or {}).get("offset"),
        "score": target.get("score"),
        "capabilities": target.get("capabilities") or [],
        "reasons": target.get("reasons") or [],
        "instruction_count": len(ops),
        "basic_block_count": len(blocks),
        "cfg_edge_count": block_edges,
        "xref_count": _jsonish_len(xrefs_json, "xrefs"),
        "function_info_count": _jsonish_len(function_info_json, "functions"),
        "pseudocode_line_count": len(pseudocode.splitlines()),
        "pseudocode_nonempty_line_count": len(pseudocode_lines),
        "mnemonic_sample": mnemonics[:200],
        "call_targets": call_targets,
        "string_refs": string_refs,
        "pseudocode_fingerprint": token_fingerprint(pseudocode),
        "feature_hash": _feature_hash(normalized_tokens),
    }


def _run_rizin_like(
    tool: str,
    library_path: Path,
    target: dict[str, Any],
    output_path: Path,
    timeout: int,
    function_inventory: list[dict[str, Any]] | None = None,
    feature_detail: str = "full",
) -> dict[str, Any]:
    function_inventory = function_inventory or []
    target_name = str(target.get("name") or "")
    seek, resolved_function = _resolve_function_seek(
        target_name,
        target.get("address"),
        function_inventory,
    )
    pseudo_result = _run_rizin_command(tool, library_path, [f"pdc @ {seek}"], timeout)
    pseudocode = pseudo_result.get("stdout") or ""
    text = pseudocode or pseudo_result.get("stderr") or ""
    safe_write_text(output_path, text[-200_000:])
    if feature_detail not in {"pseudocode", "standard", "full"}:
        raise ValueError(f"Unknown native feature detail: {feature_detail}")
    function_info_json = None
    disasm_json = None
    cfg_json = None
    xrefs_json = None
    if feature_detail in {"standard", "full"}:
        function_info_json = _run_rizin_json(tool, library_path, f"afij @ {seek}", timeout)
        disasm_json = _run_rizin_json(tool, library_path, f"pdfj @ {seek}", timeout)
    if feature_detail == "full":
        cfg_json = _run_rizin_json(tool, library_path, f"agfj @ {seek}", timeout)
        xrefs_json = _run_rizin_json(tool, library_path, f"axtj @ {seek}", timeout)
    features = _build_function_features(
        target=target,
        seek=seek,
        resolved_function=resolved_function,
        pseudocode=pseudocode,
        function_info_json=function_info_json,
        disasm_json=disasm_json,
        cfg_json=cfg_json,
        xrefs_json=xrefs_json,
    )
    return {
        "success": int(pseudo_result.get("returncode") or 0) == 0 and bool(pseudocode.strip()),
        "tool": tool,
        "returncode": pseudo_result.get("returncode"),
        "output_path": str(output_path),
        "seek": seek,
        "resolved_function": resolved_function,
        "feature_detail": feature_detail,
        "function_features": features,
        "xrefs": xrefs_json if isinstance(xrefs_json, list) else [],
        "cfg_summary": {
            "basic_block_count": features["basic_block_count"],
            "cfg_edge_count": features["cfg_edge_count"],
            "instruction_count": features["instruction_count"],
        },
        "stderr_tail": str(pseudo_result.get("stderr") or "")[-2000:],
    }


def run_targeted_decompile(
    targets: list[dict[str, Any]],
    output_dir: Path,
    *,
    decompiler: str = "auto",
    timeout_per_function: int = 90,
    timeout_per_app: int = 3600,
    max_targets: int = 40,
    max_libraries: int = 8,
    target_capabilities: tuple[str, ...] | list[str] | set[str] = (),
    feature_detail: str = "full",
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Run optional native decompilation for ranked targets when a tool is installed."""

    ensure_dir(output_dir)
    max_targets = max(1, max_targets)
    max_libraries = max(1, max_libraries)
    plan = build_decompile_plan(
        targets,
        decompiler=decompiler,
        max_targets=max_targets,
        max_libraries=max_libraries,
        target_capabilities=target_capabilities,
    )
    safe_write_json(output_dir / "native_decompile_plan.json", plan)
    _emit_progress(
        progress_callback,
        {
            "event": "decompile_plan",
            "status": plan.get("status"),
            "selected_target_count": plan.get("selected_target_count"),
            "selected_libraries": plan.get("selected_libraries") or {},
            "feature_detail": feature_detail,
        },
    )

    if plan["status"] == "disabled":
        _emit_progress(progress_callback, {"event": "decompile_skipped", "status": "disabled"})
        return {
            "status": "disabled",
            "plan": plan,
            "message": "Native decompilation was disabled by configuration.",
            "attempted_targets": 0,
            "results": [],
        }

    tool = plan.get("toolchain", {}).get("selected_decompiler")
    if plan["status"] == "tool_missing":
        _emit_progress(progress_callback, {"event": "decompile_skipped", "status": "tool_missing"})
        return {
            "status": "tool_missing",
            "plan": plan,
            "requested_decompiler": decompiler,
            "message": "Install rizin, radare2, RetDec, or Ghidra headless to emit native pseudocode.",
            "attempted_targets": 0,
            "results": [],
        }

    if plan["status"] == "tool_present_not_automated":
        _emit_progress(progress_callback, {"event": "decompile_skipped", "status": "tool_present_not_automated"})
        return {
            "status": "tool_present_not_automated",
            "tool": tool,
            "plan": plan,
            "message": "The target selector ran; this adapter is reserved for a pinned decompiler setup.",
            "attempted_targets": 0,
            "results": [],
        }

    results: list[dict[str, Any]] = []
    executable = "rizin" if tool == "rizin" else "r2"
    start_time = time.monotonic()
    attempted_counts: Counter[str] = Counter()
    inventory_cache: dict[str, list[dict[str, Any]]] = {}
    budgeted = [target for target in plan.get("targets") or [] if isinstance(target, dict)]
    total_targets = len(budgeted)
    for index, target in enumerate(budgeted, start=1):
        if time.monotonic() - start_time > timeout_per_app:
            _emit_progress(progress_callback, {"event": "app_timeout", "attempted": len(results), "total": total_targets})
            results.append(
                {
                    "success": False,
                    "tool": executable,
                    "target": target,
                    "error": "app_timeout_budget_exhausted",
                }
            )
            break
        library_path = Path(str(target["library"]))
        if not library_path.exists():
            _emit_progress(
                progress_callback,
                {
                    "event": "target_finish",
                    "index": index,
                    "total": total_targets,
                    "success": False,
                    "error": "library_not_found",
                    "library": str(library_path),
                    "name": target.get("name"),
                },
            )
            results.append(
                {
                    "success": False,
                    "tool": executable,
                    "target": target,
                    "error": "library_not_found",
                }
            )
            continue
        attempted_counts[str(library_path)] += 1
        inventory = inventory_cache.get(str(library_path))
        if inventory is None:
            _emit_progress(
                progress_callback,
                {
                    "event": "inventory_start",
                    "library": str(library_path),
                    "tool": executable,
                    "timeout": min(timeout_per_function, 120),
                },
            )
            try:
                inventory = _load_function_inventory(executable, library_path, min(timeout_per_function, 120))
            except Exception:
                inventory = []
            inventory_cache[str(library_path)] = inventory
            _emit_progress(
                progress_callback,
                {
                    "event": "inventory_finish",
                    "library": str(library_path),
                    "function_count": len(inventory),
                },
            )
        output_path = output_dir / f"{safe_name(library_path.name)}__{safe_name(str(target['name']))}.c"
        target_start = time.monotonic()
        _emit_progress(
            progress_callback,
            {
                "event": "target_start",
                "index": index,
                "total": total_targets,
                "library": str(library_path),
                "name": target.get("name"),
                "score": target.get("score"),
                "timeout": timeout_per_function,
                "tool": executable,
                "feature_detail": feature_detail,
            },
        )
        try:
            result = _run_rizin_like(
                executable,
                library_path,
                target,
                output_path,
                timeout_per_function,
                function_inventory=inventory,
                feature_detail=feature_detail,
            )
            result["target"] = target
            results.append(result)
            _emit_progress(
                progress_callback,
                {
                    "event": "target_finish",
                    "index": index,
                    "total": total_targets,
                    "success": result.get("success"),
                    "library": str(library_path),
                    "name": target.get("name"),
                    "output_path": result.get("output_path"),
                    "elapsed_seconds": round(time.monotonic() - target_start, 2),
                    "pseudocode_nonempty_line_count": (result.get("function_features") or {}).get(
                        "pseudocode_nonempty_line_count"
                    ),
                    "instruction_count": (result.get("function_features") or {}).get("instruction_count"),
                },
            )
        except Exception as exc:
            _emit_progress(
                progress_callback,
                {
                    "event": "target_finish",
                    "index": index,
                    "total": total_targets,
                    "success": False,
                    "library": str(library_path),
                    "name": target.get("name"),
                    "error": repr(exc),
                    "elapsed_seconds": round(time.monotonic() - target_start, 2),
                },
            )
            results.append(
                {
                    "success": False,
                    "tool": executable,
                    "target": target,
                    "error": repr(exc),
                }
            )

    return {
        "status": "completed",
        "tool": executable,
        "plan": plan,
        "attempted_targets": len(budgeted),
        "libraries_attempted": dict(attempted_counts),
        "libraries_selected": plan.get("selected_libraries") or {},
        "budget": {
            "max_targets": max_targets,
            "max_libraries": max_libraries,
            "timeout_per_function": timeout_per_function,
            "timeout_per_app": timeout_per_app,
            "feature_detail": feature_detail,
        },
        "results": results,
    }
