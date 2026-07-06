"""Target selection and optional native decompiler adapters."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import time
from typing import Any

from .capability_taxonomy import capability_names, classify_text
from .utils import ensure_dir, run_cmd, safe_name, safe_write_text, tool_exists


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


def score_native_text(text: str) -> tuple[int, list[str], list[str]]:
    classified = classify_text(text)
    score = 0
    capabilities: list[str] = []
    reasons: list[str] = []
    lowered = text.lower()

    for capability, details in classified.items():
        capabilities.append(capability)
        score += int(details.get("score", 0))
        strong_hits = [str(item) for item in details.get("strong_hits", [])]
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
) -> list[dict[str, Any]]:
    """Rank native functions/libraries that are likely useful for deeper review."""

    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    desired_capabilities = {str(item) for item in target_capabilities if item}
    if max_libraries is not None:
        max_libraries = max(1, max_libraries)
    per_library_limit = max(1, per_library_limit)

    for library in library_records:
        lib_path = library.get("extracted_path") or library.get("path") or library.get("entry")
        if not lib_path:
            continue

        candidates: list[tuple[str, str]] = []
        for symbol in library.get("jni_symbols") or []:
            candidates.append(("jni_symbol", str(symbol)))
        for symbol in library.get("exported_symbols") or []:
            candidates.append(("exported_symbol", str(symbol)))
        for item in library.get("interesting_strings") or []:
            value = item.get("value") if isinstance(item, dict) else item
            if value:
                candidates.append(("string", str(value)))

        if not candidates:
            library_score, capabilities, reasons = score_native_text(str(lib_path))
            if library_score > 0:
                if desired_capabilities and desired_capabilities.intersection(capabilities):
                    library_score += 8
                    reasons.append("target_capability")
                targets.append(
                    {
                        "library": str(lib_path),
                        "kind": "library",
                        "name": Path(str(lib_path)).name,
                        "score": library_score,
                        "capabilities": capabilities,
                        "reasons": reasons,
                    }
                )
            continue

        for kind, name in candidates:
            key = (str(lib_path), name)
            if key in seen:
                continue
            seen.add(key)

            score, capabilities, reasons = score_native_text(f"{lib_path} {name}")
            if kind == "jni_symbol":
                score += 10
                reasons.append("jni_symbol")
            elif kind == "exported_symbol":
                score += 4
                reasons.append("exported_symbol")
            elif kind == "string":
                score += 2
                reasons.append("matched_string")
            if desired_capabilities and desired_capabilities.intersection(capabilities):
                score += 8
                reasons.append("target_capability")

            if score <= 0:
                continue

            targets.append(
                {
                    "library": str(lib_path),
                    "kind": kind,
                    "name": name,
                    "score": score,
                    "capabilities": capability_names(capabilities),
                    "reasons": sorted(set(reasons))[:12],
                }
            )

    targets.sort(key=lambda item: (-int(item["score"]), item["library"], item["name"]))
    if max_libraries:
        best_by_library: dict[str, int] = {}
        for target in targets:
            library = str(target.get("library") or "")
            best_by_library[library] = max(best_by_library.get(library, 0), int(target.get("score") or 0))
        allowed_libraries = {
            library
            for library, _ in sorted(best_by_library.items(), key=lambda item: (-item[1], item[0]))[:max_libraries]
        }
        targets = [target for target in targets if str(target.get("library") or "") in allowed_libraries]

    grouped: Counter[str] = Counter()
    budgeted: list[dict[str, Any]] = []
    for target in targets:
        library = str(target.get("library") or "")
        if grouped[library] >= per_library_limit:
            continue
        grouped[library] += 1
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


def _run_rizin_like(
    tool: str,
    library_path: Path,
    target_name: str,
    output_path: Path,
    timeout: int,
) -> dict[str, Any]:
    command = [
        tool,
        "-2",
        "-q",
        "-A",
        "-c",
        f"s {target_name}",
        "-c",
        "pdc",
        "-c",
        "q",
        str(library_path),
    ]
    completed = run_cmd(command, check=False, timeout=timeout)
    text = completed.stdout or completed.stderr
    safe_write_text(output_path, text[-200_000:])
    return {
        "success": completed.returncode == 0 and bool(completed.stdout.strip()),
        "tool": tool,
        "returncode": completed.returncode,
        "output_path": str(output_path),
        "stderr_tail": completed.stderr[-2000:],
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
) -> dict[str, Any]:
    """Run optional native decompilation for ranked targets when a tool is installed."""

    ensure_dir(output_dir)
    max_targets = max(1, max_targets)
    max_libraries = max(1, max_libraries)
    if decompiler == "none":
        return {
            "status": "disabled",
            "message": "Native decompilation was disabled by configuration.",
            "attempted_targets": 0,
            "results": [],
        }

    tool = available_decompiler(decompiler)
    if tool is None:
        return {
            "status": "tool_missing",
            "requested_decompiler": decompiler,
            "message": "Install rizin, radare2, RetDec, or Ghidra headless to emit native pseudocode.",
            "attempted_targets": 0,
            "results": [],
        }

    if tool in {"ghidra", "retdec"}:
        return {
            "status": "tool_present_not_automated",
            "tool": tool,
            "message": "The target selector ran; this adapter is reserved for a pinned decompiler setup.",
            "attempted_targets": 0,
            "results": [],
        }

    results: list[dict[str, Any]] = []
    desired_capabilities = {str(item) for item in target_capabilities if item}
    selected = [
        target
        for target in targets
        if target.get("kind") in {"jni_symbol", "exported_symbol"}
        and (not desired_capabilities or desired_capabilities.intersection(target.get("capabilities") or []))
    ]
    if not selected and desired_capabilities:
        selected = [
            target
            for target in targets
            if target.get("kind") in {"jni_symbol", "exported_symbol"}
        ]

    budgeted: list[dict[str, Any]] = []
    selection_counts: Counter[str] = Counter()
    for target in selected:
        library = str(target.get("library") or "")
        if len(selection_counts) >= max_libraries and selection_counts[library] == 0:
            continue
        per_library_budget = max(1, (max_targets + max_libraries - 1) // max_libraries)
        if selection_counts[library] >= per_library_budget:
            continue
        selection_counts[library] += 1
        budgeted.append(target)
        if len(budgeted) >= max_targets:
            break

    executable = "rizin" if tool == "rizin" else "r2"
    start_time = time.monotonic()
    attempted_counts: Counter[str] = Counter()
    for target in budgeted:
        if time.monotonic() - start_time > timeout_per_app:
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
        output_path = output_dir / f"{safe_name(library_path.name)}__{safe_name(str(target['name']))}.c"
        try:
            result = _run_rizin_like(
                executable,
                library_path,
                str(target["name"]),
                output_path,
                timeout_per_function,
            )
            result["target"] = target
            results.append(result)
        except Exception as exc:
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
        "attempted_targets": len(budgeted),
        "libraries_attempted": dict(attempted_counts),
        "libraries_selected": dict(selection_counts),
        "budget": {
            "max_targets": max_targets,
            "max_libraries": max_libraries,
            "timeout_per_function": timeout_per_function,
            "timeout_per_app": timeout_per_app,
        },
        "results": results,
    }
