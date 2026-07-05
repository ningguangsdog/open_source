"""Phase 2: JADX decompilation and Java/Kotlin evidence indexing."""

from __future__ import annotations

import re
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .capability_taxonomy import capability_names, classify_text
from .models import PhaseResult
from .utils import ensure_dir, reset_dir, run_cmd, safe_extract_zip, safe_name, safe_read_text, safe_write_json, tool_exists, zip_contains


JADX_RELEASE_URL = "https://github.com/skylot/jadx/releases/download/v{version}/jadx-{version}.zip"
SOURCE_EXTENSIONS = (".java", ".kt", ".xml")
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", re.MULTILINE)
IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z0-9_.*]+)\s*;", re.MULTILINE)
NATIVE_METHOD_RE = re.compile(
    r"\bnative\s+(?:[A-Za-z0-9_<>\[\].]+\s+)+([A-Za-z0-9_]+)\s*\(",
    re.MULTILINE,
)
LOAD_LIBRARY_RE = re.compile(r"System\.loadLibrary\(\s*\"([A-Za-z0-9_.-]+)\"")
MAX_FILE_CHARS = 250_000
MAX_SNIPPET_LEN = 240


def _apk_has_dex(apk_path: Path) -> bool:
    return zip_contains(apk_path, lambda name: name.lower().endswith(".dex"))


def _find_jadx_binary(tools_dir: Path, version: str) -> Path | None:
    candidates = [
        tools_dir / f"jadx-{version}" / "bin" / "jadx",
        tools_dir / "jadx" / "bin" / "jadx",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    for candidate in tools_dir.glob("**/bin/jadx"):
        if candidate.exists():
            return candidate
    return None


def _ensure_jadx(workspace: Path, version: str, no_download: bool) -> list[str]:
    if tool_exists("jadx"):
        return ["jadx"]

    tools_dir = ensure_dir(workspace / "tools")
    existing = _find_jadx_binary(tools_dir, version)
    if existing:
        return [str(existing)]

    if no_download:
        raise RuntimeError("jadx is not installed and automatic download is disabled")

    zip_path = tools_dir / f"jadx-{version}.zip"
    if not zip_path.exists():
        url = JADX_RELEASE_URL.format(version=version)
        urllib.request.urlretrieve(url, zip_path)

    extract_dir = tools_dir / f"jadx-{version}"
    if not extract_dir.exists():
        ensure_dir(extract_dir)
        safe_extract_zip(zip_path, extract_dir)

    binary = _find_jadx_binary(tools_dir, version)
    if not binary:
        raise RuntimeError(f"Could not locate jadx binary after extracting {zip_path}")
    try:
        binary.chmod(binary.stat().st_mode | 0o111)
    except OSError:
        pass
    return [str(binary)]


def _run_jadx_one(
    jadx_cmd: list[str],
    apk_path: Path,
    output_dir: Path,
    *,
    threads: int,
    force: bool,
) -> dict[str, Any]:
    if output_dir.exists() and any(output_dir.rglob("*.java")) and not force:
        return {
            "apk": str(apk_path),
            "output_dir": str(output_dir),
            "success": True,
            "cached": True,
        }

    if force:
        reset_dir(output_dir)
    else:
        ensure_dir(output_dir)

    cmd = [
        *jadx_cmd,
        "--show-bad-code",
        "--no-debug-info",
        "-j",
        str(threads),
        "-d",
        str(output_dir),
        str(apk_path),
    ]
    completed = run_cmd(cmd, check=False)
    return {
        "apk": str(apk_path),
        "output_dir": str(output_dir),
        "success": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def _snippet_lines(
    path: Path,
    text: str,
    capability_hits: dict[str, dict[str, object]],
    *,
    max_per_file: int = 12,
) -> list[dict[str, Any]]:
    wanted_keywords: dict[str, set[str]] = defaultdict(set)
    for capability, details in capability_hits.items():
        for hit in details.get("hits", []):
            wanted_keywords[capability].add(str(hit).lower())
        for hit in details.get("strong_hits", []):
            wanted_keywords[capability].add(str(hit).lower())

    snippets: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        line_caps = [
            capability
            for capability, keywords in wanted_keywords.items()
            if any(keyword in lowered for keyword in keywords)
        ]
        if not line_caps:
            continue
        snippets.append(
            {
                "file": str(path),
                "line": line_no,
                "capabilities": capability_names(line_caps),
                "text": line.strip()[:MAX_SNIPPET_LEN],
            }
        )
        if len(snippets) >= max_per_file:
            break
    return snippets


def _index_source_file(path: Path, root: Path) -> dict[str, Any] | None:
    text = safe_read_text(path, limit=MAX_FILE_CHARS)
    if not text:
        return None

    rel_path = path.relative_to(root)
    capability_hits = classify_text(f"{rel_path}\n{text}")
    package_match = PACKAGE_RE.search(text)
    imports = sorted(set(IMPORT_RE.findall(text)))[:100]
    native_methods = sorted(set(NATIVE_METHOD_RE.findall(text)))[:100]
    load_libraries = sorted(set(LOAD_LIBRARY_RE.findall(text)))[:100]
    urls = sorted(set(URL_RE.findall(text)))[:100]

    if not (capability_hits or native_methods or load_libraries or urls):
        return None

    return {
        "file": str(rel_path),
        "package": package_match.group(1) if package_match else None,
        "imports": imports,
        "native_methods": native_methods,
        "load_libraries": load_libraries,
        "urls": urls,
        "capabilities": capability_hits,
        "snippets": _snippet_lines(rel_path, text, capability_hits),
    }


def build_code_index(decompile_root: Path, *, max_snippets_per_capability: int = 40) -> dict[str, Any]:
    files_scanned = 0
    indexed_files: list[dict[str, Any]] = []
    capability_counts: Counter[str] = Counter()
    snippet_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    native_method_count = 0
    load_library_calls: Counter[str] = Counter()
    urls: Counter[str] = Counter()

    for path in decompile_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        files_scanned += 1
        record = _index_source_file(path, decompile_root)
        if not record:
            continue

        indexed_files.append(record)
        for capability in record["capabilities"]:
            capability_counts[capability] += 1
        native_method_count += len(record["native_methods"])
        load_library_calls.update(record["load_libraries"])
        urls.update(record["urls"])
        for snippet in record["snippets"]:
            for capability in snippet["capabilities"]:
                bucket = snippet_buckets[capability]
                if len(bucket) < max_snippets_per_capability:
                    bucket.append(snippet)

    indexed_files.sort(
        key=lambda item: (
            -sum(int(details.get("score", 0)) for details in item["capabilities"].values()),
            item["file"],
        )
    )

    return {
        "files_scanned": files_scanned,
        "indexed_file_count": len(indexed_files),
        "capability_counts": dict(sorted(capability_counts.items())),
        "load_library_calls": dict(load_library_calls.most_common(100)),
        "native_method_count": native_method_count,
        "urls": dict(urls.most_common(100)),
        "snippets_by_capability": {
            key: value
            for key, value in sorted(snippet_buckets.items())
        },
        "files": indexed_files[:1000],
        "files_truncated": len(indexed_files) > 1000,
    }


def run_phase2_multi(
    primary_apk: Path,
    all_apks: list[Path],
    workspace: Path,
    *,
    force: bool = False,
    jadx_version: str = "1.5.0",
    jadx_threads: int = 4,
    no_jadx_download: bool = False,
    decompile_all_splits: bool = True,
    max_snippets_per_capability: int = 40,
) -> PhaseResult:
    output_dir = ensure_dir(workspace / "phase2_jadx")
    decompile_root = ensure_dir(output_dir / "decompiled")
    summary_path = output_dir / "jadx_summary.json"
    index_path = output_dir / "code_index.json"

    if summary_path.exists() and index_path.exists() and not force:
        return PhaseResult(
            name="phase2_jadx",
            success=True,
            output_paths=[summary_path, index_path],
            details={"cached": True},
        )

    targets = [apk for apk in all_apks if _apk_has_dex(apk)]
    if not decompile_all_splits:
        targets = [primary_apk] if _apk_has_dex(primary_apk) else []

    warnings: list[str] = []
    if not targets:
        payload = {
            "primary_apk": str(primary_apk),
            "targets": [],
            "runs": [],
            "success": True,
            "message": "No dex-bearing APKs found.",
        }
        safe_write_json(summary_path, payload)
        safe_write_json(index_path, build_code_index(decompile_root))
        return PhaseResult(
            name="phase2_jadx",
            success=True,
            output_paths=[summary_path, index_path],
            details={"target_count": 0, "message": payload["message"]},
        )

    try:
        jadx_cmd = _ensure_jadx(workspace, jadx_version, no_jadx_download)
    except Exception as exc:
        payload = {
            "primary_apk": str(primary_apk),
            "targets": [str(path) for path in targets],
            "runs": [],
            "success": False,
            "error": repr(exc),
        }
        safe_write_json(summary_path, payload)
        return PhaseResult(
            name="phase2_jadx",
            success=False,
            output_paths=[summary_path],
            details={"target_count": len(targets)},
            error=repr(exc),
        )

    runs = [
        _run_jadx_one(
            jadx_cmd,
            apk_path,
            decompile_root / safe_name(apk_path.stem),
            threads=jadx_threads,
            force=force,
        )
        for apk_path in targets
    ]
    if any(not run["success"] for run in runs):
        warnings.append("One or more JADX runs returned a non-zero status.")

    code_index = build_code_index(
        decompile_root,
        max_snippets_per_capability=max_snippets_per_capability,
    )
    safe_write_json(index_path, code_index)

    payload = {
        "primary_apk": str(primary_apk),
        "targets": [str(path) for path in targets],
        "decompile_all_splits": decompile_all_splits,
        "jadx_command": jadx_cmd,
        "runs": runs,
        "success": all(run["success"] for run in runs),
        "code_index_path": str(index_path),
        "code_index_summary": {
            "files_scanned": code_index["files_scanned"],
            "indexed_file_count": code_index["indexed_file_count"],
            "capability_counts": code_index["capability_counts"],
            "native_method_count": code_index["native_method_count"],
            "load_library_count": len(code_index["load_library_calls"]),
            "url_count": len(code_index["urls"]),
        },
        "warnings": warnings,
    }
    safe_write_json(summary_path, payload)

    return PhaseResult(
        name="phase2_jadx",
        success=payload["success"],
        output_paths=[summary_path, index_path],
        details=payload["code_index_summary"],
        warnings=warnings,
    )


def run_phase2(
    apk_path: Path,
    workspace: Path,
    *,
    force: bool = False,
    jadx_version: str = "1.5.0",
    jadx_threads: int = 4,
    no_jadx_download: bool = False,
) -> PhaseResult:
    return run_phase2_multi(
        apk_path,
        [apk_path],
        workspace,
        force=force,
        jadx_version=jadx_version,
        jadx_threads=jadx_threads,
        no_jadx_download=no_jadx_download,
        decompile_all_splits=False,
    )
