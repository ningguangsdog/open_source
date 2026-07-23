"""Phase 2: JADX decompilation and complete Java/Kotlin evidence indexing."""

from __future__ import annotations

import re
import subprocess
import time
import urllib.request
import zipfile
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

from .capability_taxonomy import (
    SYMBOL_AFFIX_KEYWORDS,
    capability_names,
    classify_texts,
    keyword_matches_text,
)
from .code_ownership import classify_code_ownership, normalize_prefixes
from .evidence import capability_confidence, compact_list, token_fingerprint, unit_id
from .models import PhaseResult
from .run_context import (
    build_phase_cache_spec,
    cached_phase_result,
    load_valid_phase_cache,
    write_phase_cache,
)
from .utils import (
    ensure_dir,
    reset_dir,
    run_cmd,
    safe_extract_zip,
    safe_name,
    safe_write_json,
    sha256_file,
    tool_exists,
    zip_contains,
)


PHASE_SCHEMA = "2026-07-23.phase2.v3"
JADX_RELEASE_URL = (
    "https://github.com/skylot/jadx/releases/download/v{version}/jadx-{version}.zip"
)
SOURCE_EXTENSIONS = (".java", ".kt", ".xml")
CODE_EXTENSIONS = (".java", ".kt")
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
PACKAGE_RE = re.compile(
    r"^\s*package\s+([A-Za-z0-9_.]+)\s*;?",
    re.MULTILINE,
)
IMPORT_RE = re.compile(
    r"^\s*import\s+(?:static\s+)?([A-Za-z0-9_.*]+)\s*;?",
    re.MULTILINE,
)
CLASS_RE = re.compile(r"\b(?:class|interface|enum|object)\s+([A-Za-z0-9_$]+)")
METHOD_RE = re.compile(
    r"\b(?:public|private|protected|internal|static|final|native|"
    r"synchronized|abstract|open|override|suspend|\s)+"
    r"[A-Za-z0-9_<>\[\].?,\s:]+\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
    re.MULTILINE,
)
NATIVE_METHOD_RE = re.compile(
    r"\bnative\s+(?:[A-Za-z0-9_<>\[\].]+\s+)+([A-Za-z0-9_]+)\s*\(",
    re.MULTILINE,
)
LOAD_LIBRARY_RE = re.compile(r"System\.loadLibrary\(\s*\"([A-Za-z0-9_.-]+)\"")
ERROR_LINE_RE = re.compile(r"\b(error|exception|failed|failure)\b", re.IGNORECASE)
WARNING_LINE_RE = re.compile(r"\bwarn(?:ing)?\b", re.IGNORECASE)
MAX_SNIPPET_LEN = 240
MAX_SNIPPETS_PER_FILE = 12
SOURCE_CHUNK_CHARS = 250_000
SOURCE_CHUNK_OVERLAP = 4096
OWNERSHIP_ORDER = {
    "first_party": 0,
    "unknown": 1,
    "third_party": 2,
    "platform": 3,
}


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


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _dex_class_inventory(apk_path: Path) -> dict[str, Any]:
    """Read DEX header class_defs_size values without loading the full DEX."""

    records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    try:
        with zipfile.ZipFile(apk_path) as archive:
            for info in archive.infolist():
                if not info.filename.lower().endswith(".dex"):
                    continue
                try:
                    with archive.open(info) as fh:
                        header = fh.read(0x70)
                    if len(header) < 0x64 or not (
                        header.startswith(b"dex\n") or header.startswith(b"cdex")
                    ):
                        raise ValueError("Unrecognized or truncated DEX header")
                    class_defs_size = int.from_bytes(
                        header[0x60:0x64],
                        byteorder="little",
                        signed=False,
                    )
                    records.append(
                        {
                            "path": info.filename,
                            "class_defs_size": class_defs_size,
                            "size_bytes": info.file_size,
                        }
                    )
                except Exception as exc:
                    errors.append(
                        {
                            "path": info.filename,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
    except Exception as exc:
        errors.append(
            {
                "path": str(apk_path),
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
    return {
        "dex_count": len(records),
        "expected_class_defs": sum(
            int(record["class_defs_size"]) for record in records
        ),
        "dex_files": records,
        "errors": errors,
    }


def _source_output_inventory(output_dir: Path) -> dict[str, Any]:
    extension_counts: Counter[str] = Counter()
    total_bytes = 0
    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue
        extension_counts[path.suffix.lower() or "<none>"] += 1
        try:
            total_bytes += path.stat().st_size
        except OSError:
            continue
    source_file_count = sum(extension_counts[extension] for extension in CODE_EXTENSIONS)
    return {
        "source_file_count": source_file_count,
        "java_file_count": extension_counts[".java"],
        "kotlin_file_count": extension_counts[".kt"],
        "xml_file_count": extension_counts[".xml"],
        "total_output_file_count": sum(extension_counts.values()),
        "total_output_bytes": total_bytes,
        "extension_counts": dict(sorted(extension_counts.items())),
    }


def _diagnostic_counts(*streams: str) -> dict[str, int]:
    lines = [
        line
        for stream in streams
        for line in stream.splitlines()
        if line.strip()
    ]
    return {
        "error_count": sum(1 for line in lines if ERROR_LINE_RE.search(line)),
        "warning_count": sum(1 for line in lines if WARNING_LINE_RE.search(line)),
    }


def _coverage_estimate(
    generated_source_count: int,
    expected_class_defs: int,
) -> dict[str, Any]:
    if expected_class_defs <= 0:
        return {
            "value": None,
            "method": "unavailable",
            "note": "No valid DEX class_defs_size denominator was available.",
        }
    return {
        "value": round(min(1.0, generated_source_count / expected_class_defs), 4),
        "method": "generated_java_kotlin_files_over_dex_class_defs",
        "numerator": generated_source_count,
        "denominator": expected_class_defs,
        "note": (
            "This is a reproducible coverage proxy, not a one-to-one class recovery "
            "measurement; one source file can contain multiple classes."
        ),
    }


def _run_jadx_one(
    jadx_cmd: list[str],
    apk_path: Path,
    output_dir: Path,
    *,
    threads: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    ensure_dir(output_dir)
    dex_inventory = _dex_class_inventory(apk_path)
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
    started = time.monotonic()
    stdout = ""
    stderr = ""
    returncode: int | None = None
    timed_out = False
    execution_error: str | None = None
    try:
        completed = run_cmd(cmd, check=False, timeout=timeout_seconds)
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = _as_text(exc.stdout)
        stderr = _as_text(exc.stderr)
        execution_error = (
            f"JADX exceeded the per-APK timeout of {timeout_seconds} seconds."
        )
    except Exception as exc:
        execution_error = f"{type(exc).__name__}: {exc}"

    duration_seconds = round(time.monotonic() - started, 3)
    output_inventory = _source_output_inventory(output_dir)
    generated_sources = int(output_inventory["source_file_count"])
    if returncode == 0 and not timed_out and generated_sources > 0:
        status = "success"
    elif generated_sources > 0:
        status = "partial"
    else:
        status = "failed"
    diagnostics = _diagnostic_counts(stdout, stderr)
    coverage = _coverage_estimate(
        generated_sources,
        int(dex_inventory["expected_class_defs"]),
    )
    return {
        "apk": str(apk_path),
        "output_dir": str(output_dir),
        "status": status,
        "success": status == "success",
        "usable_output": generated_sources > 0,
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "duration_seconds": duration_seconds,
        "returncode": returncode,
        "execution_error": execution_error,
        **diagnostics,
        **output_inventory,
        "successful_decompiled_file_count": generated_sources,
        "dex_inventory": dex_inventory,
        "estimated_coverage": coverage,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
    }


def _snippet_lines(
    source_path: Path,
    display_path: Path,
    capability_hits: dict[str, dict[str, object]],
    *,
    max_per_file: int = MAX_SNIPPETS_PER_FILE,
) -> dict[str, Any]:
    wanted_keywords: dict[str, dict[str, bool]] = defaultdict(dict)
    for capability, details in capability_hits.items():
        strong_hits = {str(hit).lower() for hit in details.get("strong_hits", [])}
        for hit in details.get("hits", []):
            keyword = str(hit).lower()
            wanted_keywords[capability][keyword] = (
                keyword in strong_hits and keyword in SYMBOL_AFFIX_KEYWORDS
            )

    candidates: list[dict[str, Any]] = []
    candidate_counts: Counter[str] = Counter()
    with source_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line_caps = [
                capability
                for capability, keywords in wanted_keywords.items()
                if any(
                    keyword_matches_text(
                        line,
                        keyword,
                        allow_symbol_affix=allow_affix,
                    )
                    for keyword, allow_affix in keywords.items()
                )
            ]
            if not line_caps:
                continue
            candidate_counts.update(line_caps)
            candidates.append(
                {
                    "file": str(display_path),
                    "line": line_no,
                    "capabilities": capability_names(line_caps),
                    "text": line.strip()[:MAX_SNIPPET_LEN],
                }
            )
    selected = candidates[:max_per_file]
    return {
        "selected": selected,
        "candidate_count": len(candidates),
        "candidate_count_by_capability": dict(sorted(candidate_counts.items())),
        "selected_count": len(selected),
        "excluded_count": max(0, len(candidates) - len(selected)),
        "selection_rule": (
            f"first_{max_per_file}_matching_lines_per_file; "
            "full source remains available in phase2_jadx/decompiled"
        ),
    }


def _read_source_chunks(path: Path) -> tuple[list[str], dict[str, int]]:
    chunks: list[str] = []
    carry = ""
    char_count = 0
    newline_count = 0
    last_character = ""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        while True:
            raw = fh.read(SOURCE_CHUNK_CHARS)
            if not raw:
                break
            char_count += len(raw)
            newline_count += raw.count("\n")
            last_character = raw[-1]
            chunks.append(carry + raw)
            carry = (carry + raw)[-SOURCE_CHUNK_OVERLAP:]
    line_count = newline_count + (
        1 if char_count and last_character != "\n" else 0
    )
    return chunks, {
        "char_count": char_count,
        "line_count": line_count,
        "chunk_count": len(chunks),
        "chunk_size_chars": SOURCE_CHUNK_CHARS,
        "chunk_overlap_chars": SOURCE_CHUNK_OVERLAP,
    }


def _empty_source_record(path: Path, root: Path, error: Exception) -> dict[str, Any]:
    rel_path = path.relative_to(root)
    return {
        "file": str(rel_path),
        "source_type": path.suffix.lower().lstrip("."),
        "read_status": "failed",
        "read_error": f"{type(error).__name__}: {error}",
        "size_bytes": path.stat().st_size if path.exists() else None,
        "sha256": None,
        "package": None,
        "class_name": path.stem,
        "class_names": [],
        "method_names": [],
        "imports": [],
        "native_methods": [],
        "load_libraries": [],
        "urls": [],
        "capabilities": {},
        "ownership": classify_code_ownership(None, rel_path).to_dict(),
        "snippets": [],
        "snippet_selection": {
            "candidate_count": 0,
            "candidate_count_by_capability": {},
            "selected_count": 0,
            "excluded_count": 0,
            "selection_rule": "source_read_failed",
        },
    }


def _index_source_file(
    path: Path,
    root: Path,
    *,
    app_package: str | None,
    first_party_prefixes: Iterable[str],
    third_party_prefixes: Iterable[str],
) -> dict[str, Any]:
    rel_path = path.relative_to(root)
    try:
        chunks, chunk_metadata = _read_source_chunks(path)
    except Exception as exc:
        record = _empty_source_record(path, root, exc)
        record["ownership"] = classify_code_ownership(
            None,
            rel_path,
            app_package=app_package,
            first_party_prefixes=first_party_prefixes,
            third_party_prefixes=third_party_prefixes,
        ).to_dict()
        return record

    scan_chunks = [str(rel_path), *chunks]
    capability_hits = classify_texts(scan_chunks)
    package_match = next(
        (match for chunk in chunks if (match := PACKAGE_RE.search(chunk))),
        None,
    )
    package = package_match.group(1) if package_match else None
    path_parts = rel_path.parts
    inferred_path_package = None
    if "sources" in path_parts:
        source_index = path_parts.index("sources")
        package_parts = path_parts[source_index + 1 : -1]
        if package_parts:
            inferred_path_package = ".".join(package_parts)
    class_names = sorted(
        {
            name
            for chunk in chunks
            for name in CLASS_RE.findall(chunk)
        }
    )
    method_names = sorted(
        {
            name
            for chunk in chunks
            for name in METHOD_RE.findall(chunk)
        }
    )
    snippet_selection = _snippet_lines(
        path,
        rel_path,
        capability_hits,
    )
    ownership = classify_code_ownership(
        package or inferred_path_package,
        rel_path,
        app_package=app_package,
        first_party_prefixes=first_party_prefixes,
        third_party_prefixes=third_party_prefixes,
    ).to_dict()
    snippets = snippet_selection["selected"]
    for snippet in snippets:
        snippet["package"] = package
        snippet["ownership"] = ownership["category"]
        snippet["source_type"] = path.suffix.lower().lstrip(".")

    return {
        "file": str(rel_path),
        "source_type": path.suffix.lower().lstrip("."),
        "read_status": "success",
        "read_error": None,
        "size_bytes": path.stat().st_size,
        **chunk_metadata,
        "indexing_mode": "complete_overlapping_chunks_with_method_level_parsing",
        "sha256": sha256_file(path),
        "package": package,
        "path_inferred_package": inferred_path_package,
        "class_name": class_names[0] if class_names else path.stem,
        "class_names": class_names,
        "method_names": method_names,
        "imports": sorted(
            {
                value
                for chunk in chunks
                for value in IMPORT_RE.findall(chunk)
            }
        ),
        "native_methods": sorted(
            {
                value
                for chunk in chunks
                for value in NATIVE_METHOD_RE.findall(chunk)
            }
        ),
        "load_libraries": sorted(
            {
                value
                for chunk in chunks
                for value in LOAD_LIBRARY_RE.findall(chunk)
            }
        ),
        "urls": sorted(
            {
                value
                for chunk in chunks
                for value in URL_RE.findall(chunk)
            }
        ),
        "capabilities": capability_hits,
        "ownership": ownership,
        "snippets": snippets,
        "snippet_selection": {
            key: value
            for key, value in snippet_selection.items()
            if key != "selected"
        },
    }


def _split_name(rel_path: str) -> str | None:
    parts = Path(rel_path).parts
    return parts[0] if parts else None


def _file_unit_kind(record: dict[str, Any]) -> str:
    if record.get("native_methods") or record.get("load_libraries"):
        return "native_bridge"
    file_name = str(record.get("file") or "").lower()
    if file_name.endswith(".xml"):
        return "resource_source"
    return "source_file"


def _signature_for_record(record: dict[str, Any]) -> str:
    package = record.get("package")
    class_name = record.get("class_name")
    if package and class_name:
        return f"{package}.{class_name}"
    return str(record.get("file") or class_name or "")


def _capability_metrics(
    records: list[dict[str, Any]],
    capability_counts: Counter[str],
) -> dict[str, Any]:
    readable = [record for record in records if record.get("read_status") == "success"]
    file_denominator = len(readable)
    method_denominator = sum(len(record.get("method_names") or []) for record in readable)
    method_counts: Counter[str] = Counter()
    for record in readable:
        method_count = len(record.get("method_names") or [])
        for capability in (record.get("capabilities") or {}):
            method_counts[capability] += method_count

    metrics: dict[str, Any] = {}
    for capability in sorted(capability_counts):
        file_count = int(capability_counts[capability])
        methods_in_matching_files = int(method_counts[capability])
        metrics[capability] = {
            "matching_file_count": file_count,
            "file_prevalence": (
                round(file_count / file_denominator, 6)
                if file_denominator
                else 0.0
            ),
            "matching_files_per_1000": (
                round(file_count * 1000 / file_denominator, 3)
                if file_denominator
                else 0.0
            ),
            "methods_in_matching_files": methods_in_matching_files,
            "methods_in_matching_files_per_1000_indexed_methods": (
                round(methods_in_matching_files * 1000 / method_denominator, 3)
                if method_denominator
                else 0.0
            ),
        }
    return {
        "file_denominator": file_denominator,
        "method_denominator": method_denominator,
        "method_metric_note": (
            "Method normalization counts methods contained in capability-matching "
            "files; it does not claim every method implements that capability."
        ),
        "capabilities": metrics,
    }


def _stratified_snippet_sample(
    snippets: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    buckets: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)
    for snippet in snippets:
        key = (
            str(snippet.get("ownership") or "unknown"),
            str(snippet.get("package") or "<unknown>"),
        )
        buckets[key].append(snippet)
    ordered_keys = sorted(
        buckets,
        key=lambda key: (
            OWNERSHIP_ORDER.get(key[0], 99),
            key[1],
        ),
    )
    selected: list[dict[str, Any]] = []
    while len(selected) < limit and ordered_keys:
        next_keys: list[tuple[str, str]] = []
        for key in ordered_keys:
            bucket = buckets[key]
            if bucket and len(selected) < limit:
                selected.append(bucket.popleft())
            if bucket:
                next_keys.append(key)
        ordered_keys = next_keys
    return selected


def build_java_package_index(code_index: dict[str, Any]) -> dict[str, Any]:
    packages: dict[str, dict[str, Any]] = {}
    ownership_counts: Counter[str] = Counter()
    for record in code_index.get("files") or []:
        if (
            record.get("read_status") != "success"
            or record.get("source_type") not in {"java", "kt"}
        ):
            continue
        package = record.get("package") or "<unknown>"
        ownership = (record.get("ownership") or {}).get("category") or "unknown"
        ownership_counts[ownership] += 1
        entry = packages.setdefault(
            package,
            {
                "file_count": 0,
                "capabilities": Counter(),
                "native_libraries": Counter(),
                "native_method_count": 0,
                "url_count": 0,
                "sample_files": [],
                "ownership": record.get("ownership") or {},
            },
        )
        entry["file_count"] += 1
        entry["capabilities"].update((record.get("capabilities") or {}).keys())
        entry["native_libraries"].update(record.get("load_libraries") or [])
        entry["native_method_count"] += len(record.get("native_methods") or [])
        entry["url_count"] += len(record.get("urls") or [])
        if len(entry["sample_files"]) < 20:
            entry["sample_files"].append(record.get("file"))

    normalized: dict[str, Any] = {}
    for package, entry in sorted(packages.items()):
        normalized[package] = {
            "file_count": entry["file_count"],
            "ownership": entry["ownership"],
            "capabilities": dict(entry["capabilities"].most_common()),
            "native_libraries": dict(entry["native_libraries"].most_common()),
            "native_method_count": entry["native_method_count"],
            "url_count": entry["url_count"],
            "sample_files": [item for item in entry["sample_files"] if item],
        }
    return {
        "package_count": len(normalized),
        "ownership_file_counts": dict(sorted(ownership_counts.items())),
        "packages": normalized,
    }


def build_java_evidence_units(code_index: dict[str, Any]) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    for record in code_index.get("files") or []:
        if record.get("read_status") != "success":
            continue
        capabilities = capability_names((record.get("capabilities") or {}).keys())
        snippets = record.get("snippets") or []
        text_for_hash = "\n".join(
            [
                str(record.get("file") or ""),
                str(record.get("package") or ""),
                " ".join(record.get("imports") or []),
                " ".join(record.get("method_names") or []),
                "\n".join(
                    str(item.get("text") or "")
                    for item in snippets
                    if isinstance(item, dict)
                ),
            ]
        )
        units.append(
            {
                "unit_id": unit_id("java", record.get("file")),
                "phase": "phase2_jadx",
                "kind": _file_unit_kind(record),
                "file": record.get("file"),
                "source_type": record.get("source_type"),
                "split": _split_name(str(record.get("file") or "")),
                "package": record.get("package"),
                "ownership": record.get("ownership") or {},
                "class_name": record.get("class_name"),
                "method_names": compact_list(record.get("method_names") or [], 80),
                "normalized_signature": _signature_for_record(record),
                "capabilities": capabilities,
                "imports": compact_list(record.get("imports") or [], 80),
                "native_libraries": compact_list(
                    record.get("load_libraries") or [],
                    80,
                ),
                "native_methods": compact_list(record.get("native_methods") or [], 80),
                "urls": compact_list(record.get("urls") or [], 40),
                "snippets": snippets,
                "token_fingerprint": token_fingerprint(text_for_hash),
                "confidence": capability_confidence(capabilities, len(snippets)),
                "representation": (
                    "compact evidence unit; complete lists and source metadata are "
                    "stored in code_index.json"
                ),
            }
        )

    for capability, snippets in (code_index.get("snippets_by_capability") or {}).items():
        for snippet in snippets:
            units.append(
                {
                    "unit_id": unit_id(
                        "java_snippet",
                        capability,
                        snippet.get("file"),
                        snippet.get("line"),
                        snippet.get("text"),
                    ),
                    "phase": "phase2_jadx",
                    "kind": "code_snippet",
                    "file": snippet.get("file"),
                    "source_type": snippet.get("source_type"),
                    "line": snippet.get("line"),
                    "package": snippet.get("package"),
                    "ownership": {
                        "category": snippet.get("ownership") or "unknown",
                    },
                    "capabilities": capability_names([capability]),
                    "text": snippet.get("text"),
                    "token_fingerprint": token_fingerprint(
                        str(snippet.get("text") or "")
                    ),
                    "confidence": 0.65,
                }
            )

    units.sort(
        key=lambda item: (
            OWNERSHIP_ORDER.get(
                str((item.get("ownership") or {}).get("category") or "unknown"),
                99,
            ),
            -float(item.get("confidence") or 0),
            item.get("kind") or "",
            item.get("file") or "",
        )
    )
    return units


def build_code_index(
    decompile_root: Path,
    *,
    max_snippets_per_capability: int = 40,
    app_package: str | None = None,
    first_party_prefixes: Iterable[str] = (),
    third_party_prefixes: Iterable[str] = (),
) -> dict[str, Any]:
    if max_snippets_per_capability < 0:
        raise ValueError("max_snippets_per_capability must be zero or greater")
    first_party_prefixes = tuple(first_party_prefixes)
    third_party_prefixes = tuple(third_party_prefixes)
    conflicting_prefixes = set(normalize_prefixes(first_party_prefixes)).intersection(
        normalize_prefixes(third_party_prefixes)
    )
    if conflicting_prefixes:
        raise ValueError(
            "Package prefixes cannot be both first-party and third-party: "
            + ", ".join(sorted(conflicting_prefixes))
        )
    source_paths = sorted(
        (
            path
            for path in decompile_root.rglob("*")
            if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
        ),
        key=lambda path: str(path.relative_to(decompile_root)),
    )
    records = [
        _index_source_file(
            path,
            decompile_root,
            app_package=app_package,
            first_party_prefixes=first_party_prefixes,
            third_party_prefixes=third_party_prefixes,
        )
        for path in source_paths
    ]
    readable_records = [
        record for record in records if record.get("read_status") == "success"
    ]
    failed_records = [
        record for record in records if record.get("read_status") != "success"
    ]
    capability_counts: Counter[str] = Counter()
    comparison_capability_counts: Counter[str] = Counter()
    dependency_capability_counts: Counter[str] = Counter()
    non_code_capability_counts: Counter[str] = Counter()
    ownership_file_counts: Counter[str] = Counter()
    ownership_code_file_counts: Counter[str] = Counter()
    capability_by_ownership: dict[str, Counter[str]] = defaultdict(Counter)
    snippet_candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
    snippet_line_candidate_counts: Counter[str] = Counter()
    native_method_count = 0
    load_library_calls: Counter[str] = Counter()
    urls: Counter[str] = Counter()

    for record in readable_records:
        ownership = (record.get("ownership") or {}).get("category") or "unknown"
        is_code = record.get("source_type") in {"java", "kt"}
        ownership_file_counts[ownership] += 1
        if is_code:
            ownership_code_file_counts[ownership] += 1
        capabilities = list((record.get("capabilities") or {}).keys())
        capability_counts.update(capabilities)
        capability_by_ownership[ownership].update(capabilities)
        if not is_code:
            non_code_capability_counts.update(capabilities)
        elif ownership in {"first_party", "unknown"}:
            comparison_capability_counts.update(capabilities)
        else:
            dependency_capability_counts.update(capabilities)
        native_method_count += len(record.get("native_methods") or [])
        load_library_calls.update(record.get("load_libraries") or [])
        urls.update(record.get("urls") or [])
        selection = record.get("snippet_selection") or {}
        for capability, count in (
            selection.get("candidate_count_by_capability") or {}
        ).items():
            snippet_line_candidate_counts[str(capability)] += int(count)
        for snippet in record.get("snippets") or []:
            for capability in snippet.get("capabilities") or []:
                snippet_candidates[capability].append(snippet)

    selected_snippets: dict[str, list[dict[str, Any]]] = {}
    snippet_selection: dict[str, dict[str, Any]] = {}
    for capability, candidates in sorted(snippet_candidates.items()):
        selected = _stratified_snippet_sample(
            candidates,
            max_snippets_per_capability,
        )
        selected_snippets[capability] = selected
        snippet_selection[capability] = {
            "line_candidate_count": int(snippet_line_candidate_counts[capability]),
            "retained_per_file_sample_count": len(candidates),
            "selected_count": len(selected),
            "excluded_line_count": max(
                0,
                int(snippet_line_candidate_counts[capability]) - len(selected),
            ),
            "selection_rule": (
                f"retain_first_{MAX_SNIPPETS_PER_FILE}_matches_per_file_then_"
                "round_robin_by_ownership_and_package; priority order "
                "first_party, unknown, third_party, platform; full source is retained"
            ),
            "limit": max_snippets_per_capability,
        }

    records.sort(
        key=lambda item: (
            OWNERSHIP_ORDER.get(
                str((item.get("ownership") or {}).get("category") or "unknown"),
                99,
            ),
            -sum(
                int(details.get("score", 0))
                for details in (item.get("capabilities") or {}).values()
            ),
            str(item.get("file") or ""),
        )
    )
    return {
        "schema_version": PHASE_SCHEMA,
        "app_package": app_package,
        "files_scanned": len(source_paths),
        "indexed_file_count": len(readable_records),
        "failed_file_count": len(failed_records),
        "index_coverage": (
            round(len(readable_records) / len(source_paths), 6)
            if source_paths
            else 1.0
        ),
        "files_truncated": False,
        "files_excluded_count": len(failed_records),
        "excluded_files": [
            {
                "file": record.get("file"),
                "reason": record.get("read_error") or "source_read_failed",
            }
            for record in failed_records
        ],
        "capability_counts": dict(sorted(capability_counts.items())),
        "comparison_capability_counts": dict(
            sorted(comparison_capability_counts.items())
        ),
        "excluded_dependency_capability_counts": dict(
            sorted(dependency_capability_counts.items())
        ),
        "non_code_capability_counts": dict(
            sorted(non_code_capability_counts.items())
        ),
        "capability_counts_by_ownership": {
            ownership: dict(sorted(counter.items()))
            for ownership, counter in sorted(capability_by_ownership.items())
        },
        "capability_metrics": _capability_metrics(
            readable_records,
            capability_counts,
        ),
        "comparison_capability_metrics": _capability_metrics(
            [
                record
                for record in readable_records
                if record.get("source_type") in {"java", "kt"}
                and (record.get("ownership") or {}).get("category")
                in {"first_party", "unknown"}
            ],
            comparison_capability_counts,
        ),
        "ownership_file_counts": dict(sorted(ownership_file_counts.items())),
        "ownership_code_file_counts": dict(
            sorted(ownership_code_file_counts.items())
        ),
        "ownership_policy": {
            "comparison_source_types": ["java", "kt"],
            "comparison_included": ["first_party", "unknown"],
            "comparison_excluded_by_default": ["third_party", "platform"],
            "non_code_evidence_note": (
                "XML is retained in the complete discovery index but excluded from "
                "Java/Kotlin implementation counts and similarity-facing snippets."
            ),
            "unknown_inclusion_note": (
                "Unknown code remains in comparison evidence to avoid silently "
                "discarding obfuscated first-party code."
            ),
        },
        "load_library_calls": dict(load_library_calls.most_common()),
        "native_method_count": native_method_count,
        "urls": dict(urls.most_common()),
        "snippets_by_capability": selected_snippets,
        "snippet_selection": snippet_selection,
        "files": records,
    }


def _load_manifest_package(workspace: Path) -> str | None:
    path = workspace / "phase1_manifest" / "manifest_summary.json"
    try:
        import json

        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    package = payload.get("package") if isinstance(payload, dict) else None
    return str(package).strip() if package else None


def _aggregate_run_coverage(runs: list[dict[str, Any]]) -> dict[str, Any]:
    numerator = sum(int(run.get("source_file_count") or 0) for run in runs)
    denominator = sum(
        int((run.get("dex_inventory") or {}).get("expected_class_defs") or 0)
        for run in runs
    )
    return _coverage_estimate(numerator, denominator)


def run_phase2_multi(
    primary_apk: Path,
    all_apks: list[Path],
    workspace: Path,
    *,
    force: bool = False,
    jadx_version: str = "1.5.0",
    jadx_threads: int = 4,
    jadx_timeout_per_apk: int = 1800,
    no_jadx_download: bool = False,
    decompile_all_splits: bool = True,
    max_snippets_per_capability: int = 40,
    first_party_prefixes: Iterable[str] = (),
    third_party_prefixes: Iterable[str] = (),
    run_context: dict[str, Any] | None = None,
) -> PhaseResult:
    if jadx_threads <= 0:
        raise ValueError("jadx_threads must be a positive integer")
    if jadx_timeout_per_apk <= 0:
        raise ValueError("jadx_timeout_per_apk must be a positive integer")
    if max_snippets_per_capability < 0:
        raise ValueError("max_snippets_per_capability must be zero or greater")
    first_party_prefixes = tuple(first_party_prefixes)
    third_party_prefixes = tuple(third_party_prefixes)
    conflicting_prefixes = set(normalize_prefixes(first_party_prefixes)).intersection(
        normalize_prefixes(third_party_prefixes)
    )
    if conflicting_prefixes:
        raise ValueError(
            "Package prefixes cannot be both first-party and third-party: "
            + ", ".join(sorted(conflicting_prefixes))
        )
    output_dir = ensure_dir(workspace / "phase2_jadx")
    decompile_root = output_dir / "decompiled"
    summary_path = output_dir / "jadx_summary.json"
    index_path = output_dir / "code_index.json"
    evidence_path = output_dir / "java_evidence_units.json"
    package_index_path = output_dir / "java_package_index.json"
    cache_path = output_dir / "cache_manifest.json"
    manifest_path = workspace / "phase1_manifest" / "manifest_summary.json"
    app_package = _load_manifest_package(workspace)

    output_paths = [summary_path, index_path, evidence_path, package_index_path]
    cache_spec = build_phase_cache_spec(
        phase="phase2_jadx",
        phase_schema=PHASE_SCHEMA,
        phase_config={
            "jadx_version": jadx_version,
            "jadx_threads": jadx_threads,
            "jadx_timeout_per_apk": jadx_timeout_per_apk,
            "jadx_download": not no_jadx_download,
            "decompile_all_splits": decompile_all_splits,
            "max_snippets_per_capability": max_snippets_per_capability,
            "app_package": app_package,
            "first_party_prefixes": sorted(first_party_prefixes),
            "third_party_prefixes": sorted(third_party_prefixes),
        },
        input_paths=all_apks,
        upstream_paths=[manifest_path],
        run_context=run_context,
    )
    if not force:
        cached = load_valid_phase_cache(cache_path, cache_spec, output_paths)
        if cached:
            return cached_phase_result("phase2_jadx", output_paths, cached)

    reset_dir(decompile_root)
    targets = [apk for apk in all_apks if _apk_has_dex(apk)]
    if not decompile_all_splits:
        targets = [primary_apk] if _apk_has_dex(primary_apk) else []

    if not targets:
        code_index = build_code_index(
            decompile_root,
            max_snippets_per_capability=max_snippets_per_capability,
            app_package=app_package,
            first_party_prefixes=first_party_prefixes,
            third_party_prefixes=third_party_prefixes,
        )
        java_evidence_units = build_java_evidence_units(code_index)
        package_index = build_java_package_index(code_index)
        payload = {
            "primary_apk": str(primary_apk),
            "targets": [],
            "runs": [],
            "success": True,
            "status": "success",
            "message": "No dex-bearing APKs found.",
            "app_package": app_package,
        }
        safe_write_json(summary_path, payload)
        safe_write_json(index_path, code_index)
        safe_write_json(evidence_path, java_evidence_units)
        safe_write_json(package_index_path, package_index)
        result = PhaseResult(
            name="phase2_jadx",
            success=True,
            status="success",
            output_paths=output_paths,
            details={"target_count": 0, "message": payload["message"]},
        )
        write_phase_cache(cache_path, cache_spec, output_paths, result)
        return result

    try:
        jadx_cmd = _ensure_jadx(workspace, jadx_version, no_jadx_download)
    except Exception as exc:
        code_index = build_code_index(
            decompile_root,
            max_snippets_per_capability=max_snippets_per_capability,
            app_package=app_package,
            first_party_prefixes=first_party_prefixes,
            third_party_prefixes=third_party_prefixes,
        )
        payload = {
            "primary_apk": str(primary_apk),
            "targets": [str(path) for path in targets],
            "runs": [],
            "success": False,
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
            "code_index_path": str(index_path),
            "java_evidence_units_path": str(evidence_path),
            "java_package_index_path": str(package_index_path),
        }
        safe_write_json(summary_path, payload)
        safe_write_json(index_path, code_index)
        safe_write_json(evidence_path, [])
        safe_write_json(package_index_path, build_java_package_index(code_index))
        result = PhaseResult(
            name="phase2_jadx",
            success=False,
            status="failed",
            output_paths=output_paths,
            details={"target_count": len(targets), "usable_target_count": 0},
            error=payload["error"],
        )
        write_phase_cache(cache_path, cache_spec, output_paths, result)
        return result

    runs = [
        _run_jadx_one(
            jadx_cmd,
            apk_path,
            decompile_root
            / f"{safe_name(apk_path.stem)}-{sha256_file(apk_path)[:12]}",
            threads=jadx_threads,
            timeout_seconds=jadx_timeout_per_apk,
        )
        for apk_path in targets
    ]
    code_index = build_code_index(
        decompile_root,
        max_snippets_per_capability=max_snippets_per_capability,
        app_package=app_package,
        first_party_prefixes=first_party_prefixes,
        third_party_prefixes=third_party_prefixes,
    )
    java_evidence_units = build_java_evidence_units(code_index)
    package_index = build_java_package_index(code_index)
    safe_write_json(index_path, code_index)
    safe_write_json(evidence_path, java_evidence_units)
    safe_write_json(package_index_path, package_index)

    successful_runs = sum(1 for run in runs if run.get("status") == "success")
    partial_runs = sum(1 for run in runs if run.get("status") == "partial")
    failed_runs = sum(1 for run in runs if run.get("status") == "failed")
    usable_runs = successful_runs + partial_runs
    if successful_runs == len(runs):
        status = "success"
    elif usable_runs:
        status = "partial"
    else:
        status = "failed"
    warnings = [
        (
            f"{run['apk']}: JADX status={run['status']}, "
            f"returncode={run.get('returncode')}, timed_out={run.get('timed_out')}, "
            f"generated_sources={run.get('source_file_count')}"
        )
        for run in runs
        if run.get("status") != "success"
    ]
    aggregate_coverage = _aggregate_run_coverage(runs)
    code_index_summary = {
        "files_scanned": code_index["files_scanned"],
        "indexed_file_count": code_index["indexed_file_count"],
        "failed_file_count": code_index["failed_file_count"],
        "index_coverage": code_index["index_coverage"],
        "java_evidence_unit_count": len(java_evidence_units),
        "package_count": package_index["package_count"],
        "ownership_file_counts": code_index["ownership_file_counts"],
        "ownership_code_file_counts": code_index["ownership_code_file_counts"],
        "capability_counts": code_index["capability_counts"],
        "comparison_capability_counts": code_index[
            "comparison_capability_counts"
        ],
        "non_code_capability_counts": code_index["non_code_capability_counts"],
        "native_method_count": code_index["native_method_count"],
        "load_library_count": len(code_index["load_library_calls"]),
        "url_count": len(code_index["urls"]),
        "estimated_coverage": aggregate_coverage,
        "successful_decompiled_file_count": sum(
            int(run.get("successful_decompiled_file_count") or 0)
            for run in runs
        ),
        "jadx_error_count": sum(
            int(run.get("error_count") or 0)
            for run in runs
        ),
        "jadx_warning_count": sum(
            int(run.get("warning_count") or 0)
            for run in runs
        ),
        "timed_out_target_count": sum(
            1 for run in runs if run.get("timed_out")
        ),
    }
    payload = {
        "primary_apk": str(primary_apk),
        "app_package": app_package,
        "targets": [str(path) for path in targets],
        "decompile_all_splits": decompile_all_splits,
        "jadx_command": jadx_cmd,
        "jadx_timeout_per_apk": jadx_timeout_per_apk,
        "runs": runs,
        "success": status == "success",
        "status": status,
        "code_index_path": str(index_path),
        "java_evidence_units_path": str(evidence_path),
        "java_package_index_path": str(package_index_path),
        "code_index_summary": code_index_summary,
        "warnings": warnings,
    }
    safe_write_json(summary_path, payload)

    result = PhaseResult(
        name="phase2_jadx",
        success=status == "success",
        status=status,
        output_paths=output_paths,
        details={
            **code_index_summary,
            "target_count": len(runs),
            "successful_target_count": successful_runs,
            "partial_target_count": partial_runs,
            "failed_target_count": failed_runs,
            "usable_target_count": usable_runs,
        },
        error=(
            "JADX produced no usable Java/Kotlin source for any target."
            if status == "failed"
            else None
        ),
        warnings=warnings,
    )
    write_phase_cache(cache_path, cache_spec, output_paths, result)
    return result


def run_phase2(
    apk_path: Path,
    workspace: Path,
    *,
    force: bool = False,
    jadx_version: str = "1.5.0",
    jadx_threads: int = 4,
    jadx_timeout_per_apk: int = 1800,
    no_jadx_download: bool = False,
) -> PhaseResult:
    return run_phase2_multi(
        apk_path,
        [apk_path],
        workspace,
        force=force,
        jadx_version=jadx_version,
        jadx_threads=jadx_threads,
        jadx_timeout_per_apk=jadx_timeout_per_apk,
        no_jadx_download=no_jadx_download,
        decompile_all_splits=False,
    )
