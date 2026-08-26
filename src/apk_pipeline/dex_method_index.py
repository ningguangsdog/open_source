"""Direct method-level indexing for Dalvik bytecode in APK archives."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable
import zipfile

from .capability_taxonomy import capability_names, classify_texts
from .code_ownership import classify_code_ownership
from .function_fingerprint import build_fingerprint, stable_id
from .utils import sha256_file


DEX_METHOD_INDEX_SCHEMA = "2026-08-24.dex-method-index.v2"
_QUOTED_RE = re.compile(r"['\"]((?:\\.|[^'\"\\]){3,300})['\"]")


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _descriptor_package(class_descriptor: str) -> str:
    value = class_descriptor.strip()
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    if "/" not in value:
        return ""
    return value.rsplit("/", 1)[0].replace("/", ".")


def _sorted_dex_entries(entries: Iterable[zipfile.ZipInfo]) -> list[zipfile.ZipInfo]:
    """Return DEX entries in a stable order without comparing ZipInfo objects."""

    return sorted(
        (info for info in entries if info.filename.lower().endswith(".dex")),
        key=lambda info: (
            info.filename.casefold(),
            info.filename,
            int(info.header_offset),
        ),
    )


def _instruction_output(instruction: object) -> str:
    getter = getattr(instruction, "get_output", None)
    if not callable(getter):
        return ""
    try:
        return _text(getter())
    except Exception:
        return ""


def _branch_counts(opcodes: Iterable[str]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for opcode in opcodes:
        normalized = opcode.lower()
        if normalized.startswith("if-"):
            counts["conditional"] += 1
        elif normalized.startswith("goto"):
            counts["unconditional"] += 1
        elif "switch" in normalized:
            counts["switch"] += 1
        elif normalized.startswith("return"):
            counts["return"] += 1
        elif normalized == "throw":
            counts["throw"] += 1
        elif normalized.startswith("invoke-"):
            counts["invoke"] += 1
        elif normalized.startswith("new-"):
            counts["allocation"] += 1
    return dict(sorted(counts.items()))


def build_dex_method_row(
    *,
    apk_path: Path,
    apk_sha256: str,
    dex_entry: str,
    class_descriptor: str,
    method_name: str,
    method_descriptor: str,
    access_flags: str,
    opcodes: Iterable[str],
    instruction_outputs: Iterable[str],
    app_package: str | None,
    first_party_prefixes: Iterable[str] = (),
    third_party_prefixes: Iterable[str] = (),
) -> dict[str, Any]:
    instruction_pairs = [
        (opcode.strip().lower(), output.strip())
        for opcode, output in zip(opcodes, instruction_outputs)
        if opcode.strip()
    ]
    opcode_list = [opcode for opcode, _output in instruction_pairs]
    output_list = [output for _opcode, output in instruction_pairs]
    package = _descriptor_package(class_descriptor)
    calls = [
        output
        for opcode, output in zip(opcode_list, output_list)
        if opcode.startswith("invoke-") and output
    ]
    strings = sorted(
        {
            match.group(1)
            for output in output_list
            for match in _QUOTED_RE.finditer(output)
        }
    )[:80]
    capability_text = "\n".join(
        [class_descriptor, method_name, method_descriptor, *calls[:80], *strings]
    )
    capabilities = capability_names(classify_texts([capability_text]).keys())
    ownership = classify_code_ownership(
        package,
        f"{dex_entry}:{class_descriptor}",
        app_package=app_package,
        first_party_prefixes=first_party_prefixes,
        third_party_prefixes=third_party_prefixes,
    ).to_dict()
    function_id = stable_id(
        "dex_method",
        apk_sha256,
        dex_entry,
        class_descriptor,
        method_name,
        method_descriptor,
    )
    branch_counts = _branch_counts(opcode_list)
    branch_split_count = sum(
        int(branch_counts.get(key) or 0)
        for key in ("conditional", "unconditional", "switch")
    )
    fingerprint = build_fingerprint(
        function_id=function_id,
        representation="dex_bytecode_method",
        name=f"{class_descriptor}->{method_name}{method_descriptor}",
        capabilities=capabilities,
        call_targets=calls,
        strings=strings,
        branch_counts=branch_counts,
        cfg_counts={
            "basic_block_estimate": 1 + branch_split_count,
            "edge_estimate": (
                int(branch_counts.get("conditional") or 0) * 2
                + int(branch_counts.get("unconditional") or 0)
                + int(branch_counts.get("switch") or 0) * 2
            ),
        },
        size_measure=len(opcode_list),
        instruction_tokens=opcode_list,
    )
    return {
        **fingerprint,
        "index_schema_version": DEX_METHOD_INDEX_SCHEMA,
        "apk": str(apk_path),
        "apk_sha256": apk_sha256,
        "dex_entry": dex_entry,
        "class_descriptor": class_descriptor,
        "package": package,
        "method_name": method_name,
        "method_descriptor": method_descriptor,
        "access_flags": access_flags,
        "ownership": ownership,
        "instruction_count": len(opcode_list),
        "opcode_sha256": hashlib.sha256(
            "\x1f".join(opcode_list).encode("utf-8", errors="ignore")
        ).hexdigest(),
        "call_targets": calls[:100],
        "strings": strings,
        "has_code": bool(opcode_list),
        "coverage_note": (
            "Direct Dalvik opcode inventory; instruction operands are retained only "
            "as bounded call/string evidence, not as reconstructed source semantics."
        ),
    }


def build_dex_method_index(
    apk_paths: Iterable[Path],
    *,
    app_package: str | None,
    first_party_prefixes: Iterable[str] = (),
    third_party_prefixes: Iterable[str] = (),
    output_path: Path | None = None,
    retain_rows: bool = True,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse all DEX-bearing APKs with Androguard and return deterministic rows."""

    apk_paths = sorted({Path(path) for path in apk_paths}, key=str)
    if not apk_paths:
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("", encoding="utf-8")
        return (
            {
                "schema_version": DEX_METHOD_INDEX_SCHEMA,
                "status": "completed",
                "indexed_method_count": 0,
                "code_bearing_method_count": 0,
                "dex_file_count": 0,
                "errors": [],
                "message": "No DEX-bearing APK was selected.",
            },
            [],
        )

    try:
        from androguard.core.dex import DEX
    except Exception as error:
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("", encoding="utf-8")
        return (
            {
                "schema_version": DEX_METHOD_INDEX_SCHEMA,
                "status": "tool_missing",
                "indexed_method_count": 0,
                "code_bearing_method_count": 0,
                "dex_file_count": 0,
                "errors": [f"{type(error).__name__}: {error}"],
                "message": "Androguard is required for direct DEX method indexing.",
            },
            [],
        )

    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    dex_file_count = 0
    declared_method_count = 0
    indexed_method_count = 0
    code_bearing_method_count = 0
    ownership_counts: Counter[str] = Counter()
    temporary_path = (
        output_path.with_suffix(output_path.suffix + ".tmp")
        if output_path is not None
        else None
    )
    destination = None
    if temporary_path is not None:
        temporary_path.parent.mkdir(parents=True, exist_ok=True)
        destination = temporary_path.open("w", encoding="utf-8")
    for apk_path in apk_paths:
        try:
            apk_hash = sha256_file(apk_path)
            archive = zipfile.ZipFile(apk_path)
        except Exception as error:
            errors.append(
                {"apk": str(apk_path), "error": f"{type(error).__name__}: {error}"}
            )
            continue
        with archive:
            dex_entries = _sorted_dex_entries(archive.infolist())
            for info in dex_entries:
                dex_file_count += 1
                try:
                    dex = DEX(archive.read(info))
                except Exception as error:
                    errors.append(
                        {
                            "apk": str(apk_path),
                            "dex": info.filename,
                            "error": f"{type(error).__name__}: {error}",
                        }
                    )
                    continue
                try:
                    classes = list(dex.get_classes())
                except Exception as error:
                    errors.append(
                        {
                            "apk": str(apk_path),
                            "dex": info.filename,
                            "error": f"classes: {type(error).__name__}: {error}",
                        }
                    )
                    continue
                for dex_class in classes:
                    class_descriptor = _text(dex_class.get_name())
                    try:
                        methods = list(dex_class.get_methods())
                    except Exception as error:
                        errors.append(
                            {
                                "apk": str(apk_path),
                                "dex": info.filename,
                                "class": class_descriptor,
                                "error": f"methods: {type(error).__name__}: {error}",
                            }
                        )
                        continue
                    for method in methods:
                        declared_method_count += 1
                        method_name = ""
                        try:
                            method_name = _text(method.get_name())
                            descriptor = _text(method.get_descriptor())
                            access_getter = getattr(method, "get_access_flags_string", None)
                            access_flags = _text(access_getter()) if callable(access_getter) else ""
                            code = method.get_code()
                            instructions = (
                                list(code.get_bc().get_instructions()) if code is not None else []
                            )
                            opcodes = [_text(instruction.get_name()) for instruction in instructions]
                            outputs = [_instruction_output(instruction) for instruction in instructions]
                            row = build_dex_method_row(
                                apk_path=apk_path,
                                apk_sha256=apk_hash,
                                dex_entry=info.filename,
                                class_descriptor=class_descriptor,
                                method_name=method_name,
                                method_descriptor=descriptor,
                                access_flags=access_flags,
                                opcodes=opcodes,
                                instruction_outputs=outputs,
                                app_package=app_package,
                                first_party_prefixes=first_party_prefixes,
                                third_party_prefixes=third_party_prefixes,
                            )
                            indexed_method_count += 1
                            code_bearing_method_count += int(bool(row.get("has_code")))
                            ownership_counts.update(
                                [
                                    str(
                                        (row.get("ownership") or {}).get("category")
                                        or "unknown"
                                    )
                                ]
                            )
                            if retain_rows:
                                rows.append(row)
                            if destination is not None:
                                destination.write(
                                    json.dumps(
                                        row,
                                        ensure_ascii=False,
                                        sort_keys=True,
                                    )
                                    + "\n"
                                )
                        except Exception as error:
                            errors.append(
                                {
                                    "apk": str(apk_path),
                                    "dex": info.filename,
                                    "class": class_descriptor,
                                    "method": method_name or "<unreadable>",
                                    "error": f"{type(error).__name__}: {error}",
                                }
                            )

    if destination is not None:
        destination.close()
    if temporary_path is not None and output_path is not None:
        temporary_path.replace(output_path)
    if retain_rows:
        rows.sort(
            key=lambda row: (
                str(row.get("apk")),
                str(row.get("dex_entry")),
                str(row.get("class_descriptor")),
                str(row.get("method_name")),
                str(row.get("method_descriptor")),
            )
        )
    status = "completed"
    if errors and indexed_method_count:
        status = "partial"
    elif errors and not indexed_method_count:
        status = "failed"
    return (
        {
            "schema_version": DEX_METHOD_INDEX_SCHEMA,
            "status": status,
            "dex_file_count": dex_file_count,
            "declared_method_count": declared_method_count,
            "indexed_method_count": indexed_method_count,
            "code_bearing_method_count": code_bearing_method_count,
            "ownership_method_counts": dict(sorted(ownership_counts.items())),
            "error_count": len(errors),
            "errors": errors[:200],
            "coverage_limit": (
                "Covers methods declared in DEX files parsed by Androguard. A partial "
                "or failed status is explicit and cannot be treated as full coverage."
            ),
        },
        rows,
    )
