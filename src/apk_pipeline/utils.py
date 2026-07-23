from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional, TextIO

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ZipSafetyLimits:
    max_entries: int = 20000
    max_total_uncompressed: int = 3_000_000_000
    max_single_file: int = 1_000_000_000


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def reset_dir(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def atomic_text_writer(path: Path) -> Iterator[TextIO]:
    """Write a text artifact atomically in the destination directory."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def safe_write_json(path: Path, payload: Any) -> None:
    with atomic_text_writer(path) as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def safe_write_text(path: Path, content: str) -> None:
    with atomic_text_writer(path) as fh:
        fh.write(content)


def run_cmd(
    cmd: list[str],
    cwd: Optional[Path] = None,
    check: bool = False,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    logger.info("Running command: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=check,
        timeout=timeout,
    )


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def safe_read_text(path: Path, limit: Optional[int] = None) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return text[:limit] if limit else text
    except Exception:
        return ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_name(name: str) -> str:
    import re

    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def is_safe_zip_member(name: str) -> bool:
    normalized = Path(name.replace("\\", "/"))
    if not normalized.parts:
        return False
    if normalized.is_absolute() or ":" in normalized.parts[0]:
        return False
    return ".." not in normalized.parts


def validate_zip(path: Path, limits: ZipSafetyLimits | None = None) -> list[zipfile.ZipInfo]:
    limits = limits or ZipSafetyLimits()
    with zipfile.ZipFile(path, "r") as zf:
        infos = zf.infolist()
    if len(infos) > limits.max_entries:
        raise ValueError(f"Zip has too many entries: {len(infos)} > {limits.max_entries}")
    total_size = 0
    for info in infos:
        if not is_safe_zip_member(info.filename):
            raise ValueError(f"Unsafe zip member path: {info.filename}")
        if info.file_size > limits.max_single_file:
            raise ValueError(f"Zip member is too large: {info.filename} ({info.file_size} bytes)")
        total_size += info.file_size
    if total_size > limits.max_total_uncompressed:
        raise ValueError(
            f"Zip uncompressed size too large: {total_size} > {limits.max_total_uncompressed}"
        )
    return infos


def safe_extract_zip(path: Path, out_dir: Path, limits: ZipSafetyLimits | None = None) -> None:
    infos = validate_zip(path, limits)
    out_dir = out_dir.resolve()
    with zipfile.ZipFile(path, "r") as zf:
        for info in infos:
            target = (out_dir / info.filename).resolve()
            if target != out_dir and out_dir not in target.parents:
                raise ValueError(f"Unsafe extraction target: {info.filename}")
            zf.extract(info, out_dir)


def zip_contains(path: Path, predicate) -> bool:
    try:
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path, "r") as zf:
            return any(predicate(n) for n in zf.namelist())
    except Exception:
        return False


def zip_entry_sha256(zip_path: Path, entry_name: str) -> str:
    digest = hashlib.sha256()
    with zipfile.ZipFile(zip_path, "r") as zf:
        with zf.open(entry_name, "r") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def read_zip_entry_prefix(zip_path: Path, entry_name: str, limit: int = 1_000_000) -> bytes:
    with zipfile.ZipFile(zip_path, "r") as zf:
        with zf.open(entry_name, "r") as fh:
            return fh.read(limit)


def printable_strings_from_bytes(data: bytes, min_length: int = 4, limit: int = 500) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode("utf-8", errors="ignore"))
                if len(strings) >= limit:
                    return strings
            current = bytearray()
    if len(current) >= min_length and len(strings) < limit:
        strings.append(current.decode("utf-8", errors="ignore"))
    return strings
