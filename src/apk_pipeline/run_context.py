"""Run identity, cache validation, and workspace isolation helpers."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable

from .models import PhaseResult
from .utils import safe_name, safe_write_json, sha256_file


RUN_CONTEXT_SCHEMA = "2026-07-23.run-context.v1"
PHASE_CACHE_SCHEMA = "2026-07-23.phase-cache.v1"


class WorkspaceIdentityMismatchError(RuntimeError):
    """Raised when an existing workspace belongs to different APK content."""


def _normalized(value: Any) -> Any:
    if is_dataclass(value):
        return _normalized(asdict(value))
    if isinstance(value, Path):
        return str(value.expanduser().resolve())
    if isinstance(value, dict):
        return {
            str(key): _normalized(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalized(item) for item in value]
    if isinstance(value, set):
        return sorted(_normalized(item) for item in value)
    return value


def canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        _normalized(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_identity(path: Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        return {
            "path": str(resolved),
            "name": resolved.name,
            "exists": False,
        }
    return {
        "path": str(resolved),
        "name": resolved.name,
        "exists": True,
        "size_bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def _fingerprint_file(identity: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": identity.get("name"),
        "exists": identity.get("exists"),
        "size_bytes": identity.get("size_bytes"),
        "sha256": identity.get("sha256"),
    }


def build_input_identity(
    *,
    original_path: Path,
    primary_apk: Path,
    all_apks: Iterable[Path],
    phase3_apks: Iterable[Path],
    original_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    original = original_identity or file_identity(original_path)
    resolved_files = [file_identity(path) for path in all_apks]
    primary = file_identity(primary_apk)
    native_names = sorted(path.name for path in phase3_apks)
    fingerprint_payload = {
        "original": _fingerprint_file(original),
        "resolved_files": [
            _fingerprint_file(item)
            for item in sorted(resolved_files, key=lambda item: str(item.get("name") or ""))
        ],
        "primary": _fingerprint_file(primary),
        "phase3_apk_names": native_names,
    }
    return {
        "original": original,
        "resolved_files": resolved_files,
        "primary": primary,
        "phase3_apk_names": native_names,
        "fingerprint": canonical_hash(fingerprint_payload),
    }


def isolated_workspace_path(workspace_root: Path, input_path: Path, input_sha256: str) -> Path:
    stem = safe_name(input_path.stem) or "apk"
    return workspace_root.expanduser().resolve() / stem / input_sha256[:12]


def _config_payload(config: Any) -> dict[str, Any]:
    payload = _normalized(config)
    if not isinstance(payload, dict):
        raise TypeError("Pipeline configuration must normalize to a dictionary.")
    return payload


def _analysis_config(config_payload: dict[str, Any]) -> dict[str, Any]:
    ignored = {
        "apk_path",
        "workspace",
        "force",
        "isolated_workspace",
        "log_level",
    }
    return {
        key: value
        for key, value in config_payload.items()
        if key not in ignored
    }


def _git_revision(repo_root: Path) -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            text=True,
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(repo_root),
                text=True,
                capture_output=True,
                check=True,
                timeout=5,
            ).stdout.strip()
        )
        return {"commit": commit or None, "dirty": dirty}
    except Exception:
        return {"commit": None, "dirty": None}


def _source_tree_hash(repo_root: Path) -> str:
    records: list[dict[str, str]] = []
    for root_name in ("scripts", "src"):
        root = repo_root / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            records.append(
                {
                    "path": str(path.relative_to(repo_root)),
                    "sha256": sha256_file(path),
                }
            )
    return canonical_hash(records)


def _package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _external_tool_versions() -> dict[str, dict[str, Any]]:
    commands = {
        "jadx": ("jadx", "--version"),
        "strings": ("strings", "--version"),
        "readelf": ("readelf", "--version"),
        "llvm-readelf": ("llvm-readelf", "--version"),
        "nm": ("nm", "--version"),
        "rizin": ("rizin", "-v"),
        "radare2": ("r2", "-v"),
    }
    tools: dict[str, dict[str, Any]] = {}
    for name, command in commands.items():
        executable = shutil.which(command[0])
        if not executable:
            tools[name] = {
                "available": False,
                "path": None,
                "version": None,
            }
            continue
        executable_path = Path(executable).resolve()
        try:
            binary_size = executable_path.stat().st_size
            binary_sha256 = sha256_file(executable_path)
        except OSError:
            binary_size = None
            binary_sha256 = None
        try:
            completed = subprocess.run(
                [executable, *command[1:]],
                text=True,
                capture_output=True,
                check=False,
                timeout=5,
            )
            version_text = (completed.stdout or completed.stderr or "").strip()
            version = (
                version_text.splitlines()[0][:300]
                if completed.returncode == 0 and version_text
                else None
            )
            returncode = completed.returncode
        except Exception:
            version = None
            returncode = None
        tools[name] = {
            "available": True,
            "path": str(executable_path),
            "version": version,
            "version_command_returncode": returncode,
            "binary_size_bytes": binary_size,
            "binary_sha256": binary_sha256,
        }
    return tools


def build_run_context(
    *,
    config: Any,
    workspace: Path,
    input_identity: dict[str, Any],
    pipeline_version: str,
    repo_root: Path,
    workspace_mode: str,
) -> dict[str, Any]:
    config_payload = _config_payload(config)
    analysis_config = _analysis_config(config_payload)
    config_hash = canonical_hash(analysis_config)
    git = _git_revision(repo_root)
    fingerprint = str(input_identity["fingerprint"])
    source_tree_hash = _source_tree_hash(repo_root)
    runtime = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "packages": {
            "androguard": _package_version("androguard"),
            "apkInspector": _package_version("apkInspector"),
        },
        "external_tools": _external_tool_versions(),
    }
    analysis_fingerprint = canonical_hash(
        {
            "input_fingerprint": fingerprint,
            "config_hash": config_hash,
            "pipeline_version": pipeline_version,
            "git_commit": git.get("commit"),
            "source_tree_hash": source_tree_hash,
            "runtime": runtime,
        }
    )
    input_stem = safe_name(Path(str(config_payload["apk_path"])).stem) or "apk"
    analysis_id = f"{input_stem}-{analysis_fingerprint[:16]}"
    generated_at = datetime.now(timezone.utc)
    return {
        "schema_version": RUN_CONTEXT_SCHEMA,
        "analysis_id": analysis_id,
        "run_id": (
            f"{analysis_id}-{generated_at.strftime('%Y%m%dT%H%M%S%fZ')}-"
            f"{uuid.uuid4().hex[:8]}"
        ),
        "generated_at_utc": generated_at.isoformat(),
        "execution_status": "running",
        "workspace": str(workspace),
        "workspace_mode": workspace_mode,
        "pipeline": {
            "version_label": pipeline_version,
            "git_commit": git.get("commit"),
            "git_dirty": git.get("dirty"),
            "source_tree_hash": source_tree_hash,
        },
        "runtime": runtime,
        "input": input_identity,
        "config": config_payload,
        "analysis_config": analysis_config,
        "config_hash": config_hash,
        "analysis_fingerprint": analysis_fingerprint,
    }


def assert_workspace_identity(workspace: Path, input_identity: dict[str, Any]) -> None:
    context_path = workspace / "run_context.json"
    if not context_path.exists():
        return
    try:
        existing = json.loads(context_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WorkspaceIdentityMismatchError(
            f"Existing run context is unreadable: {context_path}. "
            "Use a new workspace instead of reusing this directory."
        ) from exc
    existing_fingerprint = ((existing.get("input") or {}).get("fingerprint"))
    current_fingerprint = input_identity.get("fingerprint")
    if existing_fingerprint and existing_fingerprint != current_fingerprint:
        raise WorkspaceIdentityMismatchError(
            "The requested workspace already belongs to different APK content. "
            f"Existing fingerprint={existing_fingerprint}; current fingerprint={current_fingerprint}. "
            "Choose a new workspace or run with --isolated-workspace."
        )


def assert_workspace_original_input(
    workspace: Path,
    original_identity: dict[str, Any],
) -> None:
    """Reject a different source file before bundle extraction mutates the workspace."""

    context_path = workspace / "run_context.json"
    if not context_path.exists():
        return
    try:
        existing = json.loads(context_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WorkspaceIdentityMismatchError(
            f"Existing run context is unreadable: {context_path}. "
            "Use a new workspace instead of reusing this directory."
        ) from exc
    existing_original = ((existing.get("input") or {}).get("original") or {})
    existing_sha = existing_original.get("sha256")
    current_sha = original_identity.get("sha256")
    if existing_sha and current_sha and existing_sha != current_sha:
        raise WorkspaceIdentityMismatchError(
            "The requested workspace already belongs to a different source APK or bundle. "
            f"Existing source SHA-256={existing_sha}; current source SHA-256={current_sha}. "
            "Choose a new workspace or run with --isolated-workspace."
        )


def write_run_context(workspace: Path, run_context: dict[str, Any]) -> Path:
    output_path = workspace / "run_context.json"
    safe_write_json(output_path, run_context)
    run_id = run_context.get("run_id")
    if run_id:
        history_path = workspace / "run_records" / f"{safe_name(str(run_id))}.json"
        safe_write_json(history_path, run_context)
    return output_path


def _artifact_identity(path: Path) -> dict[str, Any]:
    identity = file_identity(path)
    return {
        "path": identity.get("path"),
        "exists": identity.get("exists"),
        "size_bytes": identity.get("size_bytes"),
        "sha256": identity.get("sha256"),
    }


def build_phase_cache_spec(
    *,
    phase: str,
    phase_schema: str,
    phase_config: dict[str, Any],
    input_paths: Iterable[Path] = (),
    upstream_paths: Iterable[Path] = (),
    run_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if run_context:
        input_payload: Any = {
            "fingerprint": (run_context.get("input") or {}).get("fingerprint"),
            "pipeline_commit": (run_context.get("pipeline") or {}).get("git_commit"),
            "source_tree_hash": (run_context.get("pipeline") or {}).get("source_tree_hash"),
            "runtime_fingerprint": canonical_hash(run_context.get("runtime") or {}),
        }
    else:
        input_payload = [_artifact_identity(path) for path in input_paths]
    upstream = [_artifact_identity(path) for path in upstream_paths]
    core = {
        "phase": phase,
        "phase_schema": phase_schema,
        "input": input_payload,
        "phase_config": _normalized(phase_config),
        "upstream": upstream,
    }
    return {
        "schema_version": PHASE_CACHE_SCHEMA,
        **core,
        "cache_key": canonical_hash(core),
    }


def load_valid_phase_cache(
    manifest_path: Path,
    expected_spec: dict[str, Any],
    output_paths: Iterable[Path],
) -> dict[str, Any] | None:
    outputs = list(output_paths)
    if not manifest_path.exists() or not all(path.is_file() for path in outputs):
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if manifest.get("cache_key") != expected_spec.get("cache_key"):
        return None
    stored_outputs = {
        str(item.get("path")): item
        for item in manifest.get("outputs") or []
        if isinstance(item, dict)
    }
    for output in outputs:
        current = _artifact_identity(output)
        stored = stored_outputs.get(str(output.expanduser().resolve()))
        if not stored:
            return None
        if (
            stored.get("exists") != current.get("exists")
            or stored.get("size_bytes") != current.get("size_bytes")
            or stored.get("sha256") != current.get("sha256")
        ):
            return None
    return manifest


def cached_phase_result(
    name: str,
    output_paths: list[Path],
    cache_manifest: dict[str, Any],
) -> PhaseResult:
    cached = cache_manifest.get("result") or {}
    status = str(cached.get("status") or ("success" if cached.get("success", True) else "failed"))
    details = dict(cached.get("details") or {})
    details["cached"] = True
    return PhaseResult(
        name=name,
        success=status == "success",
        status=status,
        output_paths=output_paths,
        details=details,
        error=cached.get("error"),
        warnings=list(cached.get("warnings") or []),
    )


def write_phase_cache(
    manifest_path: Path,
    spec: dict[str, Any],
    output_paths: Iterable[Path],
    result: PhaseResult,
) -> None:
    outputs = [_artifact_identity(path) for path in output_paths]
    payload = {
        **spec,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "outputs": outputs,
        "result": result.to_dict(),
    }
    safe_write_json(manifest_path, payload)


def update_run_tooling(workspace: Path, run_context: dict[str, Any]) -> dict[str, Any]:
    updated = json.loads(json.dumps(run_context))
    tooling: dict[str, Any] = {}
    jadx_summary_path = workspace / "phase2_jadx" / "jadx_summary.json"
    if jadx_summary_path.exists():
        try:
            jadx_summary = json.loads(jadx_summary_path.read_text(encoding="utf-8"))
            command = jadx_summary.get("jadx_command")
            detected_version = None
            if isinstance(command, list) and command:
                try:
                    completed = subprocess.run(
                        [str(item) for item in command] + ["--version"],
                        text=True,
                        capture_output=True,
                        check=False,
                        timeout=10,
                    )
                    version_text = (completed.stdout or completed.stderr or "").strip()
                    detected_version = version_text.splitlines()[0][:300] if version_text else None
                except Exception:
                    detected_version = None
            tooling["jadx"] = {
                "configured_version": ((updated.get("config") or {}).get("jadx_version")),
                "detected_version": detected_version,
                "command": command,
            }
        except Exception:
            tooling["jadx"] = {"error": "summary_unreadable"}
    native_toolchain_path = workspace / "phase3_native" / "native_toolchain.json"
    if native_toolchain_path.exists():
        try:
            tooling["native"] = json.loads(native_toolchain_path.read_text(encoding="utf-8"))
        except Exception:
            tooling["native"] = {"error": "toolchain_unreadable"}
    updated["tooling"] = tooling
    updated["execution_status"] = "completed"
    updated["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    return updated
