from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PipelineConfig:
    apk_path: Path
    workspace: Path
    force: bool = False
    isolated_workspace: bool = False
    jadx_version: str = "1.5.0"
    jadx_threads: int = 4
    jadx_timeout_per_apk: int = 1800
    jadx_download: bool = True
    log_level: str = "INFO"
    decompile_all_splits: bool = True
    resource_scan: bool = True
    emit_evidence_packets: bool = True
    native_depth: str = "auto"
    native_max_functions: int = 300
    native_decompiler: str = "auto"
    native_max_libraries: int = 8
    native_max_decompile_targets: int = 40
    native_timeout_per_function: int = 90
    native_timeout_per_app: int = 3600
    native_target_capabilities: tuple[str, ...] = ()
    max_snippets_per_capability: int = 40
    first_party_prefixes: tuple[str, ...] = ()
    third_party_prefixes: tuple[str, ...] = ()
    first_party_native_hashes: tuple[str, ...] = ()
    third_party_native_hashes: tuple[str, ...] = ()
