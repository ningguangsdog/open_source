from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PipelineConfig:
    apk_path: Path
    workspace: Path
    force: bool = False
    jadx_version: str = "1.5.0"
    jadx_threads: int = 4
    jadx_download: bool = True
    log_level: str = "INFO"
    decompile_all_splits: bool = True
    resource_scan: bool = True
    emit_evidence_packets: bool = True
    native_depth: str = "targeted"
    native_max_functions: int = 300
    native_timeout: int = 600
    max_snippets_per_capability: int = 40
