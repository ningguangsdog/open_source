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
