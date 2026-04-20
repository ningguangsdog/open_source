from __future__ import annotations

import logging
from pathlib import Path

from .config import PipelineConfig
from .logging_utils import configure_logging
from .models import PipelineSummary
from .phase1_manifest import run_phase1
from .phase2_jadx import run_phase2
from .phase3_native import run_phase3
from .utils import ensure_dir, safe_write_json

logger = logging.getLogger(__name__)


class APKPipeline:
    def __init__(self, config: PipelineConfig):
        self.config = config
        configure_logging(config.log_level)
        ensure_dir(config.workspace)

    def run(self) -> PipelineSummary:
        apk_path = self.config.apk_path
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        logger.info("Starting pipeline for %s", apk_path.name)

        p1 = run_phase1(apk_path, self.config.workspace, force=self.config.force)
        p2 = run_phase2(
            apk_path,
            self.config.workspace,
            force=self.config.force,
            jadx_version=self.config.jadx_version,
            threads=self.config.jadx_threads,
            allow_download=self.config.jadx_download,
        )
        p3 = run_phase3(apk_path, self.config.workspace, force=self.config.force)

        summary = PipelineSummary(
            apk_filename=apk_path.name,
            workspace=str(self.config.workspace),
            phases=[p1, p2, p3],
        )
        safe_write_json(self.config.workspace / "pipeline_summary.json", summary.to_dict())
        logger.info("Pipeline finished. All success = %s", summary.to_dict()["all_success"])
        return summary


__all__ = ["APKPipeline", "PipelineConfig"]
