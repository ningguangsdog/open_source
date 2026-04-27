from __future__ import annotations

import logging

from .config import PipelineConfig
from .input_resolver import resolve_apk_input
from .logging_utils import configure_logging
from .models import PipelineSummary
from .phase1_manifest import run_phase1
from .phase2_jadx import run_phase2
from .phase3_native import run_phase3_multi
from .utils import ensure_dir, safe_write_json

logger = logging.getLogger(__name__)


class APKPipeline:
    def __init__(self, config: PipelineConfig):
        self.config = config
        configure_logging(config.log_level)
        ensure_dir(config.workspace)

    def run(self) -> PipelineSummary:
        input_path = self.config.apk_path

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        resolved = resolve_apk_input(
            input_path=input_path,
            workspace=self.config.workspace,
            force=self.config.force,
        )

        logger.info("Starting pipeline for %s", resolved.original_path.name)
        logger.info("Input type: %s", resolved.input_type)
        logger.info("Primary APK for Phase I/II: %s", resolved.primary_apk)
        logger.info("APK(s) for Phase III: %d", len(resolved.phase3_apks))

        p1 = run_phase1(
            resolved.primary_apk,
            self.config.workspace,
            force=self.config.force,
        )

        p2 = run_phase2(
            resolved.primary_apk,
            self.config.workspace,
            force=self.config.force,
            jadx_version=self.config.jadx_version,
            threads=self.config.jadx_threads,
            allow_download=self.config.jadx_download,
        )

        p3 = run_phase3_multi(
            resolved.phase3_apks,
            self.config.workspace,
            force=self.config.force,
            logical_apk_name=resolved.original_path.name,
        )

        summary = PipelineSummary(
            apk_filename=resolved.original_path.name,
            workspace=str(self.config.workspace),
            phases=[p1, p2, p3],
        )

        payload = summary.to_dict()
        payload["input_resolution"] = {
            "input_type": resolved.input_type,
            "original_path": str(resolved.original_path),
            "primary_apk": str(resolved.primary_apk),
            "phase3_apks": [str(p) for p in resolved.phase3_apks],
            "extracted_dir": str(resolved.extracted_dir) if resolved.extracted_dir else None,
            "notes": resolved.notes or [],
        }

        safe_write_json(self.config.workspace / "pipeline_summary.json", payload)
        logger.info("Pipeline finished. All success = %s", payload["all_success"])

        return summary


__all__ = ["APKPipeline", "PipelineConfig"]
