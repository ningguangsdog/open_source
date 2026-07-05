"""Main APK research pipeline orchestration."""

from __future__ import annotations

import logging
from pathlib import Path

from .config import PipelineConfig
from .input_resolver import ResolvedAPKInput, resolve_apk_input
from .models import PhaseResult, PipelineSummary
from .phase0_split_inventory import run_phase0
from .phase1_manifest import run_phase1_multi
from .phase2_jadx import run_phase2_multi
from .phase3_native import run_phase3_multi
from .phase4_resources import run_phase4_resources
from .phase5_evidence import run_phase5_evidence
from .utils import ensure_dir, safe_write_json


logger = logging.getLogger(__name__)


def _input_resolution_dict(resolved: ResolvedAPKInput) -> dict[str, object]:
    return {
        "original_path": str(resolved.original_path),
        "input_type": resolved.input_type,
        "primary_apk": str(resolved.primary_apk),
        "all_apks": [str(path) for path in resolved.all_apks],
        "phase3_apks": [str(path) for path in resolved.phase3_apks],
        "extracted_dir": str(resolved.extracted_dir) if resolved.extracted_dir else None,
        "notes": resolved.notes or [],
    }


class APKPipeline:
    def __init__(self, config: PipelineConfig) -> None:
        self.config = config

    def run(self) -> PipelineSummary:
        workspace = ensure_dir(self.config.workspace.expanduser().resolve())
        logger.info("Resolving input: %s", self.config.apk_path)
        resolved = resolve_apk_input(self.config.apk_path, workspace, force=self.config.force)

        phases: list[PhaseResult] = []
        phase_calls = [
            lambda: run_phase0(
                resolved.all_apks,
                resolved.primary_apk,
                workspace,
                force=self.config.force,
            ),
            lambda: run_phase1_multi(
                resolved.primary_apk,
                resolved.all_apks,
                workspace,
                force=self.config.force,
            ),
            lambda: run_phase2_multi(
                resolved.primary_apk,
                resolved.all_apks,
                workspace,
                force=self.config.force,
                jadx_version=self.config.jadx_version,
                jadx_threads=self.config.jadx_threads,
                no_jadx_download=not self.config.jadx_download,
                decompile_all_splits=self.config.decompile_all_splits,
                max_snippets_per_capability=self.config.max_snippets_per_capability,
            ),
            lambda: run_phase3_multi(
                resolved.phase3_apks,
                workspace,
                force=self.config.force,
                native_depth=self.config.native_depth,
                native_max_functions=self.config.native_max_functions,
                native_timeout=self.config.native_timeout,
            ),
        ]

        if self.config.resource_scan:
            phase_calls.append(
                lambda: run_phase4_resources(
                    resolved.all_apks,
                    workspace,
                    force=self.config.force,
                )
            )

        if self.config.emit_evidence_packets:
            phase_calls.append(lambda: run_phase5_evidence(workspace, force=self.config.force))

        for call in phase_calls:
            try:
                result = call()
            except Exception as exc:
                logger.exception("Pipeline phase failed with an uncaught exception")
                result = PhaseResult(
                    name="unknown_phase",
                    success=False,
                    output_paths=[],
                    details={},
                    error=repr(exc),
                )
            phases.append(result)

        summary = PipelineSummary(
            apk_filename=Path(self.config.apk_path).name,
            workspace=str(workspace),
            phases=phases,
            input_resolution=_input_resolution_dict(resolved),
        )
        safe_write_json(workspace / "pipeline_summary.json", summary.to_dict())
        return summary
