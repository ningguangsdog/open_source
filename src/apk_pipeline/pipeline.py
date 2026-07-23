"""Main APK research pipeline orchestration."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import logging
from pathlib import Path
import platform
import sys

from .config import PipelineConfig
from .input_resolver import ResolvedAPKInput, resolve_apk_input
from .models import PhaseResult, PipelineSummary
from .phase0_split_inventory import run_phase0
from .phase1_manifest import run_phase1_multi
from .phase2_jadx import run_phase2_multi
from .phase3_native import run_phase3_multi
from .phase4_resources import run_phase4_resources
from .phase5_evidence import run_phase5_evidence
from .run_context import (
    assert_workspace_identity,
    assert_workspace_original_input,
    build_input_identity,
    build_run_context,
    file_identity,
    isolated_workspace_path,
    update_run_tooling,
    write_run_context,
)
from .utils import ensure_dir, safe_write_json


logger = logging.getLogger(__name__)
PIPELINE_VERSION_LABEL = (
    "July 5 + Native Deep v1 + Run Integrity v1 + Evidence Quality v1 + IDA Review v1"
)
REPO_ROOT = Path(__file__).resolve().parents[2]


def _skipped_phase(name: str, reason: str) -> PhaseResult:
    return PhaseResult(
        name=name,
        success=False,
        status="skipped",
        details={"reason": reason},
    )


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
        original_identity = file_identity(self.config.apk_path)
        if not original_identity.get("exists"):
            raise FileNotFoundError(f"Input file not found: {self.config.apk_path}")
        if self.config.isolated_workspace:
            workspace = isolated_workspace_path(
                self.config.workspace,
                self.config.apk_path,
                str(original_identity["sha256"]),
            )
            workspace_mode = "isolated"
        else:
            workspace = self.config.workspace.expanduser().resolve()
            workspace_mode = "exact"
        workspace = ensure_dir(workspace)
        assert_workspace_original_input(workspace, original_identity)
        logger.info("Resolving input: %s", self.config.apk_path)
        resolved = resolve_apk_input(self.config.apk_path, workspace, force=self.config.force)
        input_identity = build_input_identity(
            original_path=resolved.original_path,
            primary_apk=resolved.primary_apk,
            all_apks=resolved.all_apks,
            phase3_apks=resolved.phase3_apks,
            original_identity=original_identity,
        )
        assert_workspace_identity(workspace, input_identity)
        run_context = build_run_context(
            config=self.config,
            workspace=workspace,
            input_identity=input_identity,
            pipeline_version=PIPELINE_VERSION_LABEL,
            repo_root=REPO_ROOT,
            workspace_mode=workspace_mode,
        )
        run_context_path = write_run_context(workspace, run_context)

        phases: list[PhaseResult] = []
        phase_calls = [
            (
                "phase0_split_inventory",
                lambda: run_phase0(
                    resolved.all_apks,
                    resolved.primary_apk,
                    workspace,
                    force=self.config.force,
                    run_context=run_context,
                ),
            ),
            (
                "phase1_manifest",
                lambda: run_phase1_multi(
                    resolved.primary_apk,
                    resolved.all_apks,
                    workspace,
                    force=self.config.force,
                    run_context=run_context,
                ),
            ),
            (
                "phase2_jadx",
                lambda: run_phase2_multi(
                    resolved.primary_apk,
                    resolved.all_apks,
                    workspace,
                    force=self.config.force,
                    jadx_version=self.config.jadx_version,
                    jadx_threads=self.config.jadx_threads,
                    jadx_timeout_per_apk=self.config.jadx_timeout_per_apk,
                    no_jadx_download=not self.config.jadx_download,
                    decompile_all_splits=self.config.decompile_all_splits,
                    max_snippets_per_capability=self.config.max_snippets_per_capability,
                    first_party_prefixes=self.config.first_party_prefixes,
                    third_party_prefixes=self.config.third_party_prefixes,
                    run_context=run_context,
                ),
            ),
            (
                "phase3_native",
                lambda: run_phase3_multi(
                    resolved.phase3_apks,
                    workspace,
                    force=self.config.force,
                    native_depth=self.config.native_depth,
                    native_max_functions=self.config.native_max_functions,
                    native_decompiler=self.config.native_decompiler,
                    native_max_libraries=self.config.native_max_libraries,
                    native_max_decompile_targets=self.config.native_max_decompile_targets,
                    native_timeout_per_function=self.config.native_timeout_per_function,
                    native_timeout_per_app=self.config.native_timeout_per_app,
                    ida_review_limit=self.config.ida_review_limit,
                    native_target_capabilities=self.config.native_target_capabilities,
                    first_party_native_hashes=self.config.first_party_native_hashes,
                    third_party_native_hashes=self.config.third_party_native_hashes,
                    run_context=run_context,
                ),
            ),
        ]

        if self.config.resource_scan:
            phase_calls.append(
                (
                    "phase4_resources",
                    lambda: run_phase4_resources(
                        resolved.all_apks,
                        workspace,
                        force=self.config.force,
                        run_context=run_context,
                    ),
                )
            )
        else:
            phase_calls.append(
                (
                    "phase4_resources",
                    lambda: _skipped_phase(
                        "phase4_resources",
                        "Resource scanning was disabled by configuration.",
                    ),
                )
            )

        if self.config.emit_evidence_packets:
            phase_calls.append(
                (
                    "phase5_evidence",
                    lambda: run_phase5_evidence(
                        workspace,
                        force=self.config.force,
                        run_context=run_context,
                        upstream_results=phases,
                        require_resources=self.config.resource_scan,
                    ),
                )
            )
        else:
            phase_calls.append(
                (
                    "phase5_evidence",
                    lambda: _skipped_phase(
                        "phase5_evidence",
                        "Evidence packet generation was disabled by configuration.",
                    ),
                )
            )

        for phase_name, call in phase_calls:
            try:
                result = call()
            except Exception as exc:
                logger.exception("%s failed with an uncaught exception", phase_name)
                result = PhaseResult(
                    name=phase_name,
                    success=False,
                    status="failed",
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
        summary_payload = summary.to_dict()
        safe_write_json(workspace / "pipeline_summary.json", summary_payload)
        run_context = update_run_tooling(workspace, run_context)
        run_context["result"] = {
            "all_success": summary_payload["all_success"],
            "has_partial": summary_payload["has_partial"],
            "has_failed": summary_payload["has_failed"],
            "phase_status": {phase.name: phase.status for phase in phases},
        }
        write_run_context(workspace, run_context)
        config_payload = asdict(self.config)
        config_payload["apk_path"] = str(config_payload["apk_path"])
        config_payload["workspace"] = str(config_payload["workspace"])
        config_payload["native_target_capabilities"] = list(config_payload["native_target_capabilities"])
        config_payload["first_party_prefixes"] = list(config_payload["first_party_prefixes"])
        config_payload["third_party_prefixes"] = list(config_payload["third_party_prefixes"])
        config_payload["first_party_native_hashes"] = list(config_payload["first_party_native_hashes"])
        config_payload["third_party_native_hashes"] = list(config_payload["third_party_native_hashes"])
        run_manifest = {
            "schema_version": "2026-07-23.run-manifest.v2",
            "run_id": run_context["run_id"],
            "analysis_id": run_context["analysis_id"],
            "analysis_fingerprint": run_context["analysis_fingerprint"],
            "execution_status": run_context["execution_status"],
            "pipeline_version_label": PIPELINE_VERSION_LABEL,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "git_commit": (run_context.get("pipeline") or {}).get("git_commit"),
            "git_dirty": (run_context.get("pipeline") or {}).get("git_dirty"),
            "input_identity": run_context.get("input"),
            "config_hash": run_context.get("config_hash"),
            "tooling": run_context.get("tooling"),
            "config": config_payload,
            "input_resolution": summary.input_resolution,
            "phase_success": {phase.name: phase.success for phase in phases},
            "phase_status": {phase.name: phase.status for phase in phases},
            "phase_outputs": {
                phase.name: [str(path) for path in phase.output_paths]
                for phase in phases
            },
            "run_context_path": str(run_context_path),
            "native_toolchain_path": str(workspace / "phase3_native" / "native_toolchain.json"),
            "pipeline_summary_path": str(workspace / "pipeline_summary.json"),
        }
        safe_write_json(workspace / "run_manifest.json", run_manifest)
        return summary
