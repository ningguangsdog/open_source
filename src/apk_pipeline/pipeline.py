"""Main APK research pipeline orchestration."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import logging
from pathlib import Path
import platform
import sys
from typing import Callable

from .config import PipelineConfig
from .input_resolver import ResolvedAPKInput, resolve_apk_input
from .models import PhaseResult, PipelineSummary
from .phase0_split_inventory import run_phase0
from .phase1_manifest import run_phase1_multi
from .phase2_jadx import run_phase2_multi
from .phase3_native import run_phase3_multi
from .phase4_resources import run_phase4_resources
from .phase5_evidence import run_phase5_evidence
from .result_validation import write_pipeline_validation
from .reuse_regression import REGRESSION_SCHEMA, run_reuse_regression
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
    "July 5 + Native Deep v1 + IDA Classroom Automation v1 + Reuse Search v2"
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
        try:
            phase0 = run_phase0(
                resolved.all_apks,
                resolved.primary_apk,
                workspace,
                force=self.config.force,
                run_context=run_context,
            )
        except Exception as exc:
            logger.exception("phase0_split_inventory failed with an uncaught exception")
            phase0 = PhaseResult(
                name="phase0_split_inventory",
                success=False,
                status="failed",
                output_paths=[],
                details={},
                error=repr(exc),
            )
        phases.append(phase0)

        if phase0.status == "failed":
            reason = "Phase 0 rejected the primary APK; downstream evidence would be unreliable."
            phases.extend(
                _skipped_phase(name, reason)
                for name in (
                    "phase1_manifest",
                    "phase2_jadx",
                    "phase3_native",
                    "phase4_resources",
                    "phase5_evidence",
                )
            )
            phase_calls: list[tuple[str, Callable[[], PhaseResult]]] = []
        else:
            valid_paths = {
                Path(path).expanduser().resolve()
                for path in phase0.details.get("valid_apks", [])
            }
            analysis_apks = [
                path for path in resolved.all_apks if path.resolve() in valid_paths
            ]
            phase3_apks = [
                path for path in resolved.phase3_apks if path.resolve() in valid_paths
            ]
            phase_calls = [
                (
                    "phase1_manifest",
                    lambda: run_phase1_multi(
                        resolved.primary_apk,
                        analysis_apks,
                        workspace,
                        force=self.config.force,
                        run_context=run_context,
                    ),
                ),
                (
                    "phase2_jadx",
                    lambda: run_phase2_multi(
                        resolved.primary_apk,
                        analysis_apks,
                        workspace,
                        force=self.config.force,
                        jadx_version=self.config.jadx_version,
                        jadx_threads=self.config.jadx_threads,
                        jadx_timeout_per_apk=self.config.jadx_timeout_per_apk,
                        no_jadx_download=not self.config.jadx_download,
                        decompile_all_splits=self.config.decompile_all_splits,
                        build_direct_dex_index=self.config.dex_method_index,
                        max_snippets_per_capability=self.config.max_snippets_per_capability,
                        first_party_prefixes=self.config.first_party_prefixes,
                        third_party_prefixes=self.config.third_party_prefixes,
                        run_context=run_context,
                    ),
                ),
                (
                    "phase3_native",
                    lambda: run_phase3_multi(
                        phase3_apks,
                        workspace,
                        force=self.config.force,
                        native_depth=self.config.native_depth,
                        native_max_functions=self.config.native_max_functions,
                        native_decompiler=self.config.native_decompiler,
                        native_max_libraries=self.config.native_max_libraries,
                        native_max_decompile_targets=self.config.native_max_decompile_targets,
                        native_timeout_per_function=self.config.native_timeout_per_function,
                        native_timeout_per_app=self.config.native_timeout_per_app,
                        ida_install_dir=self.config.ida_install_dir,
                        ida_python_executable=self.config.ida_python_executable,
                        ida_max_retries=self.config.ida_max_retries,
                        ida_callgraph_depth=self.config.ida_callgraph_depth,
                        ida_review_limit=self.config.ida_review_limit,
                        ida_handoff_max_libraries=self.config.ida_handoff_max_libraries,
                        full_native_index=self.config.full_native_index,
                        full_native_index_timeout_per_library=(
                            self.config.full_native_index_timeout_per_library
                        ),
                        full_native_index_timeout_per_app=(
                            self.config.full_native_index_timeout_per_app
                        ),
                        full_native_index_max_instructions=(
                            self.config.full_native_index_max_instructions
                        ),
                        oss_function_index=self.config.oss_function_index,
                        oss_binary_function_index=(
                            self.config.oss_binary_function_index
                        ),
                        reuse_candidate_top_k=self.config.reuse_candidate_top_k,
                        reuse_candidate_min_score=(
                            self.config.reuse_candidate_min_score
                        ),
                        reuse_candidate_decompile_limit=(
                            self.config.reuse_candidate_decompile_limit
                        ),
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
                            analysis_apks,
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

        regression_requested = self.config.reuse_regression_labels is not None
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
            if regression_requested and phase_name == "phase3_native":
                regression_path = (
                    workspace / "phase3_native" / "reuse_regression.json"
                )
                try:
                    run_reuse_regression(
                        workspace
                        / "phase3_native"
                        / "reuse_candidates.jsonl",
                        self.config.reuse_regression_labels.expanduser().resolve(),
                        regression_path,
                    )
                except Exception as exc:
                    logger.exception("Known-positive reuse regression failed")
                    safe_write_json(
                        regression_path,
                        {
                            "schema_version": REGRESSION_SCHEMA,
                            "status": "error",
                            "error": repr(exc),
                            "labels_path": str(
                                self.config.reuse_regression_labels
                            ),
                        },
                    )

        validation = write_pipeline_validation(
            workspace,
            phases,
            expect_automated_ida=self.config.native_decompiler == "ida",
            require_evidence_packet=self.config.emit_evidence_packets,
            expect_reuse_search=self.config.full_native_index,
            expect_reuse_regression=regression_requested,
            strict_reuse_regression=self.config.strict_reuse_regression,
        )
        summary = PipelineSummary(
            apk_filename=Path(self.config.apk_path).name,
            workspace=str(workspace),
            phases=phases,
            input_resolution=_input_resolution_dict(resolved),
            validation=validation,
        )
        summary_payload = summary.to_dict()
        safe_write_json(workspace / "pipeline_summary.json", summary_payload)
        run_context = update_run_tooling(workspace, run_context)
        run_context["result"] = {
            "all_success": summary_payload["all_success"],
            "has_partial": summary_payload["has_partial"],
            "has_failed": summary_payload["has_failed"],
            "phase_status": {phase.name: phase.status for phase in phases},
            "validation_status": validation.get("status"),
            "ready_for_similarity": validation.get("ready_for_similarity"),
        }
        write_run_context(workspace, run_context)
        config_payload = asdict(self.config)
        config_payload["apk_path"] = str(config_payload["apk_path"])
        config_payload["workspace"] = str(config_payload["workspace"])
        for path_key in (
            "ida_install_dir",
            "ida_python_executable",
            "oss_function_index",
            "oss_binary_function_index",
            "reuse_regression_labels",
        ):
            if config_payload[path_key] is not None:
                config_payload[path_key] = str(config_payload[path_key])
        config_payload["native_target_capabilities"] = list(config_payload["native_target_capabilities"])
        config_payload["first_party_prefixes"] = list(config_payload["first_party_prefixes"])
        config_payload["third_party_prefixes"] = list(config_payload["third_party_prefixes"])
        config_payload["first_party_native_hashes"] = list(config_payload["first_party_native_hashes"])
        config_payload["third_party_native_hashes"] = list(config_payload["third_party_native_hashes"])
        run_manifest = {
            "schema_version": "2026-08-20.run-manifest.v3",
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
            "pipeline_validation_path": str(
                workspace / "pipeline_validation.json"
            ),
        }
        safe_write_json(workspace / "run_manifest.json", run_manifest)
        return summary
