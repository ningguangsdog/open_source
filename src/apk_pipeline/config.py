from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PipelineConfig:
    apk_path: Path
    workspace: Path
    analysis_profile: str = "standard"
    force: bool = False
    isolated_workspace: bool = False
    jadx_version: str = "1.5.0"
    jadx_threads: int = 4
    jadx_timeout_per_apk: int = 1800
    jadx_download: bool = True
    dex_method_index: bool = False
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
    ida_install_dir: Path | None = None
    ida_python_executable: Path | None = None
    ida_max_retries: int = 1
    ida_callgraph_depth: int = 2
    ida_review_limit: int = 120
    ida_handoff_max_libraries: int = 12
    full_native_index: bool = False
    full_native_index_timeout_per_library: int = 1200
    full_native_index_timeout_per_app: int = 14_400
    full_native_index_max_instructions: int = 512
    oss_function_index: Path | None = None
    oss_binary_function_index: Path | None = None
    reuse_candidate_top_k: int = 10
    reuse_candidate_min_score: float = 0.28
    reuse_candidate_decompile_limit: int = 120
    reuse_regression_labels: Path | None = None
    strict_reuse_regression: bool = False
    native_target_capabilities: tuple[str, ...] = ()
    max_snippets_per_capability: int = 40
    first_party_prefixes: tuple[str, ...] = ()
    third_party_prefixes: tuple[str, ...] = ()
    first_party_native_hashes: tuple[str, ...] = ()
    third_party_native_hashes: tuple[str, ...] = ()
