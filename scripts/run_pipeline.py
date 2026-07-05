#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from apk_pipeline import APKPipeline, PipelineConfig
from apk_pipeline.logging_utils import configure_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the APK research extraction pipeline.")
    parser.add_argument("--apk", required=True, type=Path, help="Path to .apk, .apkm, .apks, or .xapk input.")
    parser.add_argument("--workspace", required=True, type=Path, help="Directory for pipeline outputs.")
    parser.add_argument("--force", action="store_true", help="Recompute phases even when outputs already exist.")
    parser.add_argument("--jadx-version", default="1.5.0", help="JADX version to download when jadx is not installed.")
    parser.add_argument("--jadx-threads", default=4, type=int, help="Thread count passed to JADX.")
    parser.add_argument("--no-jadx-download", action="store_true", help="Require an existing JADX installation.")
    parser.add_argument(
        "--no-decompile-all-splits",
        action="store_true",
        help="Only decompile the primary APK instead of every dex-bearing split.",
    )
    parser.add_argument(
        "--native-depth",
        choices=["none", "basic", "targeted"],
        default="targeted",
        help="Native analysis depth. targeted selects high-value functions and uses a decompiler if available.",
    )
    parser.add_argument(
        "--native-max-functions",
        type=int,
        default=300,
        help="Maximum ranked native targets to keep in phase3_native/native_targets.json.",
    )
    parser.add_argument(
        "--native-timeout",
        type=int,
        default=600,
        help="Timeout in seconds for each optional native decompiler command.",
    )
    parser.add_argument(
        "--no-resource-scan",
        action="store_true",
        help="Skip raw model/resource inventory.",
    )
    parser.add_argument(
        "--no-evidence-packets",
        action="store_true",
        help="Skip phase5 evidence packet generation.",
    )
    parser.add_argument(
        "--max-snippets-per-capability",
        type=int,
        default=40,
        help="Maximum code snippets retained per capability in the code index.",
    )
    parser.add_argument("--log-level", default="INFO", help="Python logging level.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)

    config = PipelineConfig(
        apk_path=args.apk,
        workspace=args.workspace,
        force=args.force,
        jadx_version=args.jadx_version,
        jadx_threads=args.jadx_threads,
        jadx_download=not args.no_jadx_download,
        log_level=args.log_level,
        decompile_all_splits=not args.no_decompile_all_splits,
        resource_scan=not args.no_resource_scan,
        emit_evidence_packets=not args.no_evidence_packets,
        native_depth=args.native_depth,
        native_max_functions=args.native_max_functions,
        native_timeout=args.native_timeout,
        max_snippets_per_capability=args.max_snippets_per_capability,
    )

    summary = APKPipeline(config).run()
    print(summary.to_json())
    return 0 if summary.to_dict()["all_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
