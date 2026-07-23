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
from apk_pipeline.native_decompiler import detect_native_toolchain
from apk_pipeline.run_context import WorkspaceIdentityMismatchError


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the APK research extraction pipeline.")
    parser.add_argument("--apk", type=Path, help="Path to .apk, .apkm, .apks, or .xapk input.")
    parser.add_argument("--workspace", type=Path, help="Directory for pipeline outputs.")
    parser.add_argument("--force", action="store_true", help="Recompute phases even when outputs already exist.")
    parser.add_argument(
        "--isolated-workspace",
        action="store_true",
        help=(
            "Treat --workspace as a root and write this input under "
            "<workspace>/<input-name>/<input-sha-prefix>."
        ),
    )
    parser.add_argument("--jadx-version", default="1.5.0", help="JADX version to download when jadx is not installed.")
    parser.add_argument("--jadx-threads", default=4, type=positive_int, help="Thread count passed to JADX.")
    parser.add_argument(
        "--jadx-timeout-per-apk",
        default=1800,
        type=positive_int,
        help=(
            "Maximum JADX runtime in seconds for each APK or dex-bearing split. "
            "Partial source is retained and reported when the limit is reached."
        ),
    )
    parser.add_argument("--no-jadx-download", action="store_true", help="Require an existing JADX installation.")
    parser.add_argument(
        "--no-decompile-all-splits",
        action="store_true",
        help="Only decompile the primary APK instead of every dex-bearing split.",
    )
    parser.add_argument(
        "--native-depth",
        choices=["none", "basic", "targeted", "auto", "deep"],
        default="auto",
        help="Native analysis depth. auto ranks evidence and attempts pseudocode only for high-value targets.",
    )
    parser.add_argument(
        "--native-max-functions",
        type=positive_int,
        default=300,
        help="Maximum ranked native targets to keep in phase3_native/native_targets.json.",
    )
    parser.add_argument(
        "--native-decompiler",
        choices=["auto", "none", "rizin", "radare2", "ghidra", "retdec"],
        default="auto",
        help="Preferred native decompiler adapter for auto/deep native analysis.",
    )
    parser.add_argument(
        "--native-preflight-only",
        action="store_true",
        help="Print native toolchain availability and exit without running APK analysis.",
    )
    parser.add_argument(
        "--native-max-libraries",
        type=positive_int,
        default=8,
        help="Maximum native libraries selected for deeper native review.",
    )
    parser.add_argument(
        "--native-max-decompile-targets",
        type=positive_int,
        default=40,
        help="Maximum native targets sent to the optional decompiler adapter.",
    )
    parser.add_argument(
        "--native-timeout-per-function",
        type=positive_int,
        default=90,
        help="Timeout in seconds for one optional native decompiler command.",
    )
    parser.add_argument(
        "--native-timeout-per-app",
        type=positive_int,
        default=3600,
        help="Total timeout budget in seconds for optional native decompilation.",
    )
    parser.add_argument(
        "--native-target-capabilities",
        default="",
        help="Comma-separated capability names to prioritize during native target selection.",
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
        type=non_negative_int,
        default=40,
        help="Maximum code snippets retained per capability in the code index.",
    )
    parser.add_argument(
        "--first-party-prefixes",
        default="",
        help=(
            "Comma-separated package prefixes that must be treated as first-party. "
            "The manifest package is inferred automatically."
        ),
    )
    parser.add_argument(
        "--third-party-prefixes",
        default="",
        help=(
            "Comma-separated package prefixes that must be treated as dependencies. "
            "Known SDK packages are classified automatically."
        ),
    )
    parser.add_argument(
        "--first-party-native-hashes",
        default="",
        help=(
            "Comma-separated native library SHA-256 values that must be treated "
            "as first-party."
        ),
    )
    parser.add_argument(
        "--third-party-native-hashes",
        default="",
        help=(
            "Comma-separated native library SHA-256 values that must be treated "
            "as third-party dependencies."
        ),
    )
    parser.add_argument("--log-level", default="INFO", help="Python logging level.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)

    if args.native_preflight_only:
        import json

        print(json.dumps(detect_native_toolchain(args.native_decompiler), indent=2, ensure_ascii=False))
        return 0
    if args.apk is None or args.workspace is None:
        raise SystemExit("--apk and --workspace are required unless --native-preflight-only is used.")

    config = PipelineConfig(
        apk_path=args.apk,
        workspace=args.workspace,
        force=args.force,
        isolated_workspace=args.isolated_workspace,
        jadx_version=args.jadx_version,
        jadx_threads=args.jadx_threads,
        jadx_timeout_per_apk=args.jadx_timeout_per_apk,
        jadx_download=not args.no_jadx_download,
        log_level=args.log_level,
        decompile_all_splits=not args.no_decompile_all_splits,
        resource_scan=not args.no_resource_scan,
        emit_evidence_packets=not args.no_evidence_packets,
        native_depth=args.native_depth,
        native_max_functions=args.native_max_functions,
        native_decompiler=args.native_decompiler,
        native_max_libraries=args.native_max_libraries,
        native_max_decompile_targets=args.native_max_decompile_targets,
        native_timeout_per_function=args.native_timeout_per_function,
        native_timeout_per_app=args.native_timeout_per_app,
        native_target_capabilities=tuple(
            item.strip()
            for item in args.native_target_capabilities.split(",")
            if item.strip()
        ),
        max_snippets_per_capability=args.max_snippets_per_capability,
        first_party_prefixes=tuple(
            item.strip()
            for item in args.first_party_prefixes.split(",")
            if item.strip()
        ),
        third_party_prefixes=tuple(
            item.strip()
            for item in args.third_party_prefixes.split(",")
            if item.strip()
        ),
        first_party_native_hashes=tuple(
            item.strip()
            for item in args.first_party_native_hashes.split(",")
            if item.strip()
        ),
        third_party_native_hashes=tuple(
            item.strip()
            for item in args.third_party_native_hashes.split(",")
            if item.strip()
        ),
    )

    try:
        summary = APKPipeline(config).run()
    except WorkspaceIdentityMismatchError as exc:
        print(f"Workspace identity error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError) as exc:
        print(f"Input or configuration error: {exc}", file=sys.stderr)
        return 2
    print(summary.to_json())
    return 0 if summary.to_dict()["all_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
