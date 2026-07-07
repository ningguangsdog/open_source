#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from apk_pipeline.logging_utils import configure_logging
from apk_pipeline.native_probe import run_native_deep_probe
from apk_pipeline.profiles import available_profiles


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a focused native-only deep probe from an existing pipeline workspace."
    )
    parser.add_argument("--workspace", required=True, type=Path, help="Existing APK pipeline workspace.")
    parser.add_argument(
        "--profile",
        default="adobe_acrobat_deep",
        help=f"Native probe profile name. Available: {', '.join(available_profiles()) or 'none'}",
    )
    parser.add_argument(
        "--native-decompiler",
        choices=["auto", "none", "rizin", "radare2", "ghidra", "retdec"],
        default="auto",
        help="Preferred native decompiler adapter.",
    )
    parser.add_argument("--max-seed-targets", type=int, default=None)
    parser.add_argument("--max-decompile-targets", type=int, default=None)
    parser.add_argument("--max-libraries", type=int, default=None)
    parser.add_argument("--timeout-per-function", type=int, default=None)
    parser.add_argument("--timeout-per-app", type=int, default=None)
    parser.add_argument("--expansion-rounds", type=int, default=None)
    parser.add_argument("--max-expanded-targets", type=int, default=None)
    parser.add_argument(
        "--no-refresh-phase5",
        action="store_true",
        help="Do not regenerate phase5 evidence packets after the probe.",
    )
    parser.add_argument("--force", action="store_true", help="Recompute the probe even if cached outputs exist.")
    parser.add_argument("--log-level", default="INFO", help="Python logging level.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)
    summary = run_native_deep_probe(
        args.workspace,
        profile_name=args.profile,
        native_decompiler=args.native_decompiler,
        max_seed_targets=args.max_seed_targets,
        max_decompile_targets=args.max_decompile_targets,
        max_libraries=args.max_libraries,
        timeout_per_function=args.timeout_per_function,
        timeout_per_app=args.timeout_per_app,
        expansion_rounds=args.expansion_rounds,
        max_expanded_targets=args.max_expanded_targets,
        refresh_phase5=not args.no_refresh_phase5,
        force=args.force,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
