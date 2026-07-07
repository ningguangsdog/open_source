#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
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
        "--native-feature-detail",
        choices=["pseudocode", "standard", "full"],
        default=None,
        help=(
            "Native evidence detail. pseudocode runs one decompiler pass per target; "
            "standard also collects function/disassembly JSON; full also collects CFG/xrefs."
        ),
    )
    parser.add_argument(
        "--no-refresh-phase5",
        action="store_true",
        help="Do not regenerate phase5 evidence packets after the probe.",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Suppress live progress messages and only print the final summary JSON.",
    )
    parser.add_argument("--force", action="store_true", help="Recompute the probe even if cached outputs exist.")
    parser.add_argument("--log-level", default="INFO", help="Python logging level.")
    return parser.parse_args()


def _short_target(event: dict) -> str:
    library = Path(str(event.get("library") or "")).name
    name = str(event.get("name") or "")
    return f"{library}::{name}" if library or name else ""


def print_progress(event: dict) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    kind = event.get("event")
    if kind == "probe_start":
        print(
            f"[native-probe {stamp}] start profile={event.get('profile')} "
            f"detail={event.get('feature_detail')} targets={event.get('max_decompile_targets')} "
            f"libs={event.get('max_libraries')} timeout/function={event.get('timeout_per_function')}s",
            flush=True,
        )
    elif kind == "seed_targets_ready":
        print(
            f"[native-probe {stamp}] selected seed candidates: {event.get('seed_target_count')} "
            f"({event.get('targets_path')})",
            flush=True,
        )
    elif kind in {"probe_plan_ready", "decompile_plan"}:
        print(
            f"[native-probe {stamp}] plan status={event.get('status')} "
            f"selected={event.get('selected_target_count')} libs={event.get('selected_libraries')}",
            flush=True,
        )
    elif kind == "inventory_start":
        print(
            f"[native-probe {stamp}] indexing symbols for {Path(str(event.get('library'))).name} "
            f"with {event.get('tool')} timeout={event.get('timeout')}s",
            flush=True,
        )
    elif kind == "inventory_finish":
        print(
            f"[native-probe {stamp}] indexed {Path(str(event.get('library'))).name}: "
            f"{event.get('function_count')} functions",
            flush=True,
        )
    elif kind == "target_start":
        print(
            f"[native-probe {stamp}] [{event.get('index')}/{event.get('total')}] decompile "
            f"{_short_target(event)} score={event.get('score')} timeout={event.get('timeout')}s",
            flush=True,
        )
    elif kind == "target_finish":
        status = "ok" if event.get("success") else "failed"
        detail = ""
        if event.get("error"):
            detail = f" error={event.get('error')}"
        elif event.get("output_path"):
            detail = (
                f" lines={event.get('pseudocode_nonempty_line_count')} "
                f"instructions={event.get('instruction_count')} output={event.get('output_path')}"
            )
        print(
            f"[native-probe {stamp}] [{event.get('index')}/{event.get('total')}] {status} "
            f"{_short_target(event)} elapsed={event.get('elapsed_seconds')}s{detail}",
            flush=True,
        )
    elif kind == "decompile_round_start":
        print(f"[native-probe {stamp}] round start: {event.get('round')}", flush=True)
    elif kind == "decompile_round_finish":
        print(
            f"[native-probe {stamp}] round finish: {event.get('round')} "
            f"attempted={event.get('attempted_targets')} success={event.get('successful_decompilations')}",
            flush=True,
        )
    elif kind == "expanded_targets_ready":
        print(f"[native-probe {stamp}] expanded callees: {event.get('expanded_target_count')}", flush=True)
    elif kind == "phase5_refresh_start":
        print(f"[native-probe {stamp}] refreshing phase5 evidence packets", flush=True)
    elif kind == "phase5_refresh_finish":
        print(f"[native-probe {stamp}] phase5 refresh success={event.get('success')}", flush=True)
    elif kind == "probe_finish":
        print(
            f"[native-probe {stamp}] done attempted={event.get('attempted_targets')} "
            f"success={event.get('successful_decompilations')} summary={event.get('summary_path')}",
            flush=True,
        )


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
        native_feature_detail=args.native_feature_detail,
        refresh_phase5=not args.no_refresh_phase5,
        force=args.force,
        progress_callback=None if args.no_progress else print_progress,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
