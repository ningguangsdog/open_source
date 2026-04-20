from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running the script from repository root without prior package installation.
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apk_pipeline import APKPipeline, PipelineConfig


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the APK reverse-engineering pipeline.")
    parser.add_argument("--apk", required=True, help="Path to the APK file")
    parser.add_argument("--workspace", required=True, help="Workspace/output directory")
    parser.add_argument("--force", action="store_true", help="Re-run phases even if outputs already exist")
    parser.add_argument("--jadx-version", default="1.5.0")
    parser.add_argument("--jadx-threads", type=int, default=4)
    parser.add_argument("--no-jadx-download", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    config = PipelineConfig(
        apk_path=Path(args.apk),
        workspace=Path(args.workspace),
        force=args.force,
        jadx_version=args.jadx_version,
        jadx_threads=args.jadx_threads,
        jadx_download=not args.no_jadx_download,
        log_level=args.log_level,
    )
    pipeline = APKPipeline(config)
    summary = pipeline.run()
    print(summary.to_json())


if __name__ == "__main__":
    main()
