from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
import json


def build_analysis_payload(
    manifest_summary_path: Optional[Path] = None,
    jadx_summary_path: Optional[Path] = None,
    native_summary_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build a future LLM/API payload without making any external calls.

    This module is intentionally inactive. It only standardizes the structure
    that will later be sent to an LLM provider.
    """
    payload: Dict[str, Any] = {"manifest": None, "jadx": None, "native": None}

    for key, path in [
        ("manifest", manifest_summary_path),
        ("jadx", jadx_summary_path),
        ("native", native_summary_path),
    ]:
        if path and path.exists():
            payload[key] = json.loads(path.read_text(encoding="utf-8"))

    return payload
