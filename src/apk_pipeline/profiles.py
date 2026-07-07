"""Named native deep-probe profile loading."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILES_DIR = REPO_ROOT / "profiles"


@dataclass(frozen=True, slots=True)
class NativeProbeProfile:
    name: str
    description: str
    priority_libraries: tuple[str, ...]
    deprioritize_libraries: tuple[str, ...]
    seed_name_patterns: tuple[str, ...]
    generic_helper_patterns: tuple[str, ...]
    capability_priorities: tuple[str, ...]
    default_limits: dict[str, int]
    raw: dict[str, Any]


def available_profiles() -> list[str]:
    if not PROFILES_DIR.exists():
        return []
    return sorted(path.stem for path in PROFILES_DIR.glob("*.json"))


def load_native_probe_profile(name: str) -> NativeProbeProfile:
    path = PROFILES_DIR / f"{name}.json"
    if not path.exists():
        known = ", ".join(available_profiles()) or "none"
        raise ValueError(f"Unknown native probe profile: {name}. Available profiles: {known}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return NativeProbeProfile(
        name=str(payload.get("name") or name),
        description=str(payload.get("description") or ""),
        priority_libraries=tuple(str(item) for item in payload.get("priority_libraries") or []),
        deprioritize_libraries=tuple(str(item) for item in payload.get("deprioritize_libraries") or []),
        seed_name_patterns=tuple(str(item) for item in payload.get("seed_name_patterns") or []),
        generic_helper_patterns=tuple(str(item) for item in payload.get("generic_helper_patterns") or []),
        capability_priorities=tuple(str(item) for item in payload.get("capability_priorities") or []),
        default_limits={str(key): int(value) for key, value in (payload.get("default_limits") or {}).items()},
        raw=payload,
    )
