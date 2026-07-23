from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


PHASE_STATUSES = {"success", "partial", "failed", "skipped"}


@dataclass(slots=True)
class PhaseResult:
    name: str
    success: bool
    output_paths: list[Path] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    status: str | None = None

    def __post_init__(self) -> None:
        if self.status is None:
            self.status = "success" if self.success else "failed"
        if self.status not in PHASE_STATUSES:
            raise ValueError(f"Unsupported phase status: {self.status}")
        self.success = self.status == "success"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.name,
            "success": self.success,
            "status": self.status,
            "output_paths": [str(path) for path in self.output_paths],
            "details": self.details,
            "error": self.error,
            "warnings": [warning for warning in self.warnings if warning],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass(slots=True)
class PipelineSummary:
    apk_filename: str
    workspace: str
    phases: List[PhaseResult]
    input_resolution: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "2.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "apk_filename": self.apk_filename,
            "workspace": self.workspace,
            "phases": [p.to_dict() for p in self.phases],
            "all_success": all(p.status in {"success", "skipped"} for p in self.phases),
            "has_partial": any(p.status == "partial" for p in self.phases),
            "has_failed": any(p.status == "failed" for p in self.phases),
            "input_resolution": self.input_resolution,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
