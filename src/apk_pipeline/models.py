from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import json


@dataclass(slots=True)
class PhaseResult:
    phase: str
    success: bool
    apk_filename: str
    output_dir: str
    summary_path: Optional[str] = None
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass(slots=True)
class PipelineSummary:
    apk_filename: str
    workspace: str
    phases: List[PhaseResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apk_filename": self.apk_filename,
            "workspace": self.workspace,
            "phases": [p.to_dict() for p in self.phases],
            "all_success": all(p.success for p in self.phases),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
