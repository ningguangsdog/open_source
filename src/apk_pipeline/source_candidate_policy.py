"""Shared policy for classifying open-source comparison candidates."""

from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any

from .source_provenance import annotate_source_provenance


_IMPLEMENTATION_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".go",
    ".java",
    ".kt",
    ".m",
    ".mm",
    ".rs",
    ".swift",
}
_CONTROL_PATH_PARTS = {
    "benchmark",
    "benchmarks",
    "demo",
    "demos",
    "example",
    "examples",
    "sample",
    "samples",
    "test",
    "tests",
}
_EXTERNAL_PATH_PARTS = {
    "3rdparty",
    "external",
    "externals",
    "third_party",
    "thirdparty",
    "vendor",
    "vendors",
}
_GENERATED_NAME_RE = re.compile(
    r"^(?:sub_|loc_|nullsub_|j_|imp_|thunk_|operator(?:new|delete)?$)",
    re.IGNORECASE,
)


def _path_parts(source: dict[str, Any]) -> tuple[str, ...]:
    raw = str(source.get("source_path") or "").replace("\\", "/")
    return tuple(part.lower() for part in PurePosixPath(raw).parts)


def _line_count(source: dict[str, Any]) -> int:
    try:
        return max(0, int(source.get("line_count") or 0))
    except (TypeError, ValueError):
        return 0


def effective_source_role(source: dict[str, Any]) -> tuple[str, str]:
    """Return the claim role after applying representation-neutral safeguards.

    Older frozen corpora labelled every method-level source row as a control.
    A project-owned implementation body is not a control merely because it is a
    method. This policy repairs that historical label without project-specific
    names or paths.
    """

    source = annotate_source_provenance(source)
    override = source.get("provenance_candidate_role_override")
    if override:
        return str(override), "curated_source_provenance_override"
    declared = str(source.get("candidate_role") or "upstream_candidate")
    ownership = str(source.get("ownership_class") or "unknown")
    parts = _path_parts(source)
    path = str(source.get("source_path") or "")
    suffix = PurePosixPath(path).suffix.lower()
    name = str(source.get("function_name") or source.get("name") or "").strip()

    if declared in {"dependency_control", "sibling_control"}:
        return declared, "declared_control_preserved"
    if ownership in {"test_example_or_demo", "test_or_example", "demo"}:
        return "method_control", "test_or_example_control"
    if any(part in _CONTROL_PATH_PARTS for part in parts):
        return "method_control", "control_path"
    if any(part in _EXTERNAL_PATH_PARTS for part in parts):
        return "dependency_control", "external_dependency_control"

    implementation_body = bool(
        suffix in _IMPLEMENTATION_SUFFIXES
        and _line_count(source) >= 8
        and name
        and not name.startswith("~")
        and not _GENERATED_NAME_RE.match(name)
    )
    if declared == "method_control" and implementation_body:
        return "upstream_candidate", "project_owned_implementation_promoted"
    return declared, "declared_role_preserved"


def source_analysis_lane(source: dict[str, Any]) -> str:
    """Map a source row to the research claim it may support."""

    source = annotate_source_provenance(source)
    role, _reason = effective_source_role(source)
    ownership = str(source.get("ownership_class") or "unknown")
    origin_class = str(source.get("source_origin_class") or "")
    if origin_class in {
        "generated_dependency_binding",
        "vendored_dependency",
    }:
        return "usage"
    if role in {"method_control", "dependency_control", "sibling_control"}:
        return "control"
    if ownership in {"test_example_or_demo", "test_or_example", "demo"}:
        return "control"
    if ownership in {
        "vendored_or_external",
        "vendored_dependency",
        "external_dependency",
    }:
        return "usage"
    return "adaptation"


def annotate_source_policy(source: dict[str, Any]) -> dict[str, Any]:
    """Return a copy carrying the effective role and its audit rationale."""

    annotated = annotate_source_provenance(source)
    role, reason = effective_source_role(annotated)
    annotated["declared_candidate_role"] = source.get("candidate_role")
    annotated["effective_candidate_role"] = role
    annotated["candidate_role_resolution"] = reason
    return annotated
