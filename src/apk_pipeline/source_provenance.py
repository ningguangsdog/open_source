"""Conservative attribution for open-source comparison rows.

The source corpus records where a function was observed. That carrier
repository is not always the implementation's upstream owner: generated SDK
bindings and vendored dependency code often appear in unrelated projects.
This module preserves both identities and only rewrites attribution when a
rule is high confidence and auditable.
"""

from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any


PROJECT_ROLE_OVERRIDES: dict[str, dict[str, Any]] = {
    "cihantopal/ed_lib": {
        "candidate_role": "upstream_candidate",
        "canonical_upstream_project": "CihanTopal/ED_Lib",
        "canonical_component": "ED_Lib line and edge detection implementation",
        "origin_class": "project_owned_upstream",
        "origin_confidence": 1.0,
        "origin_rule": "curated_corpus_project_role",
    },
}


def _project(source: dict[str, Any]) -> str:
    return str(
        source.get("repository_full_name")
        or source.get("corpus_id")
        or source.get("project_id")
        or "unknown_project"
    )


def _path(source: dict[str, Any]) -> str:
    return str(source.get("source_path") or "").replace("\\", "/")


def _function_name(source: dict[str, Any]) -> str:
    return str(source.get("function_name") or source.get("name") or "")


def _opencv_component(source: dict[str, Any]) -> str | None:
    project = _project(source).casefold()
    if project == "opencv/opencv":
        return None
    path = f"/{_path(source).casefold().strip('/')}"
    name = _function_name(source).casefold()
    java_binding = bool(
        "/org/opencv/" in path
        or "/opencvlibrary" in path
        or (
            PurePosixPath(path).name in {"core.java", "imgproc.java"}
            and ("opencv" in path or name.startswith("org.opencv."))
        )
    )
    if java_binding:
        return "generated_java_binding"
    native_implementation = bool(
        "/third_party/opencv/" in path
        or "/third-party/opencv/" in path
        or "/vendor/opencv/" in path
        or "/opencv/modules/" in path
        or "/opencv2/" in path
        or (
            "opencv" in path
            and re.search(r"/(?:modules/[^/]+/src|src/opencv)/", path)
        )
    )
    return "vendored_native_implementation" if native_implementation else None


def source_provenance(source: dict[str, Any]) -> dict[str, Any]:
    """Return an audited origin record without discarding the carrier repo."""

    carrier = _project(source)
    override = PROJECT_ROLE_OVERRIDES.get(carrier.casefold())
    if override:
        return {"carrier_project": carrier, **override}

    opencv_component = _opencv_component(source)
    if opencv_component == "generated_java_binding":
        return {
            "carrier_project": carrier,
            "candidate_role": "dependency_control",
            "canonical_upstream_project": "opencv/opencv",
            "canonical_component": "OpenCV generated Java API binding",
            "origin_class": "generated_dependency_binding",
            "origin_confidence": 0.99,
            "origin_rule": "opencv_generated_binding_path",
        }
    if opencv_component == "vendored_native_implementation":
        return {
            "carrier_project": carrier,
            "candidate_role": "dependency_control",
            "canonical_upstream_project": "opencv/opencv",
            "canonical_component": "OpenCV native implementation",
            "origin_class": "vendored_dependency",
            "origin_confidence": 0.98,
            "origin_rule": "opencv_vendored_native_path",
        }

    ownership = str(source.get("ownership_class") or "unknown")
    if ownership in {
        "vendored_or_external",
        "vendored_dependency",
        "external_dependency",
    }:
        origin_class = "vendored_dependency"
    elif ownership in {"generated_or_build", "generated"}:
        origin_class = "generated_code"
    elif ownership in {"test_example_or_demo", "test_or_example", "demo"}:
        origin_class = "test_or_demo"
    else:
        origin_class = "carrier_project_owned_or_unknown"
    return {
        "carrier_project": carrier,
        "candidate_role": None,
        "canonical_upstream_project": carrier,
        "canonical_component": None,
        "origin_class": origin_class,
        "origin_confidence": 0.5 if carrier != "unknown_project" else 0.2,
        "origin_rule": "source_index_carrier_fallback",
    }


def annotate_source_provenance(source: dict[str, Any]) -> dict[str, Any]:
    annotated = dict(source)
    provenance = source_provenance(source)
    annotated.update(
        {
            "carrier_project": provenance["carrier_project"],
            "canonical_upstream_project": provenance[
                "canonical_upstream_project"
            ],
            "canonical_component": provenance["canonical_component"],
            "source_origin_class": provenance["origin_class"],
            "source_origin_confidence": provenance["origin_confidence"],
            "source_origin_rule": provenance["origin_rule"],
        }
    )
    if provenance.get("candidate_role"):
        annotated["provenance_candidate_role_override"] = provenance[
            "candidate_role"
        ]
    return annotated


def canonical_source_project(source: dict[str, Any]) -> str:
    return str(
        source.get("canonical_upstream_project")
        or source_provenance(source)["canonical_upstream_project"]
    )
