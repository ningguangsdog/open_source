from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from apk_pipeline.managed_candidate_comparison import (
    compare_managed_candidates,
)
from apk_pipeline.phase5_evidence import _collect_evidence_units
from apk_pipeline.result_validation import _reuse_search_checks


def _candidate(
    pair_id: str,
    *,
    lane: str,
    project: str,
    components: dict[str, float],
    method_name: str = "processDocument",
    commercial_file: str = "sources/com/example/Document.java",
    ownership_category: str = "first_party",
) -> dict[str, object]:
    return {
        "candidate_pair_id": pair_id,
        "analysis_lane": lane,
        "representation_group": "managed",
        "candidate_deep_comparison_eligible": True,
        "selection_score": 0.91,
        "selection_evidence": {
            "signal_count": 3,
            "distinctive_signal_count": 2,
        },
        "retrieval_score": 0.88,
        "components": components,
        "commercial": {
            "function_id": f"commercial-{pair_id}",
            "representation": "dex_bytecode",
            "name": method_name,
            "file": commercial_file,
            "ownership": {"category": ownership_category},
        },
        "source": {
            "function_id": f"source-{pair_id}",
            "repository_full_name": project,
            "commit_sha": "a" * 40,
            "source_path": "src/main/java/Document.java",
            "function_name": "processDocument",
            "body_sha256": f"body-{pair_id}",
            "structural_sha256": f"structure-{pair_id}",
        },
    }


class ManagedCandidateComparisonTests(unittest.TestCase):
    def test_confirmed_dependency_and_generic_method_do_not_consume_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "managed.jsonl"
            summary = compare_managed_candidates(
                [
                    _candidate(
                        "pdfnet-hash",
                        lane="usage",
                        project="opencv/opencv",
                        components={"calls": 0.50},
                        method_name="hashCode",
                        commercial_file="sources/com/pdftron/pdf/Rect.java",
                        ownership_category="unknown",
                    ),
                    _candidate(
                        "first-party-hash",
                        lane="adaptation",
                        project="example/algorithm",
                        components={"calls": 0.50},
                        method_name="hashCode",
                    ),
                    _candidate(
                        "document-core",
                        lane="adaptation",
                        project="example/algorithm",
                        components={
                            "source_shingles": 0.62,
                            "calls": 0.58,
                            "strings": 0.52,
                        },
                    ),
                ],
                output,
                root / "summary.json",
                limit=10,
            )
            rows = [
                json.loads(line)
                for line in output.read_text(encoding="utf-8").splitlines()
            ]

            self.assertEqual([row["candidate_pair_id"] for row in rows], ["document-core"])
            self.assertEqual(summary["comparison_count"], 1)
            self.assertEqual(
                summary["selection"]["exclusion_reason_counts"],
                {
                    "commercial_dependency_or_platform": 1,
                    "managed_low_information_generic_method": 1,
                },
            )

    def test_diversity_caps_are_not_relaxed_to_fill_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            candidates = [
                _candidate(
                    f"project-a-{index}",
                    lane="adaptation",
                    project="example/project-a",
                    components={
                        "source_shingles": 0.62,
                        "calls": 0.58,
                        "strings": 0.52,
                    },
                    commercial_file=f"sources/com/example/A{index}.java",
                )
                for index in range(30)
            ]
            summary = compare_managed_candidates(
                candidates,
                root / "managed.jsonl",
                root / "summary.json",
                limit=20,
            )

            self.assertEqual(summary["comparison_count"], 8)
            self.assertEqual(
                summary["selection"]["selected_source_project_counts"],
                {"example/project-a": 8},
            )
            self.assertEqual(
                summary["selection"]["comparison_budget_unused_count"], 12
            )

    def test_bounded_comparison_keeps_claim_types_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "managed.jsonl"
            summary_path = root / "summary.json"
            candidates = [
                _candidate(
                    "adaptation",
                    lane="adaptation",
                    project="example/algorithm",
                    components={
                        "source_shingles": 0.62,
                        "calls": 0.58,
                        "strings": 0.48,
                    },
                ),
                _candidate(
                    "usage",
                    lane="usage",
                    project="example/dependency",
                    components={"exact_body": 1.0},
                ),
                _candidate(
                    "native",
                    lane="adaptation",
                    project="example/native",
                    components={"exact_body": 1.0},
                )
                | {"representation_group": "native"},
            ]

            summary = compare_managed_candidates(
                candidates,
                output,
                summary_path,
                limit=10,
            )
            rows = [
                json.loads(line)
                for line in output.read_text(encoding="utf-8").splitlines()
            ]

            self.assertEqual(summary["comparison_count"], 2)
            self.assertEqual(summary["adaptation_review_ready_count"], 1)
            self.assertEqual(summary["usage_review_ready_count"], 1)
            self.assertFalse(summary["copying_conclusion_supported"])
            self.assertEqual(
                {row["analysis_lane"] for row in rows},
                {"adaptation", "usage"},
            )

    def test_phase5_and_validation_preserve_managed_comparisons(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase3 = workspace / "phase3_native"
            phase5 = workspace / "phase5_evidence"
            phase3.mkdir(parents=True)
            phase5.mkdir(parents=True)
            output = phase3 / "managed_reuse_deep_comparisons.jsonl"
            summary_path = (
                phase3 / "managed_reuse_deep_comparison_summary.json"
            )
            compare_managed_candidates(
                [
                    _candidate(
                        "managed-1",
                        lane="usage",
                        project="example/dependency",
                        components={"exact_body": 1.0},
                    )
                ],
                output,
                summary_path,
                limit=10,
            )
            units = _collect_evidence_units(workspace)
            managed_units = [
                row
                for row in units
                if row.get("kind")
                == "open_source_managed_deep_comparison"
            ]
            self.assertEqual(len(managed_units), 1)
            self.assertFalse(
                managed_units[0]["traceability"]["ida_required"]
            )
            (phase5 / "evidence_units.jsonl").write_text(
                "\n".join(json.dumps(row) for row in units) + "\n",
                encoding="utf-8",
            )

            checks = _reuse_search_checks(
                workspace,
                native_library_count=0,
                require_evidence_packet=True,
            )
            managed_check = next(
                row
                for row in checks
                if row["id"] == "managed_code_deep_comparison"
            )
            integration = next(
                row
                for row in checks
                if row["id"]
                == "phase5_managed_deep_comparison_integration"
            )
            traceability = next(
                row
                for row in checks
                if row["id"] == "phase5_reuse_traceability"
            )
            self.assertEqual(managed_check["status"], "passed")
            self.assertEqual(integration["status"], "passed")
            self.assertEqual(traceability["status"], "passed")


if __name__ == "__main__":
    unittest.main()
