from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from apk_pipeline.reuse_release_gate import (
    build_release_gate_report,
    load_release_contract,
)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


class ReuseReleaseGateTests(unittest.TestCase):
    def _workspace(self, root: Path) -> Path:
        workspace = root / "workspace"
        phase3 = workspace / "phase3_native"
        _write_json(
            workspace / "pipeline_validation.json",
            {
                "status": "passed",
                "copying_conclusion_supported": False,
                "summary": {"successful_ida_functions": 0},
            },
        )
        _write_jsonl(
            phase3 / "reuse_candidates.jsonl",
            [
                {
                    "source": {
                        "repository_full_name": "primetang/pylsd",
                    }
                }
            ],
        )
        _write_json(
            phase3 / "native_analysis.json",
            {
                "libraries": [
                    {
                        "vendor": "Apryse",
                        "component": "PDFNet SDK",
                    }
                ]
            },
        )
        _write_jsonl(
            phase3 / "managed_reuse_deep_comparisons.jsonl",
            [
                {
                    "commercial": {
                        "name": "processDocument",
                        "file": "sources/com/example/Document.java",
                    }
                }
            ],
        )
        return workspace

    def test_frozen_case_passes_when_all_contract_checks_hold(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = self._workspace(root)
            contract = {
                "cases": [
                    {
                        "id": "sample",
                        "validation_status": "passed",
                        "required_source_patterns": ["primetang/pylsd"],
                        "required_native_component_patterns": [
                            "Apryse.*PDFNet"
                        ],
                        "forbidden_managed_commercial_patterns": [
                            "com[/\\\\.]pdftron"
                        ],
                        "forbidden_managed_method_patterns": [
                            "^(hashCode|toString)$"
                        ],
                        "max_successful_ida_functions": 0,
                        "copying_conclusion_supported": False,
                    }
                ]
            }

            report = build_release_gate_report(
                contract,
                {"sample": workspace},
            )

            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["passed_case_count"], 1)

    def test_frozen_case_fails_on_dependency_or_generic_method_leak(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = self._workspace(root)
            _write_jsonl(
                workspace
                / "phase3_native"
                / "managed_reuse_deep_comparisons.jsonl",
                [
                    {
                        "commercial": {
                            "name": "hashCode",
                            "file": "sources/com/pdftron/pdf/Rect.java",
                        }
                    }
                ],
            )
            contract = {
                "cases": [
                    {
                        "id": "sample",
                        "forbidden_managed_commercial_patterns": [
                            "com[/\\\\.]pdftron"
                        ],
                        "forbidden_managed_method_patterns": ["^hashCode$"],
                    }
                ]
            }

            report = build_release_gate_report(
                contract,
                {"sample": workspace},
            )

            self.assertEqual(report["status"], "failed")
            self.assertEqual(
                set(report["cases"][0]["failed_checks"]),
                {
                    "forbidden_managed_commercial_patterns",
                    "forbidden_managed_method_patterns",
                },
            )

    def test_contract_rejects_duplicate_case_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            contract_path = Path(temp_dir) / "contract.json"
            _write_json(
                contract_path,
                {"cases": [{"id": "same"}, {"id": "same"}]},
            )

            with self.assertRaisesRegex(ValueError, "Duplicate release case id"):
                load_release_contract(contract_path)


if __name__ == "__main__":
    unittest.main()
