from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apk_pipeline.ida_backend import (
    _allocate_library_budgets,
    _latest_job_rows,
    _record_function_timeout,
    discover_ida_installation,
)
from apk_pipeline.ida_worker import (
    _completed_checkpoint,
    _current_job_rows,
    _select_functions,
    _successful_checkpoint,
)
from apk_pipeline.models import PhaseResult, PipelineSummary
from apk_pipeline.phase3_native import (
    _ida_artifacts_valid,
    build_native_evidence_units,
)
from apk_pipeline.result_validation import build_pipeline_validation
from apk_pipeline.utils import safe_write_json, sha256_file


class IDAAutomationTests(unittest.TestCase):
    def test_discovers_configured_idalib_installation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            install = Path(temp_dir) / "IDA Classroom.app"
            runtime = install / "Contents" / "MacOS"
            (runtime / "idalib" / "python").mkdir(parents=True)
            library_name = "libidalib.dylib"
            with patch("apk_pipeline.ida_backend.sys.platform", "darwin"):
                (runtime / library_name).write_bytes(b"idalib")
                (runtime / "idalib" / "python" / "idapro-0.0.9-py3-none-any.whl").write_bytes(b"wheel")
                discovered = discover_ida_installation(install)
            self.assertEqual(discovered, install.resolve())

    def test_library_budget_is_deterministic_and_covers_each_library(self) -> None:
        targets = {
            "/tmp/liba.so": [{"score": 20}],
            "/tmp/libb.so": [{"score": 90}],
            "/tmp/libc.so": [{"score": 40}],
        }
        first = _allocate_library_budgets(targets, 8)
        second = _allocate_library_budgets(targets, 8)
        self.assertEqual(first, second)
        self.assertEqual(sum(first.values()), 8)
        self.assertTrue(all(value >= 1 for value in first.values()))

    def test_ida_internal_function_becomes_native_evidence(self) -> None:
        library = {
            "name": "libcore.so",
            "extracted_path": "/tmp/libcore.so",
            "sha256": "a" * 64,
            "abi": "arm64-v8a",
            "ownership": {"category": "first_party"},
            "capability_counts": {"ocr": 1},
        }
        decompile_result = {
            "results": [
                {
                    "success": True,
                    "tool": "ida",
                    "output_path": None,
                    "target": {
                        "library": "/tmp/libcore.so",
                        "library_sha256": "a" * 64,
                        "abi": "arm64-v8a",
                        "kind": "internal_callee",
                        "name": "CoreAlgorithm",
                        "address": "0x2000",
                        "score": 75,
                        "ownership": {"category": "first_party"},
                        "capabilities": ["ocr"],
                    },
                    "function_features": {
                        "feature_hash": "feature",
                        "instruction_count": 120,
                    },
                    "semantic_role": {"role": "core_implementation"},
                }
            ]
        }
        units = build_native_evidence_units([library], [], decompile_result)
        unit = next(item for item in units if item.get("name") == "CoreAlgorithm")
        self.assertEqual(unit["evidence_source"], "automated_ida")
        self.assertEqual(unit["identity_verification"]["library_sha256"], "a" * 64)

    def test_checkpoint_retries_failure_and_detects_modified_pseudocode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "core.c"
            pseudocode.write_text("int core(void) { return 1; }", encoding="utf-8")
            result_stream = root / "functions.jsonl"
            rows = [
                {
                    "job_hash": "job",
                    "address": "0x1000",
                    "success": False,
                    "pseudocode_path": None,
                },
                {
                    "job_hash": "job",
                    "address": "0x1000",
                    "success": True,
                    "pseudocode_path": str(pseudocode),
                    "pseudocode_sha256": sha256_file(pseudocode),
                },
            ]
            result_stream.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            current = _current_job_rows(result_stream, "job")
            self.assertEqual(len(current), 1)
            self.assertTrue(_successful_checkpoint(current[0]))

            decompilation = root / "native_decompilation.json"
            safe_write_json(
                decompilation,
                {
                    "tool": "ida",
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": sha256_file(pseudocode),
                        }
                    ],
                },
            )
            self.assertTrue(_ida_artifacts_valid(decompilation))
            pseudocode.write_text("modified", encoding="utf-8")
            self.assertFalse(_successful_checkpoint(current[0]))
            self.assertFalse(_ida_artifacts_valid(decompilation))

    def test_parent_uses_only_latest_retry_state_per_function(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result_stream = Path(temp_dir) / "functions.jsonl"
            rows = [
                {
                    "job_hash": "job",
                    "address": "0x1000",
                    "success": False,
                },
                {
                    "job_hash": "other-job",
                    "address": "0x2000",
                    "success": True,
                },
                {
                    "job_hash": "job",
                    "address": "0x1000",
                    "success": True,
                },
            ]
            result_stream.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            current = _latest_job_rows(result_stream, "job")
            self.assertEqual(len(current), 1)
            self.assertTrue(current[0]["success"])

    def test_terminal_function_timeout_is_a_completed_checkpoint(self) -> None:
        self.assertTrue(
            _completed_checkpoint(
                {
                    "success": False,
                    "terminal_failure": True,
                    "error": "function_timeout:120",
                }
            )
        )

    def test_function_timeout_checkpoint_preserves_seed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            job = {
                "job_hash": "job",
                "library": "/tmp/libcore.so",
                "library_sha256": "a" * 64,
                "abi": "arm64-v8a",
                "ownership": {"category": "first_party"},
            }
            selected = {
                "address": "0x3000",
                "name": "CoreFunction",
                "selection_score": 90,
                "seed_target": {"capabilities": ["ocr"]},
                "is_pipeline_seed": True,
            }
            _record_function_timeout(root, job, selected, timeout=120)
            rows = _latest_job_rows(root / "functions.jsonl", "job")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["address"], "0x3000")
            self.assertTrue(rows[0]["terminal_failure"])
            self.assertEqual(rows[0]["seed_target"]["capabilities"], ["ocr"])

    def test_callgraph_function_inherits_seed_context_but_not_seed_role(self) -> None:
        seed = {
            "kind": "jni_symbol",
            "name": "Java_com_example_runOcr",
            "capabilities": ["ocr"],
        }
        inventory = [
            {"address": "0x1000", "name": seed["name"], "size_bytes": 200},
            {"address": "0x2000", "name": "CoreRecognition", "size_bytes": 800},
        ]
        with (
            patch(
                "apk_pipeline.ida_worker._resolve_seed_addresses",
                return_value=({0x1000}, {0x1000: seed}),
            ),
            patch(
                "apk_pipeline.ida_worker._function_refs",
                side_effect=lambda address: (
                    ([], [0x2000], 10)
                    if address == 0x1000
                    else ([0x1000], [], 20)
                ),
            ),
        ):
            selected = _select_functions(
                [seed],
                inventory,
                max_targets=2,
                callgraph_depth=1,
            )
        internal = next(row for row in selected if row["address"] == "0x2000")
        self.assertEqual(internal["seed_target"]["capabilities"], ["ocr"])
        self.assertFalse(internal["is_pipeline_seed"])
        self.assertEqual(internal["graph_depth_from_seed"], 1)

    def test_validation_passes_when_ida_evidence_reaches_phase5(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase3 = workspace / "phase3_native"
            phase5 = workspace / "phase5_evidence"
            pseudocode = phase3 / "decompiled_targets" / "core.c"
            pseudocode.parent.mkdir(parents=True)
            pseudocode.write_text("int core(void) { return 1; }", encoding="utf-8")
            digest = "b" * 64
            unit = {
                "unit_id": "ida-core",
                "kind": "native_target",
                "evidence_source": "automated_ida",
                "decompiler_success": True,
                "pseudocode_path": str(pseudocode),
                "identity_verification": {
                    "library_sha256": digest,
                    "abi": "arm64-v8a",
                    "address": "0x1000",
                },
            }
            safe_write_json(
                phase3 / "native_analysis.json",
                {"libraries": [{"sha256": digest}]},
            )
            safe_write_json(
                phase3 / "ida_automated_summary.json",
                {
                    "status": "completed",
                    "libraries_selected": {"libcore.so": 1},
                    "libraries_attempted": 1,
                    "successful_decompilations": 1,
                    "failed_decompilations": 0,
                },
            )
            safe_write_json(phase3 / "native_evidence_units.json", [unit])
            phase5.mkdir(parents=True)
            (phase5 / "evidence_units.jsonl").write_text(
                json.dumps(unit) + "\n",
                encoding="utf-8",
            )
            result = build_pipeline_validation(
                workspace,
                [
                    PhaseResult(name="phase3_native", success=True),
                    PhaseResult(name="phase5_evidence", success=True),
                ],
                expect_automated_ida=True,
                require_evidence_packet=True,
            )
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["ready_for_similarity"])

    def test_validation_fails_when_phase5_drops_ida_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase3 = workspace / "phase3_native"
            pseudocode = phase3 / "core.c"
            pseudocode.parent.mkdir(parents=True)
            pseudocode.write_text("int core(void) { return 1; }", encoding="utf-8")
            digest = "c" * 64
            safe_write_json(
                phase3 / "native_analysis.json",
                {"libraries": [{"sha256": digest}]},
            )
            safe_write_json(
                phase3 / "ida_automated_summary.json",
                {
                    "status": "completed",
                    "libraries_selected": {"libcore.so": 1},
                    "libraries_attempted": 1,
                    "successful_decompilations": 1,
                    "failed_decompilations": 0,
                },
            )
            safe_write_json(
                phase3 / "native_evidence_units.json",
                [
                    {
                        "unit_id": "ida-core",
                        "evidence_source": "automated_ida",
                        "decompiler_success": True,
                        "pseudocode_path": str(pseudocode),
                        "identity_verification": {
                            "library_sha256": digest,
                        },
                    }
                ],
            )
            result = build_pipeline_validation(
                workspace,
                [PhaseResult(name="phase3_native", success=True)],
                expect_automated_ida=True,
                require_evidence_packet=True,
            )
            self.assertEqual(result["status"], "failed")
            failed_ids = {
                item["id"] for item in result["checks"] if item["status"] == "failed"
            }
            self.assertIn("phase5_ida_integration", failed_ids)

    def test_partial_validation_blocks_pipeline_success(self) -> None:
        summary = PipelineSummary(
            apk_filename="sample.apk",
            workspace="/tmp/sample",
            phases=[PhaseResult(name="phase3_native", success=True)],
            validation={"status": "partial"},
        )
        self.assertFalse(summary.to_dict()["all_success"])


if __name__ == "__main__":
    unittest.main()
