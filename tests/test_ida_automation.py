from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apk_pipeline.ida_backend import (
    _allocate_library_budgets,
    _append_jsonl,
    _current_worker_progress,
    _latest_job_rows,
    _record_function_timeout,
    _result_from_worker_row,
    _run_worker_with_heartbeat,
    discover_ida_installation,
    run_ida_inventory,
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
    def test_non_ida_profile_uses_general_readiness_without_reuse_claims(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = build_pipeline_validation(
                Path(temp_dir),
                [PhaseResult(name="phase1_manifest", success=True)],
                expect_automated_ida=False,
                require_evidence_packet=False,
            )

            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["ready_for_similarity"])
            self.assertFalse(result["ready_for_usage_analysis"])
            self.assertFalse(result["ready_for_adaptation_analysis"])
            self.assertFalse(result["ready_for_copying_review"])
            self.assertFalse(result["copying_conclusion_supported"])

    def test_completed_inventory_job_is_reused_without_worker_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            library = root / "libcore.so"
            library.write_bytes(b"\x7fELF-test-library")
            output = root / "inventory"
            install = root / "IDA Classroom.app"
            install.mkdir()

            def fake_worker(*_args: object, **kwargs: object) -> tuple[object, ...]:
                job_dir = Path(str(kwargs["job_dir"]))
                job = json.loads((job_dir / "job.json").read_text(encoding="utf-8"))
                inventory_row = {
                    "function_id": "native-1",
                    "representation": "ida_lightweight_inventory",
                    "address": "0x1000",
                    "name": "CoreFunction",
                    "library_sha256": job["library_sha256"],
                }
                (job_dir / "inventory.jsonl").write_text(
                    json.dumps(inventory_row) + "\n",
                    encoding="utf-8",
                )
                safe_write_json(
                    job_dir / "inventory.json",
                    {
                        "job_hash": job["job_hash"],
                        "library_sha256": job["library_sha256"],
                        "function_count": 1,
                    },
                )
                safe_write_json(
                    job_dir / "summary.json",
                    {
                        "job_hash": job["job_hash"],
                        "status": "completed",
                        "completed": True,
                        "library_sha256": job["library_sha256"],
                        "inventory_function_count": 1,
                    },
                )
                return 0, "", "", None, None

            installation = {
                "available": True,
                "install_dir": str(install),
            }
            with (
                patch(
                    "apk_pipeline.ida_backend.ida_installation_info",
                    return_value=installation,
                ),
                patch(
                    "apk_pipeline.ida_backend._copy_ida_user_files",
                    return_value=None,
                ),
                patch(
                    "apk_pipeline.ida_backend._run_worker_with_heartbeat",
                    side_effect=fake_worker,
                ) as worker,
            ):
                first = run_ida_inventory(
                    [
                        {
                            "extracted_path": str(library),
                            "abi": "arm64-v8a",
                            "ownership": {"category": "first_party"},
                        }
                    ],
                    output,
                )
                self.assertEqual(worker.call_count, 1)
            self.assertEqual(first["executed_library_count"], 1)
            self.assertEqual(first["reused_library_count"], 0)

            with (
                patch(
                    "apk_pipeline.ida_backend.ida_installation_info",
                    return_value=installation,
                ),
                patch(
                    "apk_pipeline.ida_backend._run_worker_with_heartbeat",
                    side_effect=AssertionError("worker must not run"),
                ),
            ):
                second = run_ida_inventory(
                    [
                        {
                            "extracted_path": str(library),
                            "abi": "arm64-v8a",
                            "ownership": {"category": "first_party"},
                        }
                    ],
                    output,
                )
            self.assertEqual(second["status"], "completed")
            self.assertEqual(second["executed_library_count"], 0)
            self.assertEqual(second["reused_library_count"], 1)
            self.assertEqual(second["indexed_function_count"], 1)

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

    def test_library_budget_expands_to_preserve_every_upstream_seed(self) -> None:
        targets = {
            "/tmp/liba.so": [{"score": 20} for _ in range(4)],
            "/tmp/libb.so": [{"score": 90} for _ in range(3)],
        }

        budgets = _allocate_library_budgets(targets, 5)

        self.assertEqual(budgets, {"/tmp/libb.so": 3, "/tmp/liba.so": 4})
        self.assertEqual(sum(budgets.values()), 7)

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
            self.assertTrue(
                _record_function_timeout(root, job, selected, timeout=120)
            )
            self.assertFalse(
                _record_function_timeout(root, job, selected, timeout=120)
            )
            rows = _latest_job_rows(root / "functions.jsonl", "job")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["address"], "0x3000")
            self.assertTrue(rows[0]["terminal_failure"])
            self.assertEqual(rows[0]["seed_target"]["capabilities"], ["ocr"])

    def test_function_timeout_does_not_override_successful_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "core.c"
            pseudocode.write_text("int core(void) { return 1; }", encoding="utf-8")
            job = {
                "job_hash": "job",
                "library": "/tmp/libcore.so",
                "library_sha256": "a" * 64,
                "abi": "arm64-v8a",
            }
            _append_jsonl(
                root / "functions.jsonl",
                {
                    "job_hash": "job",
                    "address": "0x3000",
                    "success": True,
                    "pseudocode_path": str(pseudocode),
                    "pseudocode_sha256": sha256_file(pseudocode),
                },
            )

            recorded = _record_function_timeout(
                root,
                job,
                {"address": "0x3000", "name": "CoreFunction"},
                timeout=120,
            )

            self.assertFalse(recorded)
            rows = _latest_job_rows(root / "functions.jsonl", "job")
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["success"])

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
        self.assertEqual(internal["selection_source"], "seed_callgraph")

    def test_pipeline_seed_cannot_be_displaced_by_higher_scoring_context(self) -> None:
        seed = {
            "kind": "reuse_candidate",
            "name": "candidate_wrapper",
            "address": "0x1000",
            "commercial_function_id": "commercial-seed",
        }
        inventory = [
            {"address": "0x1000", "name": "candidate_wrapper", "size_bytes": 40},
            {"address": "0x2000", "name": "core_context", "size_bytes": 4000},
        ]
        with (
            patch(
                "apk_pipeline.ida_worker._resolve_seed_addresses",
                return_value=({0x1000}, {0x1000: seed}),
            ),
            patch(
                "apk_pipeline.ida_worker._selection_score",
                side_effect=lambda row, **_kwargs: (
                    (1, ["seed"]) if row["address"] == "0x1000" else (9999, ["context"])
                ),
            ),
        ):
            selected = _select_functions(
                [seed],
                inventory,
                max_targets=1,
                callgraph_depth=0,
            )

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["address"], "0x1000")
        self.assertEqual(selected[0]["selection_source"], "pipeline_seed")

    def test_library_inventory_selection_retains_context_without_claiming_seed_match(
        self,
    ) -> None:
        seed = {
            "kind": "library",
            "name": "libcore.so",
            "score": 80,
            "capabilities": ["ocr", "scan_image"],
            "reasons": ["library_signal"],
        }
        inventory = [
            {
                "address": "0x1000",
                "name": "RunOcrPipeline",
                "size_bytes": 800,
            },
            {
                "address": "0x2000",
                "name": "sub_2000",
                "size_bytes": 20_000,
            },
        ]
        with patch(
            "apk_pipeline.ida_worker._resolve_seed_addresses",
            return_value=(set(), {}),
        ):
            selected = _select_functions(
                [seed],
                inventory,
                max_targets=2,
                callgraph_depth=2,
            )
        named = next(row for row in selected if row["address"] == "0x1000")
        self.assertEqual(named["selection_source"], "library_inventory")
        self.assertTrue(named["seed_target"]["context_only"])
        self.assertIn("ocr", named["seed_target"]["capabilities"])

    def test_stale_worker_progress_is_ignored_after_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            progress_path = root / "progress.json"
            safe_write_json(
                progress_path,
                {
                    "job_hash": "job",
                    "updated_at_epoch": 10,
                    "current_started_at_epoch": 10,
                    "current_function": {"address": "0x1000"},
                },
            )
            self.assertEqual(
                _current_worker_progress(
                    progress_path,
                    job_hash="job",
                    worker_started_at_epoch=20,
                ),
                {},
            )

            class FakeProcess:
                returncode = 0

                def __init__(self) -> None:
                    self.communicate_calls = 0
                    self.killed = False

                def communicate(self, timeout: float | None = None):
                    self.communicate_calls += 1
                    if self.communicate_calls == 1:
                        raise subprocess.TimeoutExpired("worker", timeout)
                    return "done", ""

                def kill(self) -> None:
                    self.killed = True

            process = FakeProcess()
            with patch(
                "apk_pipeline.ida_backend.subprocess.Popen",
                return_value=process,
            ):
                returncode, _, _, error, timed_out = _run_worker_with_heartbeat(
                    ["worker"],
                    environment={},
                    timeout=30,
                    timeout_per_function=1,
                    job_dir=root,
                    progress_callback=None,
                    library="libcore.so",
                    index=1,
                    total=1,
                    attempt=2,
                    job_hash="job",
                )
            self.assertEqual(returncode, 0)
            self.assertIsNone(error)
            self.assertIsNone(timed_out)
            self.assertFalse(process.killed)

    def test_inventory_result_derives_function_capability_and_keeps_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pseudocode = Path(temp_dir) / "ocr.c"
            pseudocode.write_text(
                "int run_ocr_pipeline(Image *image) { return recognize_text(image); }",
                encoding="utf-8",
            )
            result = _result_from_worker_row(
                {
                    "success": True,
                    "library": "/tmp/libcore.so",
                    "library_sha256": "a" * 64,
                    "abi": "arm64-v8a",
                    "address": "0x1000",
                    "name": "RunOcrPipeline",
                    "selection_source": "library_inventory",
                    "seed_target": {
                        "kind": "library_context",
                        "capabilities": ["ocr", "scan_image"],
                        "context_only": True,
                    },
                    "pseudocode_path": str(pseudocode),
                    "pseudocode_sha256": sha256_file(pseudocode),
                }
            )
        target = result["target"]
        self.assertEqual(target["kind"], "internal_inventory")
        self.assertIn("ocr", target["capabilities"])
        self.assertEqual(target["context_capabilities"], ["ocr", "scan_image"])
        self.assertEqual(target["capability_provenance"], "function_content_only")

    def test_worker_result_preserves_reuse_candidate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pseudocode = Path(temp_dir) / "candidate.c"
            pseudocode.write_text("int candidate(void) { return 7; }", encoding="utf-8")
            result = _result_from_worker_row(
                {
                    "success": True,
                    "library": "/tmp/libcore.so",
                    "library_sha256": "d" * 64,
                    "abi": "arm64-v8a",
                    "address": "0x3000",
                    "name": "candidate",
                    "selection_source": "pipeline_seed",
                    "seed_target": {
                        "kind": "reuse_candidate",
                        "analysis_lane": "adaptation",
                        "candidate_pair_id": "pair-1",
                        "commercial_function_id": "commercial-1",
                        "source_function_id": "source-1",
                        "reuse_candidate": {
                            "candidate_pair_id": "pair-1",
                            "commercial": {"function_id": "commercial-1"},
                            "source": {"function_id": "source-1"},
                        },
                    },
                    "pseudocode_path": str(pseudocode),
                    "pseudocode_sha256": sha256_file(pseudocode),
                }
            )

        target = result["target"]
        self.assertEqual(target["analysis_lane"], "adaptation")
        self.assertEqual(target["candidate_pair_id"], "pair-1")
        self.assertEqual(target["commercial_function_id"], "commercial-1")
        self.assertEqual(target["source_function_id"], "source-1")

    def test_callgraph_result_keeps_origin_without_inheriting_seed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pseudocode = Path(temp_dir) / "neighbor.c"
            pseudocode.write_text("int neighbor(void) { return 9; }", encoding="utf-8")
            result = _result_from_worker_row(
                {
                    "success": True,
                    "library": "/tmp/libcore.so",
                    "library_sha256": "e" * 64,
                    "abi": "arm64-v8a",
                    "address": "0x4000",
                    "name": "neighbor",
                    "selection_source": "seed_callgraph",
                    "graph_depth_from_seed": 1,
                    "seed_target": {
                        "kind": "reuse_candidate",
                        "analysis_lane": "usage",
                        "candidate_pair_id": "pair-origin",
                        "commercial_function_id": "commercial-origin",
                        "source_function_id": "source-origin",
                        "reuse_candidate": {
                            "candidate_pair_id": "pair-origin",
                        },
                    },
                    "pseudocode_path": str(pseudocode),
                    "pseudocode_sha256": sha256_file(pseudocode),
                }
            )

        target = result["target"]
        self.assertNotIn("commercial_function_id", target)
        self.assertNotIn("reuse_candidate", target)
        self.assertEqual(
            target["origin_seed_candidate"]["commercial_function_id"],
            "commercial-origin",
        )

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
                    "failed_decompilations": 1,
                    "requested_seed_count": 1,
                    "resolved_seed_count": 1,
                    "selected_seed_count": 1,
                    "unresolved_seed_count": 0,
                    "unselected_resolved_seed_count": 0,
                },
            )
            failed_unit = {
                "unit_id": "ida-timeout",
                "kind": "native_target",
                "evidence_source": "automated_ida",
                "decompiler_success": False,
                "comparison_eligible": False,
            }
            safe_write_json(
                phase3 / "native_evidence_units.json",
                [unit, failed_unit],
            )
            phase5.mkdir(parents=True)
            (phase5 / "evidence_units.jsonl").write_text(
                json.dumps(unit) + "\n" + json.dumps(failed_unit) + "\n",
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
            self.assertFalse(result["ready_for_usage_analysis"])
            self.assertFalse(result["ready_for_copying_review"])
            self.assertFalse(result["copying_conclusion_supported"])
            integration = next(
                item
                for item in result["checks"]
                if item["id"] == "phase5_ida_integration"
            )
            self.assertEqual(
                integration["details"]["phase5_failed_ida_audit_unit_count"],
                1,
            )

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
