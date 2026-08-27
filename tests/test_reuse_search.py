from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import zipfile

from apk_pipeline.function_fingerprint import (
    bottom_k_token_signature,
    build_fingerprint,
    stable_id,
)
from apk_pipeline.dex_method_index import _sorted_dex_entries, build_dex_method_row
from apk_pipeline.deep_candidate_comparison import compare_decompiled_candidates
from apk_pipeline.models import PhaseResult
from apk_pipeline.native_decompiler import _adaptive_library_target_selection
from apk_pipeline.oss_binary_index import (
    extract_apk_native_artifacts,
    materialize_oss_binary_index,
)
from apk_pipeline.oss_build_queue import build_oss_build_queue
from apk_pipeline.phase5_evidence import _collect_evidence_units
from apk_pipeline.post_ida_reanalysis import replay_post_ida_analysis
from apk_pipeline.phase3_native import (
    _consolidate_native_inventory,
    _primary_native_projection,
)
from apk_pipeline.result_validation import (
    _reuse_search_checks,
    build_pipeline_validation,
)
from apk_pipeline.reuse_candidate_retrieval import (
    annotate_candidate_for_selection,
    native_decompile_targets,
    retrieve_candidates,
    select_candidate_cohorts,
)
from apk_pipeline.source_method_index import build_jadx_method_index
from apk_pipeline.source_candidate_policy import (
    effective_source_role,
    source_analysis_lane,
)
from apk_pipeline.utils import safe_write_json


class ReuseSearchTests(unittest.TestCase):
    def test_wrapper_seed_resolves_to_algorithm_body_and_expands_source_family(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper_path = root / "wrapper.c"
            wrapper_path.write_text(
                "return LineSegmentDetection(a1, a2);",
                encoding="utf-8",
            )
            implementation_path = root / "implementation.c"
            implementation_path.write_text(
                """int LineSegmentDetection(double ang_th, double density_th) {
                int n_bins = 1024;
                if (ang_th > 22.5) { region_grow(ang_th); }
                while (density_th < 0.7) { density_th += 0.01; }
                log_message("region image API");
                log_message("not enough memory");
                return refine_region(n_bins);
                }""",
                encoding="utf-8",
            )
            commercial_id = "commercial-lsd-wrapper"
            seed_candidate = {
                "candidate_pair_id": "pair-wrapper-control",
                "commercial_function_id": commercial_id,
                "source_function_id": "opencv-wrapper",
                "analysis_lane": "control",
                "commercial": {
                    "function_id": commercial_id,
                    "library": "libscanner.so",
                    "library_sha256": "a" * 64,
                    "address": "0x1000",
                    "ownership": {"category": "first_party"},
                },
                "source": {
                    "function_id": "opencv-wrapper",
                    "repository_full_name": "opencv/opencv",
                    "commit_sha": "b" * 40,
                    "source_path": "include/opencv2/line_descriptor.hpp",
                    "start_line": 20,
                    "function_name": "~LineSegmentDetector",
                    "candidate_role": "method_control",
                    "ownership_class": "project_owned_candidate",
                    "line_count": 1,
                },
            }
            second_seed_candidate = {
                **seed_candidate,
                "candidate_pair_id": "pair-wrapper-scale-control",
                "commercial_function_id": "commercial-lsd-scale-wrapper",
                "commercial": {
                    **seed_candidate["commercial"],
                    "function_id": "commercial-lsd-scale-wrapper",
                    "address": "0x1100",
                },
            }
            candidate_path = root / "review.jsonl"
            candidate_path.write_text(
                json.dumps(seed_candidate)
                + "\n"
                + json.dumps(second_seed_candidate)
                + "\n",
                encoding="utf-8",
            )
            source_path = root / "source.jsonl"
            source_path.write_text(
                json.dumps(seed_candidate["source"])
                + "\n"
                + json.dumps(
                    {
                        "repository_full_name": "primetang/pylsd",
                        "commit_sha": "c" * 40,
                        "source_path": "source/src/lsd.cpp",
                        "start_line": 120,
                        "function_name": "LineSegmentDetection",
                        "candidate_role": "method_control",
                        "ownership_class": "project_owned_candidate",
                        "line_count": 136,
                        "strings": [
                            "\"region image API\"",
                            "\"not enough memory\"",
                        ],
                        "constants": ["1024", "22.5", "0.7"],
                        "top_calls": [
                            {"name": "region_grow"},
                            {"name": "refine_region"},
                        ],
                        "branch_counts": {"if": 1, "while": 1, "return": 1},
                        "structure_token_count": 180,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output_path = root / "deep.jsonl"
            summary = compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(wrapper_path),
                            "pseudocode_sha256": "wrapper-hash",
                            "target": {
                                "commercial_function_id": commercial_id,
                                "candidate_pair_id": "pair-wrapper-control",
                                "analysis_lane": "control",
                                "library": "libscanner.so",
                                "library_sha256": "a" * 64,
                                "address": "0x1000",
                                "name": ".LineSegmentDetection",
                                "selection_source": "pipeline_seed",
                                "reuse_candidate": seed_candidate,
                            },
                            "function_features": {
                                "instruction_count": 4,
                                "basic_block_count": 2,
                                "pseudocode_nonempty_line_count": 1,
                                "callee_addresses": ["0x2000"],
                            },
                        },
                        {
                            "success": True,
                            "output_path": str(implementation_path),
                            "pseudocode_sha256": "implementation-hash",
                            "target": {
                                "library": "libscanner.so",
                                "library_sha256": "a" * 64,
                                "address": "0x2000",
                                "name": "LineSegmentDetection",
                                "selection_source": "seed_callgraph",
                                "origin_seed_candidate": {
                                    "candidate_pair_id": "pair-wrapper-control"
                                },
                            },
                            "function_features": {
                                "instruction_count": 1876,
                                "basic_block_count": 256,
                                "pseudocode_nonempty_line_count": 1361,
                                "string_refs": [
                                    "region image API",
                                    "not enough memory",
                                ],
                                "call_targets": ["region_grow", "refine_region"],
                            },
                        },
                        {
                            "success": True,
                            "output_path": str(wrapper_path),
                            "pseudocode_sha256": "scale-wrapper-hash",
                            "target": {
                                "commercial_function_id": "commercial-lsd-scale-wrapper",
                                "candidate_pair_id": "pair-wrapper-scale-control",
                                "analysis_lane": "control",
                                "library": "libscanner.so",
                                "library_sha256": "a" * 64,
                                "address": "0x1100",
                                "name": "lsd_scale",
                                "selection_source": "pipeline_seed",
                                "reuse_candidate": second_seed_candidate,
                            },
                            "function_features": {
                                "instruction_count": 5,
                                "basic_block_count": 2,
                                "pseudocode_nonempty_line_count": 1,
                                "callee_addresses": ["0x2000"],
                            },
                        },
                    ]
                },
                candidate_path,
                [source_path],
                output_path,
                root / "summary.json",
            )

            rows = [json.loads(line) for line in output_path.read_text().splitlines()]
            pylsd_rows = [
                row for row in rows if row["source_project"] == "primetang/pylsd"
            ]
            self.assertEqual(len(pylsd_rows), 1)
            pylsd = pylsd_rows[0]
            self.assertEqual(pylsd["commercial"]["decompiled_address"], "0x2000")
            self.assertEqual(pylsd["commercial_seed_count"], 2)
            self.assertEqual(
                {row["name"] for row in pylsd["commercial_seed_variants"]},
                {".LineSegmentDetection", "lsd_scale"},
            )
            self.assertTrue(
                pylsd["canonical_resolution"]["resolved_away_from_seed"]
            )
            self.assertEqual(pylsd["analysis_lane"], "adaptation")
            self.assertEqual(
                pylsd["source"]["effective_candidate_role"],
                "upstream_candidate",
            )
            self.assertEqual(
                pylsd["relationship_assessment"],
                "open_source_implementation_match_candidate",
            )
            self.assertEqual(
                pylsd["deep_components"]["matched_distinctive_strings"],
                ["not enough memory", "region image api"],
            )
            self.assertEqual(
                pylsd["deep_components"]["set_similarity_basis"][
                    "distinctive_strings"
                ],
                "overlap_coefficient",
            )
            self.assertEqual(summary["wrapper_seed_count"], 2)
            self.assertEqual(summary["resolved_wrapper_seed_count"], 2)
            self.assertGreater(summary["collapsed_duplicate_source_count"], 0)
            self.assertGreater(summary["source_family_expansion_candidate_count"], 0)

    def test_opencv_dependency_wrapper_is_attributed_to_dependency(self) -> None:
        source = {
            "source_path": "include/opencv2/line_descriptor.hpp",
            "function_name": "~LineSegmentDetector",
            "candidate_role": "method_control",
            "ownership_class": "project_owned_candidate",
            "line_count": 1,
        }
        role, reason = effective_source_role(source)
        self.assertEqual(role, "dependency_control")
        self.assertEqual(reason, "curated_source_provenance_override")
        self.assertEqual(source_analysis_lane(source), "usage")

    def test_unresolved_import_wrapper_cannot_expand_or_support_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "wrapper.c"
            pseudocode.write_text(
                "return BIO_set_flags(a1, a2);\n",
                encoding="utf-8",
            )
            candidate = {
                "candidate_pair_id": "pair-import-wrapper",
                "analysis_lane": "usage",
                "commercial": {
                    "function_id": "commercial-import-wrapper",
                    "library_sha256": "e" * 64,
                    "address": "0x4000",
                },
                "source": {
                    "function_id": "source-bio-set-flags",
                    "repository_full_name": "example/crypto-core",
                    "source_path": "src/bio.c",
                    "function_name": "BIO_set_flags",
                    "candidate_role": "upstream_candidate",
                    "ownership_class": "project_owned_candidate",
                    "line_count": 80,
                    "strings": ["distinctive bio implementation error"],
                },
            }
            candidate_path = root / "review.jsonl"
            candidate_path.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
            source_path = root / "source.jsonl"
            source_path.write_text(json.dumps(candidate["source"]) + "\n", encoding="utf-8")
            output_path = root / "deep.jsonl"
            summary = compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "import-wrapper-hash",
                            "target": {
                                "commercial_function_id": "commercial-import-wrapper",
                                "candidate_pair_id": "pair-import-wrapper",
                                "library_sha256": "e" * 64,
                                "address": "0x4000",
                                "name": ".BIO_set_flags",
                                "selection_source": "pipeline_seed",
                                "reuse_candidate": candidate,
                            },
                            "function_features": {
                                "instruction_count": 4,
                                "basic_block_count": 2,
                                "pseudocode_nonempty_line_count": 1,
                            },
                        }
                    ]
                },
                candidate_path,
                [source_path],
                output_path,
                root / "summary.json",
            )

            rows = [json.loads(line) for line in output_path.read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["analysis_lane"], "control")
            self.assertFalse(
                rows[0]["canonical_resolution"]["comparison_claim_eligible"]
            )
            self.assertEqual(
                rows[0]["relationship_assessment"],
                "insufficient_deep_evidence",
            )
            self.assertEqual(summary["source_family_expansion_candidate_count"], 0)
            self.assertEqual(
                summary["suppressed_unresolved_claim_lane_wrapper_seed_count"],
                1,
            )
            self.assertEqual(summary["unresolved_claim_eligible_wrapper_seed_count"], 0)

    def test_generic_same_name_does_not_expand_source_family(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "process.c"
            pseudocode.write_text("int process(int x) { return x + 1; }", encoding="utf-8")
            candidate = {
                "candidate_pair_id": "pair-generic-seed",
                "analysis_lane": "control",
                "commercial": {
                    "function_id": "commercial-process",
                    "library_sha256": "d" * 64,
                    "address": "0x3000",
                },
                "source": {
                    "function_id": "unrelated-source",
                    "repository_full_name": "example/control",
                    "source_path": "tests/control.cpp",
                    "function_name": "helper",
                    "candidate_role": "method_control",
                    "line_count": 3,
                },
            }
            candidate_path = root / "review.jsonl"
            candidate_path.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
            source_path = root / "source.jsonl"
            source_path.write_text(
                json.dumps(candidate["source"])
                + "\n"
                + json.dumps(
                    {
                        "repository_full_name": "example/generic-project",
                        "source_path": "src/process.cpp",
                        "function_name": "process",
                        "candidate_role": "method_control",
                        "ownership_class": "project_owned_candidate",
                        "line_count": 80,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            summary = compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "generic-hash",
                            "target": {
                                "commercial_function_id": "commercial-process",
                                "candidate_pair_id": "pair-generic-seed",
                                "library_sha256": "d" * 64,
                                "address": "0x3000",
                                "name": "process",
                                "reuse_candidate": candidate,
                            },
                            "function_features": {
                                "instruction_count": 8,
                                "basic_block_count": 2,
                                "pseudocode_nonempty_line_count": 1,
                            },
                        }
                    ]
                },
                candidate_path,
                [source_path],
                root / "deep.jsonl",
                root / "summary.json",
            )
            self.assertEqual(summary["source_family_expansion_candidate_count"], 0)

    def test_post_ida_comparison_resolves_identity_and_requires_deep_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "candidate.c"
            pseudocode.write_text(
                """int candidate(int value) {
                if (value > 4097) { process_edge(value); }
                while (value < 7777) { value += process_edge(value); }
                log_message("rare watershed signature");
                return value;
                }""",
                encoding="utf-8",
            )
            commercial_id = "commercial-1"
            source_id = "source-1"
            candidate = {
                "candidate_pair_id": "pair-1",
                "analysis_lane": "adaptation",
                "retrieval_score": 0.72,
                "commercial": {
                    "function_id": commercial_id,
                    "library_sha256": "a" * 64,
                    "address": "0x1000",
                },
                "source": {
                    "function_id": source_id,
                    "repository_full_name": "example/document-core",
                    "commit_sha": "c" * 40,
                    "source_path": "src/edge.c",
                    "start_line": 10,
                    "function_name": "candidate",
                },
                "source_project": "example/document-core",
            }
            candidate_path = root / "candidates.jsonl"
            candidate_path.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
            source_path = root / "source.jsonl"
            source_path.write_text(
                json.dumps(
                    {
                        **candidate["source"],
                        "body_sha256": "b" * 64,
                        "strings": ["rare watershed signature"],
                        "constants": ["4097", "7777"],
                        "top_calls": [{"name": "process_edge"}],
                        "branch_counts": {"if": 1, "while": 1, "return": 1},
                        "capabilities": ["edge", "document"],
                        "structure_token_count": 35,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output_path = root / "deep.jsonl"
            summary_path = root / "deep-summary.json"
            summary = compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "pseudocode-hash",
                            # Deliberately omit the commercial function id to
                            # exercise the stable library/address fallback.
                            "target": {
                                "library_sha256": "a" * 64,
                                "address": "4096",
                                "name": "candidate",
                                "capabilities": ["document", "edge"],
                                "selection_source": "pipeline_seed",
                            },
                            "function_features": {
                                "pseudocode_nonempty_line_count": 6,
                                "instruction_count": 35,
                                "call_targets": ["process_edge"],
                                "string_refs": ["rare watershed signature"],
                            },
                        }
                    ]
                },
                candidate_path,
                [source_path],
                output_path,
                summary_path,
            )

            rows = [json.loads(line) for line in output_path.read_text().splitlines()]
            self.assertEqual(summary["identity_fallback_resolution_count"], 1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(
                rows[0]["relationship_assessment"],
                "open_source_implementation_match_candidate",
            )
            self.assertIn(
                "control_flow_profile",
                rows[0]["independent_signals"],
            )
            self.assertTrue(rows[0]["claim_eligibility"]["adaptation_review"])
            self.assertFalse(rows[0]["claim_eligibility"]["copying_conclusion"])

    def test_post_ida_usage_accepts_exact_compiled_identity_without_copying_claim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "candidate.c"
            pseudocode.write_text(
                "int helper(int value) { return value + 1; }",
                encoding="utf-8",
            )
            candidate = {
                "candidate_pair_id": "pair-exact",
                "analysis_lane": "usage",
                "retrieval_score": 0.36,
                "components": {
                    "exact_body": 1.0,
                    "exact_structural": 1.0,
                    "instruction": 1.0,
                },
                "commercial": {
                    "function_id": "commercial-exact",
                    "library_sha256": "a" * 64,
                    "address": "0x2000",
                },
                "source": {
                    "function_id": "source-exact",
                    "repository_full_name": "example/upstream",
                    "commit_sha": "d" * 40,
                    "source_path": "src/helper.c",
                    "start_line": 2,
                    "function_name": "helper",
                },
            }
            candidate_path = root / "candidates.jsonl"
            candidate_path.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
            source_path = root / "source.jsonl"
            source_path.write_text(
                json.dumps(
                    {
                        **candidate["source"],
                        "body_sha256": "e" * 64,
                        "structure_token_count": 8,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output_path = root / "deep.jsonl"
            summary_path = root / "deep-summary.json"

            compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "exact-pseudocode",
                            "target": {
                                "commercial_function_id": "commercial-exact",
                                "library_sha256": "a" * 64,
                                "address": "0x2000",
                                "name": "helper",
                                "selection_source": "pipeline_seed",
                            },
                            "function_features": {
                                "pseudocode_nonempty_line_count": 1,
                                "instruction_count": 8,
                            },
                        }
                    ]
                },
                candidate_path,
                [source_path],
                output_path,
                summary_path,
            )

            row = json.loads(output_path.read_text().splitlines()[0])
            self.assertEqual(
                row["relationship_assessment"],
                "open_source_or_external_usage_candidate",
            )
            self.assertIn("exact_compiled_body", row["independent_signals"])
            self.assertTrue(row["claim_eligibility"]["usage_review"])
            self.assertFalse(row["claim_eligibility"]["adaptation_review"])
            self.assertFalse(row["claim_eligibility"]["copying_conclusion"])

    def test_post_ida_seed_identity_cannot_be_overwritten_by_raw_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "selected.c"
            pseudocode.write_text(
                "int selected(int value) { return value + 17; }",
                encoding="utf-8",
            )
            commercial_id = "commercial-selected"
            seed_source = {
                "function_id": "source-selected",
                "repository_full_name": "example/selected-upstream",
                "commit_sha": "a" * 40,
                "source_path": "src/selected.c",
                "start_line": 7,
                "function_name": "selected",
            }
            raw_source = {
                "function_id": "source-raw-control",
                "repository_full_name": "example/unrelated-control",
                "commit_sha": "b" * 40,
                "source_path": "src/control.c",
                "start_line": 11,
                "function_name": "selected",
            }
            raw_candidate = {
                "candidate_pair_id": "pair-raw-control",
                "analysis_lane": "control",
                "selection_score": 1.0,
                "retrieval_score": 1.0,
                "commercial": {
                    "function_id": commercial_id,
                    "library_sha256": "c" * 64,
                    "address": "0x5000",
                },
                "source": raw_source,
            }
            candidate_path = root / "review.jsonl"
            candidate_path.write_text(
                json.dumps(raw_candidate) + "\n",
                encoding="utf-8",
            )
            source_path = root / "source.jsonl"
            indexed_seed_source = {
                key: value
                for key, value in seed_source.items()
                if key != "function_id"
            }
            source_path.write_text(
                json.dumps(
                    {
                        **indexed_seed_source,
                        "instruction_count": 8,
                        "branch_counts": {"if": 3, "return": 1},
                    }
                )
                + "\n"
                + json.dumps({**raw_source, "instruction_count": 8})
                + "\n",
                encoding="utf-8",
            )
            output_path = root / "deep.jsonl"
            summary_path = root / "deep-summary.json"
            summary = compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "selected-pseudocode",
                            "target": {
                                "commercial_function_id": commercial_id,
                                "candidate_pair_id": "pair-selected",
                                "analysis_lane": "usage",
                                "library": "libselected.so",
                                "library_sha256": "c" * 64,
                                "abi": "arm64-v8a",
                                "address": "0x5000",
                                "name": "selected",
                                "ownership": {"category": "first_party"},
                                "selection_source": "pipeline_seed",
                                "reuse_candidate": {
                                    "candidate_pair_id": "pair-selected",
                                    "commercial_function_id": commercial_id,
                                    "source_function_id": "source-selected",
                                    "analysis_lane": "usage",
                                    "retrieval_score": 0.5,
                                    "components": {"exact_body": 1.0},
                                    "source": seed_source,
                                    "source_project": "example/selected-upstream",
                                },
                            },
                            "function_features": {
                                "pseudocode_nonempty_line_count": 1,
                                "instruction_count": 8,
                            },
                        }
                    ]
                },
                candidate_path,
                [source_path],
                output_path,
                summary_path,
            )

            rows = [json.loads(line) for line in output_path.read_text().splitlines()]
            selected = next(row for row in rows if row["candidate_pair_id"] == "pair-selected")
            self.assertEqual(selected["analysis_lane"], "usage")
            self.assertEqual(selected["candidate_origin"], "selected_ida_seed")
            self.assertEqual(
                selected["relationship_assessment"],
                "open_source_or_external_usage_candidate",
            )
            self.assertEqual(summary["metadata_integrity_status"], "passed")
            self.assertEqual(summary["selected_seed_lane_counts"], {"usage": 1})
            self.assertEqual(summary["compared_seed_lane_counts"], {"usage": 1})
            self.assertEqual(summary["null_candidate_pair_id_count"], 0)
            self.assertEqual(selected["deep_components"]["source_structure_size"], 8)

    def test_post_ida_semantic_only_match_is_not_claim_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "generic.c"
            pseudocode.write_text(
                "int process_document(int value) { return value; }",
                encoding="utf-8",
            )
            source = {
                "function_id": "source-generic",
                "repository_full_name": "example/generic",
                "commit_sha": "d" * 40,
                "source_path": "src/document.c",
                "start_line": 1,
                "function_name": "process_document",
                "capabilities": ["document"],
                "structure_token_count": 8,
            }
            candidate = {
                "candidate_pair_id": "pair-generic",
                "analysis_lane": "adaptation",
                "retrieval_score": 0.99,
                "commercial": {
                    "function_id": "commercial-generic",
                    "library": "libgeneric.so",
                    "library_sha256": "e" * 64,
                    "address": "0x6000",
                    "ownership": {"category": "first_party"},
                },
                "source": source,
                "source_project": "example/generic",
            }
            candidate_path = root / "review.jsonl"
            candidate_path.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
            source_path = root / "source.jsonl"
            source_path.write_text(json.dumps(source) + "\n", encoding="utf-8")
            output_path = root / "deep.jsonl"
            summary_path = root / "deep-summary.json"
            compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "generic-pseudocode",
                            "target": {
                                "commercial_function_id": "commercial-generic",
                                "library": "libgeneric.so",
                                "library_sha256": "e" * 64,
                                "address": "0x6000",
                                "name": "process_document",
                                "capabilities": ["document"],
                                "ownership": {"category": "first_party"},
                            },
                            "function_features": {
                                "pseudocode_nonempty_line_count": 1,
                                "instruction_count": 8,
                            },
                        }
                    ]
                },
                candidate_path,
                [source_path],
                output_path,
                summary_path,
            )
            row = json.loads(output_path.read_text().splitlines()[0])
            self.assertEqual(
                row["relationship_assessment"],
                "insufficient_deep_evidence",
            )
            self.assertFalse(row["claim_eligibility"]["adaptation_review"])
            self.assertIn(
                "insufficient_comparable_evidence_weight",
                row["review_gate"]["reasons"],
            )

    def test_post_ida_usage_accepts_one_independent_and_one_supporting_signal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "usage.c"
            pseudocode.write_text(
                """int document_line_detect(int value) {
                if (value > 42) { return document_line_detect(value - 1); }
                return value;
                }""",
                encoding="utf-8",
            )
            source = {
                "function_id": "source-usage",
                "repository_full_name": "example/line-detector",
                "commit_sha": "f" * 40,
                "source_path": "src/lines.cpp",
                "start_line": 10,
                "function_name": "document_line_detect",
                "top_calls": [{"name": "document_line_detect"}],
                "branch_counts": {"if": 1, "return": 2},
                "structure_token_count": 8,
            }
            candidate = {
                "candidate_pair_id": "pair-usage-signals",
                "analysis_lane": "usage",
                "retrieval_score": 0.8,
                "commercial": {
                    "function_id": "commercial-usage-signals",
                    "library_sha256": "1" * 64,
                    "address": "0x7000",
                },
                "source": source,
                "source_project": "example/line-detector",
            }
            candidate_path = root / "review.jsonl"
            candidate_path.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
            source_path = root / "source.jsonl"
            source_path.write_text(json.dumps(source) + "\n", encoding="utf-8")
            output_path = root / "deep.jsonl"
            compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "usage-pseudocode",
                            "target": {
                                "commercial_function_id": "commercial-usage-signals",
                                "library_sha256": "1" * 64,
                                "address": "0x7000",
                                "name": "document_line_detect",
                            },
                            "function_features": {
                                "pseudocode_nonempty_line_count": 5,
                                "instruction_count": 8,
                                "call_targets": ["document_line_detect"],
                            },
                        }
                    ]
                },
                candidate_path,
                [source_path],
                output_path,
                root / "summary.json",
            )
            row = json.loads(output_path.read_text().splitlines()[0])
            self.assertEqual(
                row["relationship_assessment"],
                "open_source_or_external_usage_candidate",
            )
            self.assertTrue(row["claim_eligibility"]["usage_review"])
            self.assertIn("call_pattern", row["independent_signals"])
            self.assertIn("semantic_operation", row["independent_signals"])

    def test_post_ida_collapses_multi_abi_source_builds_into_one_family(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pseudocode = root / "candidate.c"
            pseudocode.write_text(
                "int edge(int value) { return value > 12 ? value : 12; }",
                encoding="utf-8",
            )
            candidate_rows = []
            source_rows = []
            for abi, source_id in (("arm64-v8a", "source-arm64"), ("x86_64", "source-x64")):
                source = {
                    "function_id": source_id,
                    "repository_full_name": "example/edge-core",
                    "commit_sha": "f" * 40,
                    "source_path": "src/edge.c",
                    "start_line": 4,
                    "function_name": "edge",
                    "representation": "oss_compiled_binary_function",
                    "build_variant": "O2",
                    "abi": abi,
                }
                candidate_rows.append(
                    {
                        "candidate_pair_id": f"pair-{abi}",
                        "analysis_lane": "usage",
                        "retrieval_score": 0.5,
                        "components": {"exact_structural": 1.0},
                        "commercial": {
                            "function_id": "commercial-family",
                            "library_sha256": "a" * 64,
                            "address": "0x3000",
                        },
                        "source": source,
                        "source_project": "example/edge-core",
                    }
                )
                source_rows.append({**source, "instruction_count": 8})
            candidate_path = root / "candidates.jsonl"
            candidate_path.write_text(
                "".join(json.dumps(row) + "\n" for row in candidate_rows),
                encoding="utf-8",
            )
            source_path = root / "source.jsonl"
            source_path.write_text(
                "".join(json.dumps(row) + "\n" for row in source_rows),
                encoding="utf-8",
            )
            output_path = root / "deep.jsonl"
            summary_path = root / "deep-summary.json"

            summary = compare_decompiled_candidates(
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "family-pseudocode",
                            "target": {
                                "commercial_function_id": "commercial-family",
                                "library_sha256": "a" * 64,
                                "address": "0x3000",
                                "name": "edge",
                                "selection_source": "pipeline_seed",
                            },
                            "function_features": {
                                "pseudocode_nonempty_line_count": 1,
                                "instruction_count": 8,
                            },
                        }
                    ]
                },
                candidate_path,
                [source_path],
                output_path,
                summary_path,
            )

            rows = [json.loads(line) for line in output_path.read_text().splitlines()]
            self.assertEqual(summary["comparison_pair_count"], 2)
            self.assertEqual(summary["source_family_comparison_count"], 1)
            self.assertEqual(summary["collapsed_duplicate_source_count"], 1)
            self.assertEqual(rows[0]["source_family_member_count"], 2)
            self.assertEqual(
                {row["abi"] for row in rows[0]["source_family_variants"]},
                {"arm64-v8a", "x86_64"},
            )

    def test_primary_native_projection_keeps_one_abi_per_logical_library(self) -> None:
        selected, summary = _primary_native_projection(
            [
                {
                    "name": "libdocument.so",
                    "abi": "arm64-v8a",
                    "sha256": "a" * 64,
                },
                {
                    "name": "libdocument.so",
                    "abi": "x86_64",
                    "sha256": "b" * 64,
                },
                {
                    "name": "libscanner.so",
                    "abi": "x86_64",
                    "sha256": "c" * 64,
                },
            ]
        )

        self.assertEqual(selected, {"a" * 64, "c" * 64})
        self.assertEqual(summary["logical_library_count"], 2)
        self.assertEqual(summary["selected_library_hash_count"], 2)
        self.assertEqual(summary["excluded_abi_counts"], {"x86_64": 1})

    def test_phase5_prefers_global_review_set_over_full_stream_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            native_dir = workspace / "phase3_native"
            native_dir.mkdir(parents=True)
            full_candidate = {
                "retrieval_score": 0.31,
                "commercial": {"function_id": "early-low"},
                "source": {"function_id": "oss-low"},
            }
            review_candidate = {
                "retrieval_score": 0.91,
                "commercial": {"function_id": "global-high"},
                "source": {"function_id": "oss-high"},
            }
            (native_dir / "reuse_candidates.jsonl").write_text(
                json.dumps(full_candidate) + "\n",
                encoding="utf-8",
            )
            (native_dir / "reuse_candidates_review.jsonl").write_text(
                json.dumps(review_candidate) + "\n",
                encoding="utf-8",
            )

            units = _collect_evidence_units(workspace)

            reuse_units = [
                row
                for row in units
                if row.get("kind") == "open_source_retrieval_candidate"
            ]
            self.assertEqual(len(reuse_units), 1)
            self.assertEqual(
                reuse_units[0]["commercial_function"]["function_id"],
                "global-high",
            )

    def test_phase5_preserves_candidate_lane_and_claim_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            native_dir = workspace / "phase3_native"
            native_dir.mkdir(parents=True)
            candidate = {
                "retrieval_score": 0.84,
                "selection_score": 0.72,
                "analysis_lane": "usage",
                "analysis_semantics": "dependency usage evidence",
                "candidate_deep_comparison_eligible": True,
                "selection_evidence": {"signal_count": 2},
                "commercial": {
                    "function_id": "commercial-native",
                    "representation": "ida_lightweight_inventory",
                    "ownership": {"category": "first_party"},
                },
                "source": {
                    "function_id": "oss-native",
                    "ownership_class": "vendored_or_external",
                },
            }
            (native_dir / "reuse_candidates_review.jsonl").write_text(
                json.dumps(candidate) + "\n",
                encoding="utf-8",
            )

            unit = next(
                row
                for row in _collect_evidence_units(workspace)
                if row.get("kind") == "open_source_retrieval_candidate"
            )

            self.assertEqual(unit["analysis_lane"], "usage")
            self.assertTrue(unit["claim_eligibility"]["usage_review"])
            self.assertFalse(unit["claim_eligibility"]["adaptation_review"])
            self.assertFalse(unit["claim_eligibility"]["copying_conclusion"])
            self.assertFalse(unit["comparison_eligible"])

    def test_stratified_selection_prevents_java_from_starving_native(self) -> None:
        rows = []
        for index in range(100):
            rows.append(
                {
                    "retrieval_score": 0.99 - index / 1000,
                    "source_project": f"managed/project-{index % 3}",
                    "components": {"semantic": 0.9, "calls": 0.7},
                    "evidence_sufficiency": {
                        "deep_comparison_eligible": True
                    },
                    "commercial": {
                        "function_id": f"managed-{index}",
                        "representation": "jadx_source_method",
                        "name": f"renderPage{index}",
                    },
                    "source": {
                        "function_id": f"oss-managed-{index}",
                        "candidate_role": "upstream_candidate",
                        "ownership_class": "project_owned_candidate",
                    },
                }
            )
        for index in range(6):
            rows.append(
                {
                    "retrieval_score": 0.70 - index / 100,
                    "source_project": f"native/project-{index % 2}",
                    "components": {"semantic": 0.8, "calls": 0.6},
                    "evidence_sufficiency": {
                        "deep_comparison_eligible": True
                    },
                    "commercial": {
                        "function_id": f"native-{index}",
                        "representation": "ida_lightweight_inventory",
                        "name": f"detectDocument{index}",
                        "library": f"/tmp/libscan{index % 2}.so",
                        "library_sha256": str(index + 1) * 64,
                        "address": hex(0x1000 + index * 16),
                        "ownership": {"category": "first_party"},
                    },
                    "source": {
                        "function_id": f"oss-native-{index}",
                        "candidate_role": "upstream_candidate",
                        "ownership_class": "project_owned_candidate",
                    },
                }
            )

        summary, review, native_pool = select_candidate_cohorts(
            rows,
            review_limit=20,
            native_decompile_limit=6,
        )
        targets = native_decompile_targets(native_pool, limit=6)

        self.assertGreater(
            sum(row["representation_group"] == "native" for row in review),
            0,
        )
        self.assertEqual(summary["native_deep_eligible_count"], 6)
        self.assertEqual(len(targets), 6)
        self.assertTrue(all(row["analysis_lane"] == "adaptation" for row in targets))

    def test_vendored_source_is_usage_not_proprietary_adaptation(self) -> None:
        row = {
            "retrieval_score": 0.92,
            "source_project": "example/zlib",
            "components": {"semantic": 0.8, "calls": 0.5},
            "evidence_sufficiency": {"deep_comparison_eligible": True},
            "commercial": {
                "function_id": "commercial-zlib",
                "representation": "ida_lightweight_inventory",
                "name": "inflate_fast",
                "library": "/tmp/libdocument.so",
                "library_sha256": "a" * 64,
                "address": "0x1000",
                "ownership": {"category": "first_party"},
            },
            "source": {
                "function_id": "oss-zlib",
                "candidate_role": "upstream_candidate",
                "ownership_class": "vendored_or_external",
            },
        }

        annotated = annotate_candidate_for_selection(row)
        targets = native_decompile_targets([annotated], limit=1)

        self.assertEqual(annotated["analysis_lane"], "usage")
        self.assertEqual(targets[0]["analysis_lane"], "usage")
        self.assertEqual(
            targets[0]["reuse_candidate"]["source"]["ownership_class"],
            "vendored_or_external",
        )

    def test_managed_generic_method_is_excluded_before_deep_budgeting(self) -> None:
        row = {
            "retrieval_score": 0.84,
            "components": {"semantic": 0.8, "calls": 0.5},
            "evidence_sufficiency": {"deep_comparison_eligible": True},
            "commercial": {
                "function_id": "commercial-hash",
                "representation": "dex_bytecode_method",
                "name": "hashCode",
                "file": "sources/com/example/Rect.java",
                "ownership": {"category": "first_party"},
            },
            "source": {
                "function_id": "oss-hash",
                "repository_full_name": "example/geometry",
                "candidate_role": "upstream_candidate",
                "ownership_class": "project_owned_candidate",
            },
        }

        annotated = annotate_candidate_for_selection(row)

        self.assertFalse(annotated["candidate_deep_comparison_eligible"])
        self.assertEqual(
            annotated["selection_evidence"]["deep_comparison_exclusion_reason"],
            "managed_low_information_generic_method",
        )

    def test_managed_domain_method_with_structural_context_remains_eligible(self) -> None:
        row = {
            "retrieval_score": 0.84,
            "components": {
                "semantic": 0.8,
                "source_shingles": 0.62,
                "calls": 0.68,
                "strings": 0.52,
            },
            "evidence_sufficiency": {"deep_comparison_eligible": True},
            "commercial": {
                "function_id": "commercial-detect-page",
                "representation": "dex_bytecode_method",
                "name": "detectDocumentCorners",
                "file": "sources/com/example/Detector.java",
                "ownership": {"category": "first_party"},
            },
            "source": {
                "function_id": "oss-detect-page",
                "repository_full_name": "example/document-detector",
                "candidate_role": "upstream_candidate",
                "ownership_class": "project_owned_candidate",
            },
        }

        annotated = annotate_candidate_for_selection(row)

        self.assertTrue(annotated["candidate_deep_comparison_eligible"])
        self.assertIsNone(
            annotated["selection_evidence"]["deep_comparison_exclusion_reason"]
        )

    def test_retrieval_resumes_from_checkpoint_and_reuses_completed_output(self) -> None:
        source_rows = [
            {
                "function_id": "oss-a",
                "representation": "source_code_function",
                "corpus_id": "project-a",
                "repository_full_name": "example/project-a",
                "source_path": "src/a.c",
                "start_line": 1,
                "function_name": "detectPageA",
                "body_sha256": "a" * 64,
                "structural_sha256": "1" * 64,
                "line_count": 30,
            },
            {
                "function_id": "oss-b",
                "representation": "source_code_function",
                "corpus_id": "project-b",
                "repository_full_name": "example/project-b",
                "source_path": "src/b.c",
                "start_line": 1,
                "function_name": "detectPageB",
                "body_sha256": "b" * 64,
                "structural_sha256": "2" * 64,
                "line_count": 30,
            },
        ]
        commercial_rows = [
            {
                "function_id": "commercial-a",
                "representation": "jadx_source_method",
                "function_name": "detectPageA",
                "ownership": {"category": "first_party"},
                "body_sha256": "a" * 64,
                "structural_sha256": "1" * 64,
                "line_count": 30,
            },
            {
                "function_id": "commercial-b",
                "representation": "jadx_source_method",
                "function_name": "detectPageB",
                "ownership": {"category": "first_party"},
                "body_sha256": "b" * 64,
                "structural_sha256": "2" * 64,
                "line_count": 30,
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "candidates.jsonl"
            summary_path = root / "summary.json"
            checkpoint = root / "checkpoint.json"

            def interrupted_rows():
                yield commercial_rows[0]
                raise KeyboardInterrupt

            with self.assertRaises(KeyboardInterrupt):
                retrieve_candidates(
                    interrupted_rows(),
                    source_rows,
                    minimum_score=0,
                    top_k=1,
                    output_path=output,
                    summary_path=summary_path,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                    resume_key="resume-test",
                )
            self.assertTrue(checkpoint.is_file())
            self.assertTrue(output.with_suffix(".jsonl.part").is_file())
            interrupted_summary = json.loads(
                summary_path.read_text(encoding="utf-8")
            )
            self.assertEqual(interrupted_summary["status"], "interrupted")

            summary, candidates = retrieve_candidates(
                commercial_rows,
                source_rows,
                minimum_score=0,
                top_k=1,
                output_path=output,
                summary_path=summary_path,
                checkpoint_path=checkpoint,
                checkpoint_interval=1,
                resume_key="resume-test",
            )
            self.assertEqual(summary["status"], "completed")
            self.assertEqual(summary["cache_status"], "resumed")
            self.assertEqual(summary["commercial_function_count"], 2)
            self.assertEqual(summary["candidate_pair_count"], 2)
            self.assertEqual(len(candidates), 2)
            self.assertFalse(checkpoint.exists())
            self.assertEqual(len(output.read_text().splitlines()), 2)

            def must_not_iterate():
                raise AssertionError("completed retrieval must be reused")
                yield {}

            cached_summary, cached_candidates = retrieve_candidates(
                must_not_iterate(),
                source_rows,
                minimum_score=0,
                top_k=1,
                output_path=output,
                summary_path=summary_path,
                checkpoint_path=checkpoint,
                resume_key="resume-test",
            )
            self.assertEqual(cached_summary["cache_status"], "reused")
            self.assertEqual(len(cached_candidates), 2)

    def test_dex_entries_are_sorted_without_comparing_zipinfo_objects(self) -> None:
        entries = [
            zipfile.ZipInfo("classes3.dex"),
            zipfile.ZipInfo("assets/ignored.txt"),
            zipfile.ZipInfo("classes.dex"),
            zipfile.ZipInfo("classes2.dex"),
        ]
        entries[0].header_offset = 300
        entries[2].header_offset = 100
        entries[3].header_offset = 200

        ordered = _sorted_dex_entries(entries)

        self.assertEqual(
            [entry.filename for entry in ordered],
            ["classes.dex", "classes2.dex", "classes3.dex"],
        )

    def test_adaptive_library_selection_preserves_coverage_and_uses_budget(self) -> None:
        targets = [
            {
                "library": "/tmp/liba.so",
                "address": f"0x{index:X}",
                "name": f"a_{index}",
                "score": 100 - index,
            }
            for index in range(8)
        ]
        targets.extend(
            [
                {
                    "library": "/tmp/libb.so",
                    "address": "0x2000",
                    "name": "b_0",
                    "score": 70,
                },
                {
                    "library": "/tmp/libc.so",
                    "address": "0x3000",
                    "name": "c_0",
                    "score": 60,
                },
            ]
        )

        selected, counts = _adaptive_library_target_selection(
            targets,
            max_targets=6,
            max_libraries=3,
        )

        self.assertEqual(len(selected), 6)
        self.assertEqual(set(counts), {"/tmp/liba.so", "/tmp/libb.so", "/tmp/libc.so"})
        self.assertEqual(counts["/tmp/liba.so"], 4)
        self.assertEqual(counts["/tmp/libb.so"], 1)
        self.assertEqual(counts["/tmp/libc.so"], 1)

    def test_fingerprint_is_deterministic_and_representation_explicit(self) -> None:
        first = build_fingerprint(
            function_id=stable_id("libcore", "0x1000"),
            representation="ida_lightweight_inventory",
            name="runDocumentDewarping",
            capabilities=["scan_image"],
            call_targets=["findLineSegments", "estimateHomography"],
            strings=["invalid region image"],
            branch_counts={"conditional": 3},
            cfg_counts={"basic_blocks": 5, "edges": 7},
            size_measure=84,
            instruction_tokens=["load", "compare", "branch", "call", "return"],
        )
        second = build_fingerprint(
            function_id=stable_id("libcore", "0x1000"),
            representation="ida_lightweight_inventory",
            name="runDocumentDewarping",
            capabilities=["scan_image"],
            call_targets=["findLineSegments", "estimateHomography"],
            strings=["invalid region image"],
            branch_counts={"conditional": 3},
            cfg_counts={"basic_blocks": 5, "edges": 7},
            size_measure=84,
            instruction_tokens=["load", "compare", "branch", "call", "return"],
        )
        self.assertEqual(first, second)
        self.assertEqual(first["representation"], "ida_lightweight_inventory")
        self.assertEqual(first["cfg_counts"], {"basic_blocks": 5, "edges": 7})
        self.assertGreater(
            first["instruction_signature"]["retained_hash_count"], 0
        )
        self.assertEqual(
            bottom_k_token_signature(["a", "b", "c", "d"]),
            bottom_k_token_signature(["a", "b", "c", "d"]),
        )

    def test_retrieval_backfills_stable_identity_for_legacy_source_rows(self) -> None:
        commercial = {
            "representation": "source_code_function",
            "function_name": "detectDocumentEdges",
            "ownership": {"category": "first_party"},
            "body_sha256": "a" * 64,
            "structural_sha256": "b" * 64,
            "branch_counts": {"if": 2},
            "line_count": 20,
        }
        legacy_source = {
            "corpus_id": "OSS006",
            "repository_full_name": "example/edge-library",
            "commit_sha": "c" * 40,
            "source_path": "src/edge.cpp",
            "start_line": 10,
            "end_line": 29,
            "function_name": "detectDocumentEdges",
            "candidate_role": "upstream_candidate",
            "body_sha256": "a" * 64,
            "structural_sha256": "b" * 64,
            "branch_counts": {"if": 2},
            "line_count": 20,
        }

        summary, candidates = retrieve_candidates(
            [commercial],
            [legacy_source],
            minimum_score=0.0,
        )

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertTrue(candidate["commercial"]["function_id"])
        self.assertEqual(candidate["commercial"]["name"], "detectDocumentEdges")
        self.assertTrue(candidate["source"]["function_id"])
        self.assertEqual(
            candidate["source"]["representation"],
            "source_code_function",
        )

    def test_native_inventory_consolidation_keeps_identity_and_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            inventory = root / "inventory.jsonl"
            inventory.write_text(
                json.dumps(
                    {
                        "function_id": "native-1",
                        "representation": "ida_lightweight_inventory",
                        "address": "0x1000",
                        "name": "runLocalOcr",
                        "library_sha256": "a" * 64,
                        "ownership": {"category": "first_party"},
                        "call_targets": ["recognizeText"],
                        "string_refs": ["ocr model"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / "full.jsonl"
            callgraph = root / "callgraph.jsonl"

            summary = _consolidate_native_inventory(
                {
                    "status": "completed",
                    "input_library_count": 1,
                    "unique_library_count": 1,
                    "completed_library_count": 1,
                    "library_summaries": [
                        {"inventory_path": str(inventory)}
                    ],
                },
                output,
                callgraph,
            )

            rows = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(summary["status"], "completed")
            self.assertEqual(summary["indexed_function_count"], 1)
            self.assertEqual(summary["indexed_library_hash_count"], 1)
            self.assertEqual(rows[0]["function_id"], "native-1")
            edges = [json.loads(line) for line in callgraph.read_text().splitlines()]
            self.assertEqual(summary["callgraph_edge_count"], 1)
            self.assertEqual(edges[0]["callee_name"], "recognizeText")
            self.assertIn("ocr", rows[0]["capabilities"])
            self.assertIn("without requiring Hex-Rays", rows[0]["coverage_note"])

    def test_java_and_kotlin_methods_are_indexed_with_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            java_path = root / "com" / "example" / "PageDetector.java"
            kotlin_path = root / "com" / "example" / "Enhancer.kt"
            java_path.parent.mkdir(parents=True)
            java_path.write_text(
                """
                package com.example;
                public class PageDetector {
                    public int detectPage(String image) {
                        if (image == null) { return -1; }
                        return estimateHomography(findLineSegments(image));
                    }
                    private int estimateHomography(int lines) {
                        return lines > 4 ? lines : 0;
                    }
                }
                """,
                encoding="utf-8",
            )
            kotlin_path.write_text(
                """
                package com.example
                class Enhancer {
                    fun removeShadow(input: String): String {
                        return normalizeIllumination(input)
                    }
                }
                """,
                encoding="utf-8",
            )
            ownership = {"category": "first_party", "confidence": 0.9}
            code_index = {
                "files": [
                    {
                        "file": "com/example/PageDetector.java",
                        "package": "com.example",
                        "ownership": ownership,
                    },
                    {
                        "file": "com/example/Enhancer.kt",
                        "package": "com.example",
                        "ownership": ownership,
                    },
                ]
            }
            summary, rows = build_jadx_method_index(root, code_index)
            names = {row["function_name"] for row in rows}
            self.assertEqual(summary["status"], "completed")
            self.assertEqual(summary["indexed_method_count"], 3)
            self.assertEqual(
                names,
                {"detectPage", "estimateHomography", "removeShadow"},
            )
            self.assertTrue(
                all((row.get("ownership") or {}).get("category") == "first_party" for row in rows)
            )

    def test_retrieval_ranks_known_positive_and_ignores_unrelated_source(self) -> None:
        commercial = [
            {
                "function_id": "commercial-dewarp",
                "representation": "ida_lightweight_inventory",
                "name": "runDocumentDewarping",
                "library": "/tmp/libscan.so",
                "library_sha256": "a" * 64,
                "abi": "arm64-v8a",
                "address": "0x1000",
                "ownership": {"category": "first_party"},
                "semantic_tokens": ["document", "dewarp", "line", "segment"],
                "call_tokens": ["line", "segment", "homography", "region"],
                "string_tokens": ["invalid", "region", "image"],
                "capabilities": ["scan_image"],
                "branch_counts": {"if": 4, "return": 2},
                "size_measure": 90,
            }
        ]
        known_positive = {
            "corpus_id": "ipol-lsd",
            "repository_full_name": "example/lsd",
            "source_path": "src/lsd.c",
            "start_line": 100,
            "end_line": 220,
            "function_name": "line_segment_region",
            "candidate_role": "upstream_candidate",
            "capabilities": ["scan_image"],
            "top_calls": [
                {"name": "estimate_homography", "count": 1},
                {"name": "region_grow", "count": 2},
            ],
            "strings": ["invalid region image"],
            "branch_counts": {"if": 5, "return": 2},
            "structure_token_count": 100,
        }
        unrelated = {
            "corpus_id": "audio-codec",
            "repository_full_name": "example/audio",
            "source_path": "src/codec.c",
            "start_line": 1,
            "function_name": "decode_audio_packet",
            "candidate_role": "upstream_candidate",
            "capabilities": ["audio_voice"],
            "top_calls": [{"name": "read_pcm", "count": 1}],
            "strings": ["sample rate"],
            "branch_counts": {"if": 2},
            "structure_token_count": 95,
        }
        summary, candidates = retrieve_candidates(
            commercial,
            [unrelated, known_positive],
            top_k=5,
            minimum_score=0.2,
        )
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            (candidates[0].get("source") or {}).get("corpus_id"),
            "ipol-lsd",
        )
        self.assertIn("not a copying probability", candidates[0]["score_interpretation"])
        self.assertNotIn("branches", candidates[0]["weighted_channels"])
        self.assertNotIn("size", candidates[0]["weighted_channels"])
        targets = native_decompile_targets(candidates, limit=10)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["kind"], "reuse_candidate")

    def test_trivial_exact_match_is_retained_but_does_not_consume_deep_budget(self) -> None:
        source = {
            "corpus_id": "OSS001",
            "repository_full_name": "example/scanner",
            "candidate_role": "upstream_candidate",
            "function_name": "getCount",
            "source_path": "Adapter.kt",
            "start_line": 10,
            "line_count": 3,
            "structure_token_count": 3,
            "body_sha256": "a" * 64,
            "structural_sha256": "b" * 64,
            "branch_counts": {"return": 1},
            "top_calls": [{"name": "getCount", "count": 1}],
            "strings": [],
            "capabilities": [],
        }
        commercial = {
            **source,
            "function_id": "commercial-short",
            "representation": "jadx_source_method",
            "name": "getCount",
            "size_measure": 3,
            "semantic_tokens": ["get", "count"],
            "call_tokens": ["get", "count"],
            "ownership": {"category": "first_party"},
        }
        summary, candidates = retrieve_candidates(
            [commercial],
            [source],
            top_k=1,
            minimum_score=0.1,
        )
        self.assertEqual(len(candidates), 1)
        sufficiency = candidates[0]["evidence_sufficiency"]
        self.assertEqual(sufficiency["level"], "low")
        self.assertFalse(sufficiency["deep_comparison_eligible"])
        self.assertEqual(summary["evidence_sufficiency_counts"], {"low": 1})
        self.assertEqual(summary["deep_comparison_eligible_candidate_count"], 0)

        low_native = {
            **candidates[0],
            "commercial": {
                **candidates[0]["commercial"],
                "representation": "ida_lightweight_inventory",
                "library": "/tmp/libscanner.so",
                "library_sha256": "c" * 64,
                "address": "0x1000",
            },
        }
        self.assertEqual(native_decompile_targets([low_native], limit=10), [])

        build_summary, build_rows = build_oss_build_queue(
            candidates,
            [],
            snapshot_root=Path("/tmp/not-used"),
            limit=1,
        )
        self.assertEqual(build_rows, [])
        self.assertEqual(
            build_summary["skipped_low_information_candidate_count"],
            1,
        )

    def test_source_structure_channels_are_used_only_for_source_methods(self) -> None:
        commercial = [
            {
                "function_id": "java-method",
                "representation": "jadx_source_method",
                "name": "detectPage",
                "semantic_tokens": ["detect", "page"],
                "call_tokens": ["find", "contours"],
                "branch_counts": {"if": 2, "return": 1},
                "size_measure": 20,
            }
        ]
        source = [
            {
                "corpus_id": "scanner",
                "repository_full_name": "example/scanner",
                "source_path": "src/page.cpp",
                "start_line": 5,
                "function_name": "detect_page",
                "candidate_role": "upstream_candidate",
                "top_calls": [{"name": "findContours", "count": 1}],
                "branch_counts": {"if": 2, "return": 1},
                "structure_token_count": 18,
            }
        ]

        _summary, candidates = retrieve_candidates(
            commercial,
            source,
            top_k=2,
            minimum_score=0.1,
        )

        self.assertEqual(len(candidates), 1)
        self.assertIn("branches", candidates[0]["weighted_channels"])
        self.assertIn("size", candidates[0]["weighted_channels"])

    def test_dex_opcode_channels_require_compiled_dex_on_both_sides(self) -> None:
        commercial = build_dex_method_row(
            apk_path=Path("commercial.apk"),
            apk_sha256="a" * 64,
            dex_entry="classes.dex",
            class_descriptor="Lcom/example/PageDetector;",
            method_name="detectPage",
            method_descriptor="(Ljava/lang/String;)I",
            access_flags="public",
            opcodes=["const-string", "invoke-static", "if-eqz", "return"],
            instruction_outputs=[
                'v0, "invalid region image"',
                "{}, Lcom/example/Lines;->detect()I",
                "v0, +004h",
                "v0",
            ],
            app_package="com.example",
        )
        compiled_source = {
            **commercial,
            "function_id": "oss-dex-method",
            "representation": "oss_compiled_dex_method",
            "corpus_id": "OSS001",
            "repository_full_name": "example/scanner",
            "commit_sha": "b" * 40,
            "candidate_role": "upstream_candidate",
        }
        _summary, candidates = retrieve_candidates(
            [commercial],
            [compiled_source],
            minimum_score=0.1,
        )
        self.assertEqual(len(candidates), 1)
        self.assertIn("instruction", candidates[0]["weighted_channels"])
        self.assertIn("cfg", candidates[0]["weighted_channels"])
        self.assertTrue(
            candidates[0]["representation_compatibility"]["dex"]
        )
        self.assertGreater(
            len(candidates[0]["matched_fingerprints"]["instruction_hashes"]),
            0,
        )

    def test_oss_binary_index_preserves_build_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            inventory = root / "inventory.jsonl"
            inventory.write_text(
                json.dumps(
                    {
                        "function_id": "ida-original",
                        "representation": "ida_lightweight_inventory",
                        "address": "0x1000",
                        "name": "detectPage",
                        "library_sha256": "c" * 64,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / "oss.jsonl"
            summary = materialize_oss_binary_index(
                {
                    "status": "completed",
                    "library_summaries": [
                        {
                            "library_sha256": "c" * 64,
                            "inventory_path": str(inventory),
                        }
                    ],
                },
                [
                    {
                        "sha256": "c" * 64,
                        "repository_full_name": "example/scanner",
                        "commit_sha": "d" * 40,
                        "build_variant": "arm64-v8a-O2",
                        "build_recipe_id": "recipe-1",
                    }
                ],
                output,
            )
            row = json.loads(output.read_text().strip())
            self.assertEqual(summary["status"], "completed")
            self.assertEqual(row["representation"], "oss_compiled_binary_function")
            self.assertEqual(row["commit_sha"], "d" * 40)
            self.assertEqual(row["build_variant"], "arm64-v8a-O2")

    def test_oss_binary_index_preserves_multiple_sources_for_same_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            inventory = root / "inventory.jsonl"
            inventory.write_text(
                json.dumps(
                    {
                        "address": "0x1000",
                        "name": "detectPage",
                        "library_sha256": "c" * 64,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / "oss.jsonl"
            summary = materialize_oss_binary_index(
                {
                    "status": "completed",
                    "library_summaries": [
                        {
                            "library_sha256": "c" * 64,
                            "inventory_path": str(inventory),
                        }
                    ],
                },
                [
                    {
                        "sha256": "c" * 64,
                        "repository_full_name": "example/one",
                        "commit_sha": "d" * 40,
                        "build_variant": "arm64-v8a-O2",
                    },
                    {
                        "sha256": "c" * 64,
                        "repository_full_name": "example/two",
                        "commit_sha": "e" * 40,
                        "build_variant": "arm64-v8a-O2",
                    },
                ],
                output,
            )
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(summary["manifest_binary_count"], 2)
            self.assertEqual(summary["unique_binary_hash_count"], 1)
            self.assertEqual(len(rows), 2)
            self.assertEqual(
                {row["repository_full_name"] for row in rows},
                {"example/one", "example/two"},
            )
            self.assertEqual(len({row["function_id"] for row in rows}), 2)

    def test_extracts_native_artifacts_from_compiled_oss_apk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "candidate.apk"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("classes.dex", b"dex\n035\x00")
                output.writestr("lib/arm64-v8a/libscanner.so", b"ELF scanner")
                output.writestr("assets/not-a-library.so", b"ignored")
            rows = extract_apk_native_artifacts(
                [
                    {
                        "binary_path": str(archive),
                        "repository_full_name": "example/scanner",
                        "commit_sha": "f" * 40,
                        "build_variant": "arm64-v8a-O2",
                    }
                ],
                root / "native",
            )
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["abi"], "arm64-v8a")
            self.assertEqual(
                rows[0]["source_archive_entry"],
                "lib/arm64-v8a/libscanner.so",
            )
            self.assertEqual(Path(rows[0]["binary_path"]).read_bytes(), b"ELF scanner")

    def test_phase5_reuse_units_keep_compiled_function_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase3 = workspace / "phase3_native"
            phase3.mkdir(parents=True)
            common = {
                "retrieval_score": 0.8,
                "evidence_sufficiency": {
                    "level": "high",
                    "deep_comparison_eligible": True,
                },
                "commercial": {
                    "function_id": "commercial-1",
                    "representation": "ida_lightweight_inventory",
                    "ownership": {"category": "first_party"},
                },
            }
            rows = [
                {
                    **common,
                    "source": {
                        "function_id": function_id,
                        "repository_full_name": "example/scanner",
                        "representation": "oss_compiled_binary_function",
                        "library_sha256": "a" * 64,
                        "address": address,
                        "build_variant": "arm64-v8a-O2",
                    },
                }
                for function_id, address in (
                    ("oss-function-1", "0x1000"),
                    ("oss-function-2", "0x2000"),
                )
            ]
            (phase3 / "reuse_candidates.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            evidence = [
                row
                for row in _collect_evidence_units(workspace)
                if row.get("kind") == "open_source_retrieval_candidate"
            ]

            self.assertEqual(len(evidence), 2)
            self.assertEqual(len({row["unit_id"] for row in evidence}), 2)
            self.assertTrue(
                all(
                    row["evidence_sufficiency"]["deep_comparison_eligible"]
                    for row in evidence
                )
            )

    def test_phase5_deep_units_keep_end_to_end_traceability(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase3 = workspace / "phase3_native"
            phase3.mkdir(parents=True)
            pseudocode = phase3 / "pair-traced.c"
            pseudocode.write_text("int detect_page(void) { return 1; }\n", encoding="utf-8")
            safe_write_json(
                phase3 / "reuse_candidate_targets.json",
                {
                    "targets": [
                        {
                            "candidate_pair_id": "pair-traced",
                            "analysis_lane": "usage",
                        }
                    ]
                },
            )
            deep_row = {
                "comparison_id": "comparison-traced",
                "candidate_pair_id": "pair-traced",
                "candidate_origin": "selected_ida_seed",
                "analysis_lane": "usage",
                "deep_comparison_score": 0.81,
                "relationship_assessment": "open_source_or_external_usage_candidate",
                "claim_eligibility": {
                    "usage_review": True,
                    "adaptation_review": False,
                    "copying_conclusion": False,
                },
                "commercial_function_id": "commercial-traced",
                "commercial": {
                    "function_id": "commercial-traced",
                    "library": "libscanner.so",
                    "library_sha256": "a" * 64,
                    "decompiled_address": "0x1000",
                    "pseudocode_path": str(pseudocode),
                    "pseudocode_sha256": "pseudocode-traced",
                },
                "source": {
                    "function_id": "source-traced",
                    "repository_full_name": "example/scanner",
                    "source_path": "src/scanner.cpp",
                    "start_line": 10,
                },
                "source_family": "example/scanner:src/scanner.cpp:10",
            }
            (phase3 / "reuse_deep_comparisons.jsonl").write_text(
                json.dumps(deep_row) + "\n",
                encoding="utf-8",
            )

            evidence = [
                row
                for row in _collect_evidence_units(workspace)
                if row.get("kind") == "open_source_deep_comparison"
            ]

            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0]["candidate_pair_id"], "pair-traced")
            self.assertEqual(evidence[0]["analysis_lane"], "usage")
            self.assertEqual(
                evidence[0]["traceability"]["deep_comparison_id"],
                "comparison-traced",
            )
            self.assertTrue(
                evidence[0]["traceability"]["ida_pseudocode_available"]
            )
            self.assertEqual(
                evidence[0]["commercial_function"]["function_id"],
                "commercial-traced",
            )
            self.assertEqual(
                evidence[0]["open_source_function"]["function_id"],
                "source-traced",
            )

    def test_validation_blocks_incomplete_authoritative_candidate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase2 = workspace / "phase2_jadx"
            phase3 = workspace / "phase3_native"
            phase2.mkdir(parents=True)
            phase3.mkdir(parents=True)
            safe_write_json(
                phase2 / "java_method_index_summary.json",
                {"status": "completed", "indexed_method_count": 1},
            )
            safe_write_json(
                phase2 / "dex_method_index_summary.json",
                {"status": "completed", "indexed_method_count": 1},
            )
            safe_write_json(
                phase3 / "native_full_index_summary.json",
                {"status": "completed", "indexed_function_count": 1},
            )
            safe_write_json(
                phase3 / "reuse_candidate_summary.json",
                {
                    "status": "completed",
                    "commercial_function_count": 1,
                    "source_function_count": 1,
                    "candidate_pair_count": 1,
                },
            )
            safe_write_json(
                phase3 / "reuse_candidate_selection_summary.json",
                {
                    "status": "completed",
                    "native_deep_eligible_count": 1,
                    "native_decompile_target_count": 1,
                    "selection_starved": False,
                },
            )
            safe_write_json(
                phase3 / "reuse_candidate_targets.json",
                {
                    "targets": [
                        {
                            "candidate_pair_id": "pair-incomplete",
                            "analysis_lane": "usage",
                            "reuse_candidate": {
                                "candidate_pair_id": "pair-incomplete",
                                "analysis_lane": "usage",
                                "commercial_function_id": "commercial-1",
                                "source_function_id": "source-1",
                            },
                        }
                    ]
                },
            )

            checks = _reuse_search_checks(
                workspace,
                native_library_count=1,
                require_evidence_packet=False,
            )
            identity = next(
                row
                for row in checks
                if row["id"] == "reuse_candidate_target_identity"
            )

            self.assertEqual(identity["status"], "failed")
            self.assertTrue(identity["blocking"])
            self.assertEqual(
                identity["details"]["incomplete_metadata"][0]["missing_fields"],
                ["address", "library_sha256", "source_project"],
            )

    def test_validation_blocks_dependency_owned_native_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase2 = workspace / "phase2_jadx"
            phase3 = workspace / "phase3_native"
            phase2.mkdir(parents=True)
            phase3.mkdir(parents=True)
            safe_write_json(
                phase2 / "java_method_index_summary.json",
                {"status": "completed", "indexed_method_count": 1},
            )
            safe_write_json(
                phase2 / "dex_method_index_summary.json",
                {"status": "completed", "indexed_method_count": 1},
            )
            safe_write_json(
                phase3 / "native_full_index_summary.json",
                {"status": "completed", "indexed_function_count": 1},
            )
            safe_write_json(
                phase3 / "reuse_candidate_summary.json",
                {
                    "status": "completed",
                    "commercial_function_count": 1,
                    "source_function_count": 1,
                    "candidate_pair_count": 1,
                },
            )
            safe_write_json(
                phase3 / "reuse_candidate_selection_summary.json",
                {
                    "status": "completed",
                    "native_deep_eligible_count": 1,
                    "native_decompile_target_count": 1,
                    "selection_starved": False,
                },
            )
            safe_write_json(
                phase3 / "reuse_candidate_targets.json",
                {
                    "targets": [
                        {
                            "candidate_pair_id": "pair-dependency",
                            "analysis_lane": "adaptation",
                            "commercial_function_id": "commercial-1",
                            "source_function_id": "source-1",
                            "library_sha256": "a" * 64,
                            "address": "0x1000",
                            "library": "libPDFNetC.so",
                            "reuse_candidate": {
                                "candidate_pair_id": "pair-dependency",
                                "analysis_lane": "adaptation",
                                "source_project": "example/project",
                                "commercial": {
                                    "function_id": "commercial-1",
                                    "library_sha256": "a" * 64,
                                    "address": "0x1000",
                                    "library": "libPDFNetC.so",
                                    "ownership": {"category": "third_party"},
                                },
                                "source": {
                                    "function_id": "source-1",
                                    "repository_full_name": "example/project",
                                },
                            },
                        }
                    ]
                },
            )

            checks = _reuse_search_checks(
                workspace,
                native_library_count=1,
                require_evidence_packet=False,
            )
            identity = next(
                row
                for row in checks
                if row["id"] == "reuse_candidate_target_identity"
            )

            self.assertEqual(identity["status"], "failed")
            self.assertTrue(identity["blocking"])
            self.assertEqual(
                identity["details"]["prohibited_commercial_ownership"][0][
                    "ownership_category"
                ],
                "third_party",
            )

    def test_post_ida_replay_is_non_destructive_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "run"
            phase3 = workspace / "phase3_native"
            phase3.mkdir(parents=True)
            source_index = root / "source.jsonl"
            pseudocode = phase3 / "selected.c"
            pseudocode.write_text(
                "int detect_page(int value) { return value + 17; }\n",
                encoding="utf-8",
            )
            source = {
                "function_id": "source-replay",
                "repository_full_name": "example/replay",
                "commit_sha": "b" * 40,
                "source_path": "src/replay.c",
                "start_line": 4,
                "function_name": "detect_page",
                "structure_token_count": 8,
            }
            source_index.write_text(json.dumps(source) + "\n", encoding="utf-8")
            candidate = {
                "candidate_pair_id": "pair-replay",
                "analysis_lane": "usage",
                "retrieval_score": 0.8,
                "commercial": {
                    "function_id": "commercial-replay",
                    "library": "libreplay.so",
                    "library_sha256": "c" * 64,
                    "address": "0x1000",
                },
                "source": source,
                "source_project": "example/replay",
            }
            (phase3 / "reuse_candidates_review.jsonl").write_text(
                json.dumps(candidate) + "\n",
                encoding="utf-8",
            )
            target = {
                "kind": "reuse_candidate",
                "candidate_pair_id": "pair-replay",
                "analysis_lane": "usage",
                "commercial_function_id": "commercial-replay",
                "source_function_id": "source-replay",
                "library": "libreplay.so",
                "library_sha256": "c" * 64,
                "address": "0x1000",
                "reuse_candidate": candidate,
            }
            safe_write_json(
                phase3 / "native_targets.json",
                {"reuse_candidate_target_count": 1, "targets": [target]},
            )
            safe_write_json(
                phase3 / "ida_automated_summary.json",
                {
                    "results": [
                        {
                            "success": True,
                            "output_path": str(pseudocode),
                            "pseudocode_sha256": "replay-pseudocode",
                            "target": target,
                            "function_features": {
                                "pseudocode_nonempty_line_count": 1,
                                "instruction_count": 8,
                            },
                        }
                    ]
                },
            )
            safe_write_json(
                workspace / "run_context.json",
                {"config": {"oss_function_index": str(source_index)}},
            )

            report = replay_post_ida_analysis(workspace, apply=False)

            self.assertEqual(report["status"], "completed")
            self.assertFalse(report["applied"])
            self.assertFalse((phase3 / "reuse_deep_comparisons.jsonl").exists())
            self.assertFalse((phase3 / "reuse_candidate_targets.json").exists())
            staging = workspace / "reanalysis" / "post_ida"
            self.assertTrue((staging / "reuse_deep_comparisons.jsonl").is_file())
            self.assertTrue((staging / "reuse_candidate_targets.json").is_file())

    def test_build_queue_prefers_detected_native_build_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "OSS001_example_scanner" / ("a" * 40) / "source"
            source.mkdir(parents=True)
            (source / "CMakeLists.txt").write_text("project(scanner)\n")
            (source / "scanner.cpp").write_text("int detect_page() { return 1; }\n")
            summary, rows = build_oss_build_queue(
                [
                    {
                        "retrieval_score": 0.8,
                        "commercial": {"function_id": "commercial-1"},
                        "source": {
                            "corpus_id": "OSS001",
                            "repository_full_name": "example/scanner",
                            "candidate_role": "upstream_candidate",
                        },
                    }
                ],
                [
                    {
                        "corpus_id": "OSS001",
                        "repository_full_name": "example/scanner",
                        "candidate_role": "upstream_candidate",
                        "source_directory": "source",
                        "selected_commit": {"sha": "a" * 40},
                    }
                ],
                snapshot_root=root,
                limit=1,
            )
            self.assertEqual(summary["selected_eligible_repository_count"], 1)
            self.assertEqual(rows[0]["queue_rank"], 1)
            self.assertEqual(rows[0]["build_system_counts"], {"cmake": 1})
            self.assertEqual(
                rows[0]["requested_build_variants"][0]["optimization"],
                "O2",
            )

    def test_method_control_reaches_build_and_decompile_queues(self) -> None:
        candidate = {
            "retrieval_score": 0.91,
            "commercial": {
                "function_id": "commercial-native-1",
                "representation": "ida_lightweight_inventory",
                "library": "/tmp/libcommercial.so",
                "library_sha256": "a" * 64,
                "address": "0x1000",
                "name": "detectLines",
                "ownership": {"category": "first_party"},
            },
            "source": {
                "corpus_id": "OSS006",
                "repository_full_name": "CihanTopal/ED_Lib",
                "candidate_role": "method_control",
            },
        }
        targets = native_decompile_targets([candidate], limit=10)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["kind"], "reuse_candidate")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "OSS006_CihanTopal_ED_Lib" / ("b" * 40) / "source"
            source.mkdir(parents=True)
            (source / "CMakeLists.txt").write_text("project(edlib)\n")
            (source / "edge.cpp").write_text("int detect_lines() { return 1; }\n")
            summary, rows = build_oss_build_queue(
                [candidate],
                [
                    {
                        "corpus_id": "OSS006",
                        "repository_full_name": "CihanTopal/ED_Lib",
                        "candidate_role": "method_control",
                        "source_directory": "source",
                        "selected_commit": {"sha": "b" * 40},
                    }
                ],
                snapshot_root=root,
                limit=1,
            )
            self.assertEqual(summary["selected_eligible_repository_count"], 1)
            self.assertEqual(rows[0]["candidate_role"], "method_control")

    def test_large_candidate_pool_prefers_rare_overlap_deterministically(self) -> None:
        commercial = [
            {
                "function_id": "commercial",
                "representation": "jadx_source_method",
                "name": "rareCommon",
                "semantic_tokens": ["rare", "common"],
            }
        ]
        sources = [
            {
                "corpus_id": "rare-source",
                "repository_full_name": "example/rare",
                "source_path": "rare.cpp",
                "start_line": 1,
                "function_name": "rare_common",
                "candidate_role": "upstream_candidate",
            },
            {
                "corpus_id": "common-source",
                "repository_full_name": "example/common",
                "source_path": "common.cpp",
                "start_line": 1,
                "function_name": "common_helper",
                "candidate_role": "upstream_candidate",
            },
        ]

        summary, candidates = retrieve_candidates(
            commercial,
            sources,
            top_k=2,
            minimum_score=0.1,
            max_candidates_per_commercial=1,
        )

        self.assertEqual(summary["truncated_candidate_pool_function_count"], 1)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            (candidates[0].get("source") or {}).get("corpus_id"),
            "rare-source",
        )

    def test_third_party_native_candidate_does_not_enter_deep_queue(self) -> None:
        candidates = [
            {
                "retrieval_score": 0.95,
                "commercial": {
                    "function_id": "sdk-function",
                    "representation": "ida_lightweight_inventory",
                    "name": "thirdPartyDetector",
                    "library": "/tmp/libopencv.so",
                    "library_sha256": "b" * 64,
                    "abi": "arm64-v8a",
                    "address": "0x2000",
                    "ownership": {"category": "third_party"},
                },
                "source": {
                    "candidate_role": "upstream_candidate",
                    "repository_full_name": "opencv/opencv",
                },
            }
        ]
        self.assertEqual(native_decompile_targets(candidates, limit=10), [])

        summary, retrieved = retrieve_candidates(
            [candidates[0]["commercial"]],
            [
                {
                    "corpus_id": "opencv",
                    "repository_full_name": "opencv/opencv",
                    "source_path": "modules/imgproc/detector.cpp",
                    "start_line": 1,
                    "function_name": "thirdPartyDetector",
                    "candidate_role": "upstream_candidate",
                }
            ],
            minimum_score=0,
        )
        self.assertEqual(retrieved, [])
        self.assertEqual(summary["eligible_commercial_function_count"], 0)
        self.assertEqual(
            summary["skipped_commercial_ownership_counts"],
            {"third_party": 1},
        )

    def test_zero_candidates_is_a_valid_retrieval_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase2 = workspace / "phase2_jadx"
            phase3 = workspace / "phase3_native"
            phase5 = workspace / "phase5_evidence"
            phase2.mkdir(parents=True)
            phase3.mkdir(parents=True)
            phase5.mkdir(parents=True)
            safe_write_json(phase3 / "native_analysis.json", {"libraries": []})
            safe_write_json(
                phase2 / "java_method_index_summary.json",
                {
                    "status": "completed",
                    "indexed_method_count": 2,
                    "source_file_count": 1,
                },
            )
            safe_write_json(
                phase2 / "dex_method_index_summary.json",
                {
                    "status": "completed",
                    "dex_file_count": 1,
                    "declared_method_count": 2,
                    "indexed_method_count": 2,
                    "code_bearing_method_count": 2,
                    "error_count": 0,
                },
            )
            safe_write_json(
                phase3 / "native_full_index_summary.json",
                {
                    "status": "completed",
                    "indexed_function_count": 0,
                    "indexed_library_hash_count": 0,
                },
            )
            safe_write_json(
                phase3 / "reuse_candidate_summary.json",
                {
                    "status": "completed",
                    "commercial_function_count": 2,
                    "searchable_commercial_function_count": 0,
                    "source_function_count": 50,
                    "candidate_pair_count": 0,
                    "commercial_function_with_candidate_count": 0,
                },
            )
            safe_write_json(
                phase3 / "native_targets.json",
                {"reuse_candidate_target_count": 0},
            )
            safe_write_json(phase3 / "native_evidence_units.json", [])
            (phase5 / "evidence_units.jsonl").write_text("", encoding="utf-8")
            result = build_pipeline_validation(
                workspace,
                [
                    PhaseResult(name="phase2_jadx", success=True),
                    PhaseResult(name="phase3_native", success=True),
                    PhaseResult(name="phase5_evidence", success=True),
                ],
                expect_automated_ida=True,
                require_evidence_packet=True,
                expect_reuse_search=True,
            )
            self.assertEqual(result["status"], "passed")
            retrieval = next(
                row
                for row in result["checks"]
                if row["id"] == "open_source_candidate_retrieval"
            )
            self.assertEqual(retrieval["status"], "passed")
            self.assertEqual(retrieval["details"]["candidate_pair_count"], 0)

    def test_native_app_with_zero_candidates_does_not_require_hex_rays(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase2 = workspace / "phase2_jadx"
            phase3 = workspace / "phase3_native"
            phase5 = workspace / "phase5_evidence"
            phase2.mkdir(parents=True)
            phase3.mkdir(parents=True)
            phase5.mkdir(parents=True)
            safe_write_json(
                phase3 / "native_analysis.json",
                {"libraries": [{"sha256": "a" * 64}]},
            )
            safe_write_json(
                phase2 / "java_method_index_summary.json",
                {
                    "status": "completed",
                    "indexed_method_count": 3,
                    "source_file_count": 1,
                },
            )
            safe_write_json(
                phase2 / "dex_method_index_summary.json",
                {
                    "status": "completed",
                    "dex_file_count": 1,
                    "declared_method_count": 3,
                    "indexed_method_count": 3,
                    "code_bearing_method_count": 3,
                    "error_count": 0,
                },
            )
            safe_write_json(
                phase3 / "native_full_index_summary.json",
                {
                    "status": "completed",
                    "indexed_function_count": 12,
                    "indexed_library_hash_count": 1,
                },
            )
            safe_write_json(
                phase3 / "reuse_candidate_summary.json",
                {
                    "status": "completed",
                    "commercial_function_count": 15,
                    "searchable_commercial_function_count": 4,
                    "source_function_count": 50,
                    "candidate_pair_count": 0,
                    "commercial_function_with_candidate_count": 0,
                },
            )
            safe_write_json(
                phase3 / "native_targets.json",
                {"reuse_candidate_target_count": 0},
            )
            safe_write_json(phase3 / "native_evidence_units.json", [])
            (phase5 / "evidence_units.jsonl").write_text("", encoding="utf-8")

            result = build_pipeline_validation(
                workspace,
                [
                    PhaseResult(name="phase2_jadx", success=True),
                    PhaseResult(name="phase3_native", success=True),
                    PhaseResult(name="phase5_evidence", success=True),
                ],
                expect_automated_ida=True,
                require_evidence_packet=True,
                expect_reuse_search=True,
            )

            self.assertEqual(result["status"], "passed")
            self.assertFalse(result["automated_ida_required"])
            self.assertTrue(result["ready_for_similarity"])
            self.assertTrue(result["ready_for_dependency_analysis"])
            self.assertTrue(result["ready_for_usage_analysis"])
            self.assertFalse(result["ready_for_adaptation_analysis"])
            self.assertFalse(result["ready_for_copying_review"])
            self.assertFalse(result["copying_candidate_present"])
            self.assertFalse(result["copying_conclusion_supported"])
            ida_check = next(
                row for row in result["checks"] if row["id"] == "automated_ida"
            )
            self.assertEqual(ida_check["status"], "not_applicable")

    def test_native_candidate_starvation_is_not_similarity_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase2 = workspace / "phase2_jadx"
            phase3 = workspace / "phase3_native"
            phase5 = workspace / "phase5_evidence"
            phase2.mkdir(parents=True)
            phase3.mkdir(parents=True)
            phase5.mkdir(parents=True)
            safe_write_json(
                phase3 / "native_analysis.json",
                {"libraries": [{"sha256": "a" * 64}]},
            )
            safe_write_json(
                phase2 / "java_method_index_summary.json",
                {
                    "status": "completed",
                    "indexed_method_count": 3,
                    "source_file_count": 1,
                },
            )
            safe_write_json(
                phase2 / "dex_method_index_summary.json",
                {
                    "status": "completed",
                    "dex_file_count": 1,
                    "declared_method_count": 3,
                    "indexed_method_count": 3,
                    "code_bearing_method_count": 3,
                    "error_count": 0,
                },
            )
            safe_write_json(
                phase3 / "native_full_index_summary.json",
                {
                    "status": "completed",
                    "indexed_function_count": 12,
                    "indexed_library_hash_count": 1,
                },
            )
            safe_write_json(
                phase3 / "reuse_candidate_summary.json",
                {
                    "status": "completed",
                    "commercial_function_count": 15,
                    "searchable_commercial_function_count": 4,
                    "source_function_count": 50,
                    "candidate_pair_count": 8,
                    "commercial_function_with_candidate_count": 2,
                },
            )
            safe_write_json(
                phase3 / "reuse_candidate_selection_summary.json",
                {
                    "status": "completed",
                    "native_deep_eligible_count": 3,
                    "native_decompile_target_count": 0,
                    "selection_starved": True,
                },
            )
            safe_write_json(
                phase3 / "native_targets.json",
                {"reuse_candidate_target_count": 0},
            )
            safe_write_json(phase3 / "native_evidence_units.json", [])
            (phase5 / "evidence_units.jsonl").write_text("", encoding="utf-8")

            result = build_pipeline_validation(
                workspace,
                [
                    PhaseResult(name="phase2_jadx", success=True),
                    PhaseResult(name="phase3_native", success=True),
                    PhaseResult(name="phase5_evidence", success=True),
                ],
                expect_automated_ida=True,
                require_evidence_packet=True,
                expect_reuse_search=True,
            )

            cohort_check = next(
                row
                for row in result["checks"]
                if row["id"] == "reuse_candidate_cohort_selection"
            )
            self.assertEqual(result["status"], "partial")
            self.assertFalse(result["ready_for_similarity"])
            self.assertTrue(result["automated_ida_required"])
            self.assertEqual(cohort_check["status"], "partial")


if __name__ == "__main__":
    unittest.main()
