from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apk_pipeline.ida_integration import (
    IDA_RESULT_SCHEMA,
    build_ida_task_manifest,
    build_java_native_hints,
    import_manual_ida_results,
)
from apk_pipeline.native_decompiler import (
    _resolve_function_seek,
    select_native_targets,
)
from apk_pipeline.native_semantics import classify_native_semantics
from apk_pipeline.phase3_native import _extract_symbols, build_native_function_index
from apk_pipeline.phase5_evidence import run_phase5_evidence
from apk_pipeline.utils import safe_write_json, sha256_file


def _symbol(
    name: str,
    address: str,
    *,
    size_bytes: int = 128,
    source: str = "readelf",
) -> dict[str, object]:
    return {
        "name": name,
        "address": address,
        "size_bytes": size_bytes,
        "symbol_type": "FUNC",
        "binding": "GLOBAL",
        "section": "12",
        "symbol_source": source,
        "is_jni": name.startswith("Java_"),
    }


class Phase3IDAIntegrationTests(unittest.TestCase):
    def test_symbol_extraction_preserves_elf_addresses_and_sizes(self) -> None:
        output = "\n".join(
            [
                "Symbol table '.dynsym' contains 3 entries:",
                "  Num:    Value          Size Type    Bind   Vis      Ndx Name",
                "    1: 0000000000001010   144 FUNC    GLOBAL DEFAULT   12 Java_com_example_Core_run",
                "    2: 0000000000002200    32 FUNC    GLOBAL DEFAULT   12 helper@@LIB_1.0",
                "    3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND missing",
            ]
        )
        completed = subprocess.CompletedProcess(
            ["readelf"],
            0,
            output,
            "",
        )

        def has_tool(name: str) -> bool:
            return name == "readelf"

        with (
            patch("apk_pipeline.phase3_native.tool_exists", side_effect=has_tool),
            patch("apk_pipeline.phase3_native.run_cmd", return_value=completed),
        ):
            exported, jni, records, warnings = _extract_symbols(
                Path("libcore.so")
            )

        self.assertEqual(exported, ["Java_com_example_Core_run", "helper"])
        self.assertEqual(jni, ["Java_com_example_Core_run"])
        self.assertEqual(warnings, [])
        self.assertEqual(records[0]["address"], "0x1010")
        self.assertEqual(records[0]["size_bytes"], 144)
        self.assertEqual(records[1]["address"], "0x2200")

    def test_automated_decompiler_seeks_exact_address_before_name(self) -> None:
        seek, function = _resolve_function_seek(
            "duplicate_name",
            "0x2000",
            [
                {"name": "duplicate_name", "offset": 0x1000},
                {"name": "renamed_by_tool", "offset": 0x2000},
            ],
        )
        self.assertEqual(seek, "0x2000")
        self.assertEqual(function["name"], "renamed_by_tool")

    def test_native_ranking_uses_java_abi_and_wrapper_signals(self) -> None:
        arm64 = {
            "name": "libcore.so",
            "extracted_path": "/tmp/arm64/libcore.so",
            "sha256": "a" * 64,
            "abi": "arm64-v8a",
            "ownership": {"category": "first_party"},
            "capability_counts": {"ocr": 2, "local_ml": 1},
            "interesting_strings": [{"value": "TFLite Interpreter OCR"}],
            "jni_symbols": ["Java_com_example_NativeBridge_runOcr"],
            "exported_symbols": [
                "Java_com_example_NativeBridge_runOcr",
                "getState",
            ],
            "symbol_records": [
                _symbol(
                    "Java_com_example_NativeBridge_runOcr",
                    "0x1000",
                    size_bytes=500,
                ),
                _symbol("getState", "0x1100", size_bytes=16),
            ],
        }
        x86 = {
            **arm64,
            "extracted_path": "/tmp/x86/libcore.so",
            "sha256": "b" * 64,
            "abi": "x86_64",
        }
        code_index = {
            "files": [
                {
                    "file": "sources/com/example/NativeBridge.java",
                    "package": "com.example",
                    "class_name": "NativeBridge",
                    "native_methods": ["runOcr"],
                    "load_libraries": ["core"],
                }
            ]
        }
        hints = build_java_native_hints(code_index, [arm64, x86])
        targets = select_native_targets(
            [x86, arm64],
            max_targets=20,
            max_libraries=4,
            java_native_hints=hints,
        )
        arm64_core = next(
            item
            for item in targets
            if item["library"] == arm64["extracted_path"]
            and item["name"] == "Java_com_example_NativeBridge_runOcr"
        )
        x86_core = next(
            item
            for item in targets
            if item["library"] == x86["extracted_path"]
            and item["name"] == "Java_com_example_NativeBridge_runOcr"
        )
        getter = next(
            item
            for item in targets
            if item["library"] == arm64["extracted_path"]
            and item["name"] == "getState"
        )
        self.assertGreater(arm64_core["score"], x86_core["score"])
        self.assertGreater(arm64_core["score"], getter["score"])
        self.assertEqual(arm64_core["address"], "0x1000")
        self.assertEqual(
            arm64_core["abi_analysis_role"],
            "primary_production",
        )
        self.assertEqual(len(arm64_core["associated_java_methods"]), 1)
        self.assertEqual(
            getter["semantic_role_prior"]["role"],
            "wrapper",
        )

        function_index = build_native_function_index([arm64, x86])
        manifest = build_ida_task_manifest(
            [arm64, x86],
            function_index,
            targets,
            code_index=code_index,
            review_limit=2,
        )
        self.assertEqual(manifest["candidate_count"], 4)
        self.assertEqual(manifest["review_queue_count"], 2)
        self.assertTrue(manifest["all_candidates_retained"])
        self.assertEqual(
            manifest["review_queue"][0]["abi"],
            "arm64-v8a",
        )

    def test_long_jni_pseudocode_is_not_assumed_to_be_a_wrapper(self) -> None:
        pseudocode = "\n".join(
            ["int score = 0;"]
            + [f"score += pixels[{index}] * weights[{index}];" for index in range(24)]
            + ["return score;"]
        )
        result = classify_native_semantics(
            "Java_com_example_Core_runOcr",
            pseudocode=pseudocode,
        )
        self.assertEqual(result["role"], "algorithm")

    def test_long_call_only_ocr_function_is_not_claimed_as_algorithm(self) -> None:
        pseudocode = "\n".join(
            ["int RunOCR(Context *ctx) {"]
            + [f"  stage_{index}(ctx);" for index in range(20)]
            + ["  return finalize(ctx);", "}"]
        )
        result = classify_native_semantics(
            "Java_com_example_Core_runOcr",
            pseudocode=pseudocode,
            features={
                "call_targets": [f"stage_{index}" for index in range(20)]
            },
        )
        self.assertEqual(result["role"], "orchestration")

    def test_manual_ida_import_accepts_exact_identity_and_rejects_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            library_path = workspace / "phase3_native" / "libs" / "libcore.so"
            library_path.parent.mkdir(parents=True)
            library_path.write_bytes(b"\x7fELFcore")
            library_sha = sha256_file(library_path)
            library = {
                "name": "libcore.so",
                "extracted_path": str(library_path),
                "sha256": library_sha,
                "abi": "arm64-v8a",
                "ownership": {"category": "first_party"},
                "symbol_records": [
                    _symbol("RunOCR", "0x1000", size_bytes=512),
                    _symbol("Helper", "0x2000", size_bytes=64),
                ],
                "exported_symbols": ["RunOCR", "Helper"],
                "jni_symbols": [],
                "capability_counts": {"ocr": 1},
                "interesting_strings": [{"value": "OCR pixel transform"}],
            }
            function_index = build_native_function_index([library])
            targets = select_native_targets([library])
            manifest = build_ida_task_manifest(
                [library],
                function_index,
                targets,
            )
            safe_write_json(
                workspace / "phase3_native" / "ida_target_manifest.json",
                manifest,
            )
            safe_write_json(
                workspace / "phase3_native" / "native_analysis.json",
                {"libraries": [library]},
            )

            results_dir = (
                workspace / "phase3_native" / "manual_ida" / "results"
            )
            results_dir.mkdir(parents=True)
            pseudocode_path = results_dir / "run_ocr.c"
            pseudocode_path.write_text(
                "\n".join(
                    ["int RunOCR(unsigned char *pixels) {"]
                    + [
                        f"  score += pixels[{index}] * kernel[{index}];"
                        for index in range(24)
                    ]
                    + ["  return score;", "}"]
                ),
                encoding="utf-8",
            )
            safe_write_json(
                results_dir / "valid.json",
                {
                    "schema_version": IDA_RESULT_SCHEMA,
                    "library_sha256": library_sha,
                    "library_name": "libcore.so",
                    "abi": "arm64-v8a",
                    "address": "0x1000",
                    "symbol": "RunOCR",
                    "ida_version": "9.4",
                    "pseudocode_file": "run_ocr.c",
                },
            )
            safe_write_json(
                results_dir / "mismatch.json",
                {
                    "schema_version": IDA_RESULT_SCHEMA,
                    "library_sha256": library_sha,
                    "library_name": "libcore.so",
                    "abi": "arm64-v8a",
                    "address": "0x2000",
                    "symbol": "RunOCR",
                    "ida_version": "9.4",
                    "pseudocode": "return 0;",
                },
            )

            summary = import_manual_ida_results(workspace)
            evidence = json.loads(
                (
                    workspace
                    / "phase3_native"
                    / "manual_ida"
                    / "evidence_units.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(summary["status"], "partial")
            self.assertEqual(summary["accepted_count"], 1)
            self.assertEqual(summary["rejected_count"], 1)
            self.assertIn(
                "identify different tasks",
                summary["rejected"][0]["error"],
            )
            self.assertTrue(evidence[0]["decompiled"])
            self.assertTrue(evidence[0]["algorithm_recovered"])
            self.assertEqual(
                evidence[0]["identity_verification"],
                "verified_manifest_function",
            )
            self.assertEqual(evidence[0]["library_sha256"], library_sha)
            self.assertEqual(evidence[0]["abi"], "arm64-v8a")
            self.assertEqual(evidence[0]["address"], "0x1000")
            self.assertEqual(evidence[0]["ida_version"], "9.4")

            required_payloads = {
                "phase0_split_inventory/split_inventory.json": {},
                "phase1_manifest/manifest_summary.json": {},
                "phase2_jadx/code_index.json": {},
                "phase2_jadx/java_evidence_units.json": [],
                "phase3_native/native_evidence_units.json": [],
            }
            for relative_path, payload in required_payloads.items():
                safe_write_json(workspace / relative_path, payload)
            run_phase5_evidence(
                workspace,
                force=True,
                require_resources=False,
            )
            packet = json.loads(
                (
                    workspace / "phase5_evidence" / "review_packet.json"
                ).read_text(encoding="utf-8")
            )
            similarity_packet = json.loads(
                (
                    workspace
                    / "phase5_evidence"
                    / "similarity_ready_packet.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                packet["evidence_units_summary"]["by_kind"][
                    "manual_ida_function"
                ],
                1,
            )
            self.assertEqual(
                packet["manual_ida"]["import"]["accepted_count"],
                1,
            )
            manual_units = [
                item
                for item in similarity_packet["high_value_units"]
                if item.get("kind") == "manual_ida_function"
            ]
            self.assertEqual(len(manual_units), 1)
            self.assertTrue(manual_units[0]["decompiled"])
            self.assertTrue(manual_units[0]["algorithm_recovered"])


if __name__ == "__main__":
    unittest.main()
