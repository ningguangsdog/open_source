from __future__ import annotations

import json
import importlib.util
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apk_pipeline.capability_taxonomy import classify_text
from apk_pipeline.code_ownership import (
    classify_code_ownership,
    classify_native_ownership,
)
from apk_pipeline.config import PipelineConfig
from apk_pipeline.pipeline import APKPipeline
from apk_pipeline.phase0_split_inventory import classify_split_type, run_phase0
from apk_pipeline.phase1_manifest import _extract_manifest_summary
from apk_pipeline.phase2_jadx import (
    _run_jadx_one,
    build_code_index,
    build_java_evidence_units,
    run_phase2_multi,
)
from apk_pipeline.phase3_native import (
    _extract_native_libraries,
    run_phase3_multi,
)
from apk_pipeline.phase4_resources import _scan_apk
from apk_pipeline.phase5_evidence import (
    _build_similarity_packet,
    run_phase5_evidence,
)
from apk_pipeline.tflite_parser import parse_model_metadata
from apk_pipeline.models import PhaseResult
from apk_pipeline.utils import safe_write_json


class _ManifestXML:
    def __init__(self, text: str = "<manifest/>") -> None:
        self.text = text

    def toxml(self) -> str:
        return self.text


class _CompleteAPK:
    def get_package(self) -> str:
        return "com.adobe.reader"

    def get_app_name(self) -> str:
        return "Reader"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"

    def get_permissions(self) -> list[str]:
        return []

    def get_android_manifest_xml(self) -> _ManifestXML:
        return _ManifestXML()

    def get_activities(self) -> list[str]:
        return ["com.adobe.reader.MainActivity"]

    def get_services(self) -> list[str]:
        return []

    def get_receivers(self) -> list[str]:
        return []

    def get_providers(self) -> list[str]:
        return []

    def get_min_sdk_version(self) -> str:
        return "24"

    def get_target_sdk_version(self) -> str:
        return "35"

    def get_max_sdk_version(self) -> None:
        return None

    def get_libraries(self) -> list[str]:
        return []

    def get_features(self) -> list[str]:
        return []


class _PartialAPK(_CompleteAPK):
    def get_target_sdk_version(self) -> None:
        return None

    def get_app_name(self) -> str:
        raise ValueError("resource table unavailable")


class _CriticalFailureAPK(_CompleteAPK):
    def get_package(self) -> None:
        return None


def _write_apk(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)


class Phase012QualityTests(unittest.TestCase):
    @unittest.skipUnless(
        importlib.util.find_spec("flatbuffers")
        and importlib.util.find_spec("tflite"),
        "structured TFLite parser dependencies are not installed",
    )
    def test_tflite_schema_parser_reads_graph_metadata(self) -> None:
        import flatbuffers
        import tflite

        builder = flatbuffers.Builder(256)
        description = builder.CreateString("test model")
        tflite.ModelStart(builder)
        tflite.ModelAddVersion(builder, 3)
        tflite.ModelAddDescription(builder, description)
        model = tflite.ModelEnd(builder)
        builder.Finish(model, file_identifier=b"TFL3")
        metadata = parse_model_metadata(
            "test.tflite",
            bytes(builder.Output()),
        )
        graph = metadata["structured_graph"]
        self.assertEqual(graph["status"], "parsed")
        self.assertEqual(graph["model_version"], 3)
        self.assertEqual(graph["description"], "test model")
        self.assertEqual(graph["subgraph_count"], 0)
        self.assertRegex(graph["graph_fingerprint"], r"^[0-9a-f]{64}$")

    def test_capability_classifier_avoids_generic_substrings(self) -> None:
        result = classify_text(
            "capital allocation hashmap page form asset api object"
        )
        self.assertEqual(result, {})

    def test_capability_classifier_keeps_strong_domain_signals(self) -> None:
        result = classify_text(
            "PdfRenderer performs OCR with a TFLite Interpreter"
        )
        self.assertIn("document_pdf", result)
        self.assertIn("ocr", result)
        self.assertIn("local_ml", result)

    def test_split_config_language_is_not_config_other(self) -> None:
        self.assertEqual(
            classify_split_type(Path("split_config.en.apk")),
            "config_language",
        )
        self.assertEqual(
            classify_split_type(Path("split_config.arm64_v8a.apk")),
            "config_abi",
        )

    def test_phase0_requires_primary_manifest_and_keeps_multi_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            valid = root / "base.apk"
            _write_apk(
                valid,
                {
                    "AndroidManifest.xml": b"binary-manifest",
                    "assets/ocr_scan_model_tensor.json": b"{}",
                },
            )
            result = run_phase0([valid], valid, root / "workspace")
            payload = json.loads(
                (
                    root
                    / "workspace"
                    / "phase0_split_inventory"
                    / "split_inventory.json"
                ).read_text(encoding="utf-8")
            )
            candidates = payload["splits"][0]["resource_candidates"]
            self.assertEqual(result.status, "success")
            self.assertEqual(
                {candidate["capability"] for candidate in candidates},
                {"ocr", "scan_image", "local_ml"},
            )

            missing = root / "missing_manifest.apk"
            _write_apk(missing, {"classes.dex": b"dex\n035\x00"})
            failed = run_phase0(
                [missing],
                missing,
                root / "missing_workspace",
            )
            self.assertEqual(failed.status, "failed")
            self.assertIn("AndroidManifest.xml", failed.error or "")

    def test_phase0_rejects_empty_apk_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            empty = root / "empty.apk"
            _write_apk(empty, {})
            result = run_phase0([empty], empty, root / "workspace")
            self.assertEqual(result.status, "failed")
            payload = json.loads(
                (
                    root
                    / "workspace"
                    / "phase0_split_inventory"
                    / "split_inventory.json"
                ).read_text(encoding="utf-8")
            )
            self.assertIn(
                "empty_apk_archive",
                payload["splits"][0]["validation_errors"],
            )

    def test_phase1_reports_field_level_partial_state(self) -> None:
        with patch(
            "apk_pipeline.phase1_manifest._build_apk_parser",
            return_value=_PartialAPK(),
        ):
            summary = _extract_manifest_summary(Path("sample.apk"))
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(
            summary["field_status"]["sdk.target_sdk"]["status"],
            "missing",
        )
        self.assertEqual(
            summary["field_status"]["app_name"]["status"],
            "error",
        )
        self.assertGreater(len(summary["field_warnings"]), 1)
        self.assertLess(summary["completeness_score"], 1.0)

    def test_phase1_critical_failure_has_explicit_error(self) -> None:
        with patch(
            "apk_pipeline.phase1_manifest._build_apk_parser",
            return_value=_CriticalFailureAPK(),
        ):
            summary = _extract_manifest_summary(Path("sample.apk"))
        self.assertEqual(summary["status"], "failed")
        self.assertIn("package", summary["error"])

    def test_ownership_precedence_and_dependency_registry(self) -> None:
        first = classify_code_ownership(
            "com.adobe.reader.ui",
            "sources/com/adobe/reader/ui/Main.java",
            app_package="com.adobe.reader",
        )
        third = classify_code_ownership(
            "com.google.firebase.analytics",
            "sources/com/google/firebase/Analytics.java",
            app_package="com.adobe.reader",
        )
        platform = classify_code_ownership(
            "androidx.lifecycle",
            "sources/androidx/lifecycle/ViewModel.java",
            app_package="com.adobe.reader",
        )
        unknown = classify_code_ownership(
            "a.b",
            "sources/a/b/C.java",
            app_package="com.adobe.reader",
        )
        same_org_dependency = classify_code_ownership(
            "com.google.firebase.analytics",
            "sources/com/google/firebase/Analytics.java",
            app_package="com.google.product",
        )
        self.assertEqual(first.category, "first_party")
        self.assertEqual(third.category, "third_party")
        self.assertEqual(platform.category, "platform")
        self.assertEqual(unknown.category, "unknown")
        self.assertEqual(same_org_dependency.category, "third_party")

    def test_native_ownership_uses_jni_names_library_names_and_hashes(self) -> None:
        first = classify_native_ownership(
            "libreader.so",
            "1" * 64,
            app_package="com.adobe.reader",
            jni_symbols=["Java_com_adobe_reader_Core_run"],
        )
        known_dependency = classify_native_ownership(
            "libtensorflowlite_jni.so",
            "2" * 64,
        )
        hash_dependency = classify_native_ownership(
            "libcustom.so",
            "3" * 64,
            third_party_hashes=["3" * 64],
        )
        unknown = classify_native_ownership(
            "libcustom.so",
            "4" * 64,
        )
        product_wrapper = classify_native_ownership(
            "libpage_segmentation_tflite.so",
            "5" * 64,
        )
        self.assertEqual(first.category, "first_party")
        self.assertEqual(known_dependency.category, "third_party")
        self.assertEqual(hash_dependency.category, "third_party")
        self.assertEqual(unknown.category, "unknown")
        self.assertEqual(product_wrapper.category, "unknown")
        self.assertEqual(unknown.matched_prefix, "4" * 64)

    def test_conflicting_or_invalid_ownership_configuration_fails_early(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source_root = Path(temp_dir) / "decompiled"
            source_root.mkdir()
            with self.assertRaises(ValueError):
                build_code_index(
                    source_root,
                    first_party_prefixes=["com.example"],
                    third_party_prefixes=["com.example."],
                )
            with self.assertRaises(ValueError):
                run_phase3_multi(
                    [],
                    Path(temp_dir) / "workspace",
                    native_depth="none",
                    first_party_native_hashes=("not-a-sha256",),
                )
            with self.assertRaises(ValueError):
                run_phase3_multi(
                    [],
                    Path(temp_dir) / "workspace",
                    native_depth="invalid",
                )
            with self.assertRaises(ValueError):
                run_phase3_multi(
                    [],
                    Path(temp_dir) / "workspace",
                    native_target_capabilities=("not_a_capability",),
                )

    def test_native_extraction_separates_duplicate_apk_stems(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first_apk = root / "one" / "base.apk"
            second_apk = root / "two" / "base.apk"
            first_apk.parent.mkdir()
            second_apk.parent.mkdir()
            _write_apk(first_apk, {"LIB/ARM64-V8A/libcore.SO": b"first"})
            _write_apk(second_apk, {"lib/arm64-v8a/libcore.so": b"second"})

            records = _extract_native_libraries(
                [first_apk, second_apk],
                root / "libs",
            )

            self.assertEqual(len(records), 2)
            output_paths = {
                Path(str(record["extracted_path"])) for record in records
            }
            self.assertEqual(len(output_paths), 2)
            self.assertEqual(
                {path.read_bytes() for path in output_paths},
                {b"first", b"second"},
            )

    def test_native_extraction_rejects_unsafe_archive_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk = root / "unsafe.apk"
            _write_apk(apk, {"lib/../../../escaped.so": b"escape"})
            records = _extract_native_libraries(
                [apk],
                root / "workspace" / "libs",
            )
            self.assertEqual(len(records), 1)
            self.assertFalse(records[0]["success"])
            self.assertFalse((root / "escaped.so").exists())

    def test_resource_selection_keeps_late_high_value_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk = root / "resources.apk"
            entries = {
                f"assets/rules/rule_{index:04d}.txt": b"ordinary rule"
                for index in range(801)
            }
            entries["assets/ocr/model_labels.txt"] = b"ocr recognizer labels"
            _write_apk(apk, entries)
            records, summary = _scan_apk(apk)
            selected_paths = {record["path"] for record in records}
            self.assertIn("assets/ocr/model_labels.txt", selected_paths)
            self.assertEqual(
                summary["resource_candidate_discovered_count"],
                802,
            )
            self.assertEqual(summary["resource_candidate_count"], 800)
            self.assertEqual(summary["resource_candidate_excluded_count"], 2)

    def test_jadx_nonzero_and_timeout_preserve_partial_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk = root / "sample.apk"
            dex_header = bytearray(0x70)
            dex_header[:8] = b"dex\n035\x00"
            dex_header[0x60:0x64] = (2).to_bytes(4, "little")
            _write_apk(apk, {"classes.dex": bytes(dex_header)})

            def nonzero_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
                output = root / "nonzero"
                output.mkdir(parents=True, exist_ok=True)
                (output / "Recovered.java").write_text(
                    "class Recovered {}",
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess([], 1, "", "ERROR incomplete")

            with patch("apk_pipeline.phase2_jadx.run_cmd", side_effect=nonzero_run):
                partial = _run_jadx_one(
                    ["jadx"],
                    apk,
                    root / "nonzero",
                    threads=1,
                    timeout_seconds=10,
                )
            self.assertEqual(partial["status"], "partial")
            self.assertEqual(partial["source_file_count"], 1)
            self.assertEqual(partial["error_count"], 1)
            self.assertEqual(partial["estimated_coverage"]["value"], 0.5)

            def timeout_run(*args: object, **kwargs: object) -> None:
                output = root / "timeout"
                output.mkdir(parents=True, exist_ok=True)
                (output / "Recovered.kt").write_text(
                    "class Recovered",
                    encoding="utf-8",
                )
                raise subprocess.TimeoutExpired(["jadx"], 1)

            with patch("apk_pipeline.phase2_jadx.run_cmd", side_effect=timeout_run):
                timed_out = _run_jadx_one(
                    ["jadx"],
                    apk,
                    root / "timeout",
                    threads=1,
                    timeout_seconds=1,
                )
            self.assertEqual(timed_out["status"], "partial")
            self.assertTrue(timed_out["timed_out"])
            self.assertEqual(timed_out["source_file_count"], 1)

    def test_phase2_separates_duplicate_apk_stems(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first_apk = root / "one" / "base.apk"
            second_apk = root / "two" / "base.apk"
            first_apk.parent.mkdir()
            second_apk.parent.mkdir()
            _write_apk(first_apk, {"classes.dex": b"dex\n035\x00first"})
            _write_apk(second_apk, {"classes.dex": b"dex\n035\x00second"})

            def fake_jadx_run(
                cmd: list[str],
                **kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                output_dir = Path(cmd[cmd.index("-d") + 1])
                apk_path = Path(cmd[-1])
                source = output_dir / "sources" / f"{apk_path.parent.name}.java"
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    f"class {apk_path.parent.name.title()} {{}}",
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with (
                patch(
                    "apk_pipeline.phase2_jadx._ensure_jadx",
                    return_value=["jadx"],
                ),
                patch(
                    "apk_pipeline.phase2_jadx.run_cmd",
                    side_effect=fake_jadx_run,
                ),
            ):
                result = run_phase2_multi(
                    first_apk,
                    [first_apk, second_apk],
                    root / "workspace",
                )

            summary = json.loads(
                (
                    root
                    / "workspace"
                    / "phase2_jadx"
                    / "jadx_summary.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(result.status, "success")
            self.assertEqual(
                len({run["output_dir"] for run in summary["runs"]}),
                2,
            )
            self.assertEqual(
                summary["code_index_summary"]["files_scanned"],
                2,
            )

    def test_code_index_is_complete_and_similarity_excludes_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "decompiled"
            first_party = (
                source_root
                / "base"
                / "sources"
                / "com"
                / "adobe"
                / "reader"
                / "Recognizer.java"
            )
            dependency = (
                source_root
                / "base"
                / "sources"
                / "com"
                / "google"
                / "ml"
                / "Runtime.java"
            )
            neutral = source_root / "base" / "sources" / "a" / "b" / "Plain.java"
            first_party.parent.mkdir(parents=True)
            dependency.parent.mkdir(parents=True)
            neutral.parent.mkdir(parents=True)
            first_party.write_text(
                "package com.adobe.reader; class Recognizer { "
                + ("x" * 260_000)
                + " void runTfliteInterpreter() {} }",
                encoding="utf-8",
            )
            dependency.write_text(
                "package com.google.ml; class Runtime { "
                "void runTfliteInterpreter() {} }",
                encoding="utf-8",
            )
            neutral.write_text(
                "package a.b; class Plain { void nothing() {} }",
                encoding="utf-8",
            )

            code_index = build_code_index(
                source_root,
                app_package="com.adobe.reader",
            )
            units = build_java_evidence_units(code_index)
            self.assertEqual(code_index["files_scanned"], 3)
            self.assertEqual(code_index["indexed_file_count"], 3)
            self.assertFalse(code_index["files_truncated"])
            self.assertEqual(code_index["capability_counts"]["local_ml"], 2)
            self.assertEqual(
                code_index["comparison_capability_counts"]["local_ml"],
                1,
            )
            self.assertEqual(
                code_index["excluded_dependency_capability_counts"]["local_ml"],
                1,
            )
            self.assertEqual(
                code_index["ownership_file_counts"],
                {"first_party": 1, "third_party": 1, "unknown": 1},
            )
            self.assertEqual(len(units), 5)
            self.assertIn(
                "file_prevalence",
                code_index["capability_metrics"]["capabilities"]["local_ml"],
            )

    def test_code_index_does_not_drop_files_after_one_thousand(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source_root = Path(temp_dir) / "decompiled" / "base" / "sources" / "a" / "b"
            source_root.mkdir(parents=True)
            for index in range(1005):
                (source_root / f"C{index}.java").write_text(
                    f"package a.b; class C{index} {{}}",
                    encoding="utf-8",
                )
            code_index = build_code_index(Path(temp_dir) / "decompiled")
            self.assertEqual(code_index["files_scanned"], 1005)
            self.assertEqual(code_index["indexed_file_count"], 1005)
            self.assertEqual(len(code_index["files"]), 1005)
            self.assertFalse(code_index["files_truncated"])

    def test_xml_signals_are_retained_but_not_counted_as_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source_root = Path(temp_dir) / "decompiled" / "base"
            java_path = source_root / "sources" / "com" / "example" / "Main.java"
            xml_path = source_root / "resources" / "res" / "xml" / "config.xml"
            java_path.parent.mkdir(parents=True)
            xml_path.parent.mkdir(parents=True)
            java_path.write_text(
                "package com.example; class Main {}",
                encoding="utf-8",
            )
            xml_path.write_text(
                '<config engine="tflite_interpreter"/>',
                encoding="utf-8",
            )

            code_index = build_code_index(
                Path(temp_dir) / "decompiled",
                app_package="com.example",
            )

            self.assertEqual(code_index["capability_counts"]["local_ml"], 1)
            self.assertNotIn(
                "local_ml",
                code_index["comparison_capability_counts"],
            )
            self.assertEqual(
                code_index["non_code_capability_counts"]["local_ml"],
                1,
            )
            self.assertEqual(
                code_index["ownership_code_file_counts"],
                {"first_party": 1},
            )

    def test_phase5_uses_comparison_java_counts_and_excludes_sdk_units(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            required_payloads = {
                "phase0_split_inventory/split_inventory.json": {
                    "apk_count": 1,
                    "splits": [],
                    "summary": {},
                },
                "phase1_manifest/manifest_summary.json": {
                    "package": "com.example.app",
                },
                "phase2_jadx/code_index.json": {
                    "app_package": "com.example.app",
                    "capability_counts": {"ocr": 99},
                    "comparison_capability_counts": {"ocr": 2},
                    "excluded_dependency_capability_counts": {"ocr": 97},
                    "ownership_file_counts": {
                        "first_party": 2,
                        "third_party": 97,
                    },
                    "ownership_policy": {
                        "comparison_included": ["first_party", "unknown"],
                    },
                    "capability_metrics": {},
                    "comparison_capability_metrics": {},
                    "index_coverage": 1.0,
                    "files_truncated": False,
                    "files_excluded_count": 0,
                },
                "phase2_jadx/java_evidence_units.json": [
                    {
                        "unit_id": "first",
                        "phase": "phase2_jadx",
                        "kind": "source_file",
                        "ownership": {"category": "first_party"},
                        "capabilities": ["ocr"],
                        "confidence": 0.8,
                    },
                    {
                        "unit_id": "sdk",
                        "phase": "phase2_jadx",
                        "kind": "source_file",
                        "ownership": {"category": "third_party"},
                        "capabilities": ["ocr"],
                        "confidence": 0.99,
                    },
                ],
                "phase3_native/native_analysis.json": {
                    "capability_counts": {"local_ml": 10},
                    "comparison_capability_counts": {"local_ml": 1},
                    "excluded_dependency_capability_counts": {"local_ml": 9},
                    "ownership_library_counts": {
                        "first_party": 1,
                        "third_party": 1,
                    },
                },
                "phase3_native/native_evidence_units.json": [
                    {
                        "unit_id": "native-first",
                        "phase": "phase3_native",
                        "kind": "native_library",
                        "ownership": {"category": "first_party"},
                        "capabilities": ["local_ml"],
                        "confidence": 0.85,
                    },
                    {
                        "unit_id": "native-sdk",
                        "phase": "phase3_native",
                        "kind": "native_library",
                        "ownership": {"category": "third_party"},
                        "capabilities": ["local_ml"],
                        "confidence": 0.98,
                    },
                ],
            }
            for relative_path, payload in required_payloads.items():
                safe_write_json(workspace / relative_path, payload)
            upstream = [
                PhaseResult(name="phase0_split_inventory", success=True),
                PhaseResult(name="phase1_manifest", success=True),
                PhaseResult(name="phase2_jadx", success=True),
                PhaseResult(name="phase3_native", success=True),
            ]
            result = run_phase5_evidence(
                workspace,
                upstream_results=upstream,
                require_resources=False,
            )
            packet = json.loads(
                (
                    workspace / "phase5_evidence" / "review_packet.json"
                ).read_text(encoding="utf-8")
            )
            similarity = json.loads(
                (
                    workspace
                    / "phase5_evidence"
                    / "similarity_ready_packet.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(result.status, "success")
            self.assertEqual(packet["capability_counts"]["ocr"], 2)
            self.assertEqual(packet["capability_counts"]["local_ml"], 1)
            self.assertEqual(
                packet["java_code_attribution"][
                    "excluded_dependency_capability_counts"
                ]["ocr"],
                97,
            )
            self.assertEqual(similarity["comparison_evidence_unit_count"], 2)
            self.assertEqual(
                similarity["excluded_dependency_java_unit_count"],
                1,
            )
            self.assertEqual(
                similarity["excluded_dependency_native_unit_count"],
                1,
            )
            self.assertEqual(
                {unit["unit_id"] for unit in similarity["high_value_units"]},
                {"native-first", "first"},
            )

    def test_similarity_packet_sampling_does_not_starve_native_units(self) -> None:
        java_units = [
            {
                "unit_id": f"java-{index}",
                "phase": "phase2_jadx",
                "kind": "source_file",
                "source_type": "java",
                "file": f"C{index}.java",
                "ownership": {"category": "first_party"},
                "capabilities": ["document_pdf"],
                "confidence": 0.8,
            }
            for index in range(300)
        ]
        native_unit = {
            "unit_id": "native-core",
            "phase": "phase3_native",
            "kind": "native_target",
            "ownership": {"category": "unknown"},
            "capabilities": ["local_ml"],
            "confidence": 0.9,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            packet = _build_similarity_packet(
                {},
                {},
                {},
                [*java_units, native_unit],
                Path(temp_dir) / "evidence_graph.json",
            )

        selected_ids = {
            unit["unit_id"] for unit in packet["high_value_units"]
        }
        self.assertIn("native-core", selected_ids)
        self.assertEqual(
            packet["high_value_selection"]["selected_count"],
            250,
        )
        self.assertEqual(
            packet["high_value_selection"]["excluded_count"],
            51,
        )

    def test_pipeline_phase0_to_phase5_contract_with_partial_safe_phase2(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk = root / "sample.apk"
            dex_header = bytearray(0x70)
            dex_header[:8] = b"dex\n035\x00"
            dex_header[0x60:0x64] = (1).to_bytes(4, "little")
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": b"binary-manifest",
                    "classes.dex": bytes(dex_header),
                },
            )

            def fake_jadx_run(
                cmd: list[str],
                **kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                output_dir = Path(cmd[cmd.index("-d") + 1])
                source = (
                    output_dir
                    / "sources"
                    / "com"
                    / "adobe"
                    / "reader"
                    / "Recognizer.java"
                )
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    "package com.adobe.reader; "
                    "class Recognizer { void runTfliteInterpreter() {} }",
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(cmd, 0, "", "")

            config = PipelineConfig(
                apk_path=apk,
                workspace=root / "runs",
                isolated_workspace=True,
                force=True,
                jadx_download=False,
                native_depth="none",
            )
            with (
                patch(
                    "apk_pipeline.phase1_manifest._build_apk_parser",
                    return_value=_CompleteAPK(),
                ),
                patch(
                    "apk_pipeline.phase2_jadx._ensure_jadx",
                    return_value=["jadx"],
                ),
                patch(
                    "apk_pipeline.phase2_jadx.run_cmd",
                    side_effect=fake_jadx_run,
                ),
            ):
                summary = APKPipeline(config).run()

            payload = summary.to_dict()
            workspace = Path(payload["workspace"])
            phase_status = {
                phase["phase"]: phase["status"]
                for phase in payload["phases"]
            }
            code_index = json.loads(
                (
                    workspace / "phase2_jadx" / "code_index.json"
                ).read_text(encoding="utf-8")
            )
            review_packet = json.loads(
                (
                    workspace / "phase5_evidence" / "review_packet.json"
                ).read_text(encoding="utf-8")
            )
            self.assertTrue(payload["all_success"])
            self.assertEqual(set(phase_status.values()), {"success"})
            self.assertEqual(
                code_index["ownership_file_counts"],
                {"first_party": 1},
            )
            self.assertEqual(
                code_index["comparison_capability_counts"]["local_ml"],
                1,
            )
            self.assertEqual(
                review_packet["capability_counts"]["local_ml"],
                1,
            )

    def test_pipeline_stops_after_primary_phase0_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk = root / "sample.apk"
            _write_apk(apk, {"AndroidManifest.xml": b"manifest"})
            failed_phase0 = PhaseResult(
                name="phase0_split_inventory",
                success=False,
                status="failed",
                error="rejected",
            )
            config = PipelineConfig(
                apk_path=apk,
                workspace=root / "workspace",
                force=True,
            )
            with (
                patch(
                    "apk_pipeline.pipeline.run_phase0",
                    return_value=failed_phase0,
                ),
                patch("apk_pipeline.pipeline.run_phase1_multi") as phase1,
                patch("apk_pipeline.pipeline.run_phase2_multi") as phase2,
                patch("apk_pipeline.pipeline.run_phase3_multi") as phase3,
                patch("apk_pipeline.pipeline.run_phase4_resources") as phase4,
                patch("apk_pipeline.pipeline.run_phase5_evidence") as phase5,
            ):
                summary = APKPipeline(config).run()
            self.assertEqual(
                [phase.status for phase in summary.phases],
                [
                    "failed",
                    "skipped",
                    "skipped",
                    "skipped",
                    "skipped",
                    "skipped",
                ],
            )
            for mocked in (phase1, phase2, phase3, phase4, phase5):
                mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
