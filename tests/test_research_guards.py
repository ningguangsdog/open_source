from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from apk_pipeline.code_ownership import (
    classify_code_ownership,
    classify_native_ownership,
)
from apk_pipeline.phase2_jadx import _detect_managed_code_coverage
from apk_pipeline.result_validation import _reuse_regression_check
from apk_pipeline.reuse_regression import (
    build_regression_report,
    load_regression_labels,
)
from apk_pipeline.source_candidate_policy import (
    annotate_source_policy,
    effective_source_role,
    source_analysis_lane,
)


class SourceProvenanceTests(unittest.TestCase):
    def test_ed_lib_is_an_upstream_implementation_candidate(self) -> None:
        source = {
            "repository_full_name": "CihanTopal/ED_Lib",
            "source_path": "EDLineDetector.cpp",
            "function_name": "EDLineDetector",
            "candidate_role": "method_control",
            "ownership_class": "project_owned_candidate",
            "line_count": 4,
        }

        role, reason = effective_source_role(source)
        annotated = annotate_source_policy(source)

        self.assertEqual(role, "upstream_candidate")
        self.assertEqual(reason, "curated_source_provenance_override")
        self.assertEqual(source_analysis_lane(source), "adaptation")
        self.assertEqual(
            annotated["canonical_upstream_project"], "CihanTopal/ED_Lib"
        )
        self.assertEqual(
            annotated["source_origin_class"], "project_owned_upstream"
        )

    def test_opencv_binding_in_demo_is_attributed_to_opencv(self) -> None:
        source = {
            "repository_full_name": "example/AndroidScannerDemo",
            "source_path": (
                "scanlibrary/src/main/jni/sdk/java/src/org/opencv/"
                "imgproc/Imgproc.java"
            ),
            "function_name": "createLineSegmentDetector",
            "candidate_role": "method_control",
            "ownership_class": "vendored_or_external",
            "line_count": 12,
        }

        annotated = annotate_source_policy(source)

        self.assertEqual(annotated["carrier_project"], source["repository_full_name"])
        self.assertEqual(annotated["canonical_upstream_project"], "opencv/opencv")
        self.assertEqual(
            annotated["source_origin_class"], "generated_dependency_binding"
        )
        self.assertEqual(source_analysis_lane(source), "usage")

    def test_pdfium_is_not_treated_as_unknown_first_party_code(self) -> None:
        result = classify_native_ownership("libpdfium.so", None)
        self.assertEqual(result.category, "third_party")
        self.assertGreaterEqual(result.confidence, 0.9)

    def test_vendor_component_precedes_app_jni_namespace(self) -> None:
        result = classify_native_ownership(
            "libPDFNetC.so",
            None,
            app_package="com.xodo.pdf.reader",
            jni_symbols=["Java_com_xodo_pdf_reader_PDFNet_initialize"],
        )

        self.assertEqual(result.category, "third_party")
        self.assertEqual(result.vendor, "Apryse")
        self.assertEqual(result.component, "PDFNet SDK")
        self.assertEqual(result.attribution_kind, "vendor_component_registry")

    def test_conditional_component_requires_cross_layer_corroboration(self) -> None:
        unconfirmed = classify_native_ownership(
            "libdatastore_shared_counter.so",
            None,
        )
        confirmed = classify_native_ownership(
            "libdatastore_shared_counter.so",
            None,
            evidence_tokens=["androidx.datastore.core.SharedCounter"],
        )

        self.assertEqual(unconfirmed.category, "unknown")
        self.assertEqual(
            unconfirmed.attribution_kind, "unconfirmed_component_name"
        )
        self.assertEqual(confirmed.category, "third_party")
        self.assertEqual(confirmed.vendor, "AndroidX")

    def test_opencv_native_vendor_path_is_attributed_to_upstream(self) -> None:
        source = {
            "repository_full_name": "example/ScannerApp",
            "source_path": "third_party/opencv/modules/imgproc/src/lsd.cpp",
            "function_name": "LineSegmentDetectorImpl::detect",
            "candidate_role": "upstream_candidate",
            "ownership_class": "vendored_or_external",
        }

        annotated = annotate_source_policy(source)

        self.assertEqual(annotated["canonical_upstream_project"], "opencv/opencv")
        self.assertEqual(annotated["source_origin_class"], "vendored_dependency")
        self.assertEqual(source_analysis_lane(source), "usage")

    def test_unrelated_modules_path_is_not_assigned_to_opencv(self) -> None:
        source = {
            "repository_full_name": "example/ImageProject",
            "source_path": "modules/imgproc/src/custom_filter.cpp",
            "function_name": "custom_filter",
            "ownership_class": "project_owned_candidate",
        }

        annotated = annotate_source_policy(source)

        self.assertEqual(
            annotated["canonical_upstream_project"], "example/ImageProject"
        )

    def test_apryse_managed_namespace_is_attributed_to_pdfnet(self) -> None:
        result = classify_code_ownership(
            "com.pdftron.pdf",
            "sources/com/pdftron/pdf/Rect.java",
            app_package="com.xodo.pdf.reader",
        )

        self.assertEqual(result.category, "third_party")
        self.assertEqual(result.vendor, "Apryse")
        self.assertEqual(result.component, "PDFNet SDK")
        self.assertEqual(result.attribution_kind, "managed_component_registry")

    def test_osano_managed_namespace_is_attributed_to_sdk(self) -> None:
        result = classify_code_ownership(
            "com.osano.mobile_sdk",
            "sources/com/osano/mobile_sdk/ConsentManager.java",
            app_package="com.example.reader",
        )

        self.assertEqual(result.category, "third_party")
        self.assertEqual(result.vendor, "Osano")

    def test_exact_application_package_precedes_component_registry(self) -> None:
        result = classify_code_ownership(
            "com.pdftron.custom.reader",
            "sources/com/pdftron/custom/reader/Main.java",
            app_package="com.pdftron.custom.reader",
        )

        self.assertEqual(result.category, "first_party")


class ManagedCodeCoverageTests(unittest.TestCase):
    def test_shell_loader_is_reported_as_a_coverage_boundary(self) -> None:
        coverage = _detect_managed_code_coverage(
            [
                {
                    "package": "s.h.e.l.l",
                    "path_inferred_package": "s.h.e.l.l",
                    "class_names": ["S", "N"],
                }
            ],
            Counter({"exec": 1, "execmain": 1}),
        )

        self.assertTrue(coverage["protected_shell_detected"])
        self.assertEqual(
            coverage["business_logic_visibility"], "likely_incomplete"
        )

    def test_ordinary_managed_code_is_not_flagged(self) -> None:
        coverage = _detect_managed_code_coverage(
            [
                {
                    "package": "com.example.reader",
                    "path_inferred_package": "com.example.reader",
                    "class_names": ["ReaderActivity"],
                }
            ],
            Counter({"reader": 1}),
        )

        self.assertFalse(coverage["protected_shell_detected"])
        self.assertEqual(coverage["classification"], "not_detected")


class ReuseRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = {
            "rank": 7,
            "retrieval_score": 0.81,
            "commercial": {
                "library": "libscanner.so",
                "function_name": "EDLineDetector",
            },
            "source": {
                "repository_full_name": "CihanTopal/ED_Lib",
                "function_name": "EDLineDetector",
            },
        }
        self.labels = {
            "known_positives": [
                {
                    "id": "ed-line-known-positive",
                    "commercial_pattern": "EDLineDetector",
                    "source_pattern": "CihanTopal/ED_Lib",
                }
            ],
            "negative_controls": [],
        }

    def test_known_positive_retrieval_passes(self) -> None:
        report = build_regression_report([self.candidate], self.labels)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["known_positive_recall"], 1.0)

    def test_missing_known_positive_fails(self) -> None:
        report = build_regression_report([], self.labels)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["known_positive_recall"], 0.0)

    def test_empty_positive_label_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "labels.json"
            path.write_text(
                json.dumps({"known_positives": [], "negative_controls": []}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_regression_labels(path)

    def test_strict_failed_regression_is_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            phase3 = workspace / "phase3_native"
            phase3.mkdir()
            (phase3 / "reuse_regression.json").write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "known_positive_count": 1,
                        "known_positive_hit_count": 0,
                    }
                ),
                encoding="utf-8",
            )

            check = _reuse_regression_check(
                workspace,
                required=True,
                strict=True,
            )

            self.assertIsNotNone(check)
            self.assertEqual(check["status"], "failed")
            self.assertTrue(check["blocking"])


if __name__ == "__main__":
    unittest.main()
