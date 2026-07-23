from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apk_pipeline.input_resolver import resolve_apk_input
from apk_pipeline.evidence import token_shingle_signature
from apk_pipeline.models import PhaseResult, PipelineSummary
from apk_pipeline.phase0_split_inventory import run_phase0
from apk_pipeline.phase2_jadx import run_phase2_multi
from apk_pipeline.phase5_evidence import run_phase5_evidence
from apk_pipeline.run_context import (
    WorkspaceIdentityMismatchError,
    assert_workspace_identity,
    assert_workspace_original_input,
    build_run_context,
    build_phase_cache_spec,
    cached_phase_result,
    isolated_workspace_path,
    load_valid_phase_cache,
    write_run_context,
    write_phase_cache,
)
from apk_pipeline.utils import (
    is_safe_zip_member,
    safe_write_json,
    safe_write_text,
)


class RunIntegrityTests(unittest.TestCase):
    def test_token_shingle_signature_is_stable_across_literal_changes(self) -> None:
        first = token_shingle_signature(
            "int score = pixels[12] * weights[99]; return score;"
        )
        second = token_shingle_signature(
            "int score = pixels[42] * weights[7]; return score;"
        )
        self.assertEqual(first["hashes"], second["hashes"])
        self.assertGreater(first["retained_hash_count"], 0)

    def test_partial_phase_is_not_legacy_success(self) -> None:
        result = PhaseResult(
            name="example",
            success=True,
            status="partial",
        )
        self.assertFalse(result.success)
        self.assertEqual(result.to_dict()["status"], "partial")

    def test_skipped_optional_phase_does_not_fail_pipeline(self) -> None:
        summary = PipelineSummary(
            apk_filename="sample.apk",
            workspace="/tmp/sample",
            phases=[
                PhaseResult(name="required", success=True),
                PhaseResult(name="optional", success=False, status="skipped"),
            ],
        )
        self.assertTrue(summary.to_dict()["all_success"])

    def test_atomic_writes_replace_complete_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            text_path = root / "artifact.txt"
            json_path = root / "artifact.json"
            safe_write_text(text_path, "first")
            safe_write_text(text_path, "second")
            safe_write_json(json_path, {"complete": True})
            self.assertEqual(text_path.read_text(encoding="utf-8"), "second")
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), {"complete": True})
            self.assertFalse(any(path.name.endswith(".tmp") for path in root.iterdir()))

    def test_phase_cache_validates_key_and_output_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "sample.apk"
            output_path = root / "phase" / "output.json"
            manifest_path = root / "phase" / "cache_manifest.json"
            input_path.write_bytes(b"apk-v1")
            safe_write_json(output_path, {"value": 1})
            spec_v1 = build_phase_cache_spec(
                phase="example",
                phase_schema="v1",
                phase_config={"mode": "full"},
                input_paths=[input_path],
            )
            result = PhaseResult(name="example", success=True, output_paths=[output_path])
            write_phase_cache(manifest_path, spec_v1, [output_path], result)

            cached = load_valid_phase_cache(manifest_path, spec_v1, [output_path])
            self.assertIsNotNone(cached)
            restored = cached_phase_result("example", [output_path], cached or {})
            self.assertTrue(restored.success)
            self.assertTrue(restored.details["cached"])

            safe_write_json(output_path, {"value": 2})
            self.assertIsNone(load_valid_phase_cache(manifest_path, spec_v1, [output_path]))

            input_path.write_bytes(b"apk-v2")
            spec_v2 = build_phase_cache_spec(
                phase="example",
                phase_schema="v1",
                phase_config={"mode": "full"},
                input_paths=[input_path],
            )
            self.assertNotEqual(spec_v1["cache_key"], spec_v2["cache_key"])
            spec_v3 = build_phase_cache_spec(
                phase="example",
                phase_schema="v1",
                phase_config={"mode": "light"},
                input_paths=[input_path],
            )
            self.assertNotEqual(spec_v2["cache_key"], spec_v3["cache_key"])

    def test_phase_cache_changes_with_runtime_tooling(self) -> None:
        base_context = {
            "input": {"fingerprint": "apk-fingerprint"},
            "pipeline": {
                "git_commit": "abc123",
                "source_tree_hash": "source-hash",
            },
            "runtime": {
                "python": "3.12.0",
                "external_tools": {"jadx": {"version": "1.5.0"}},
            },
        }
        updated_context = json.loads(json.dumps(base_context))
        updated_context["runtime"]["external_tools"]["jadx"]["version"] = "1.5.1"
        first = build_phase_cache_spec(
            phase="phase2_jadx",
            phase_schema="v1",
            phase_config={},
            run_context=base_context,
        )
        second = build_phase_cache_spec(
            phase="phase2_jadx",
            phase_schema="v1",
            phase_config={},
            run_context=updated_context,
        )
        self.assertNotEqual(first["cache_key"], second["cache_key"])

    def test_run_identity_separates_analysis_from_execution(self) -> None:
        config = {
            "apk_path": "/tmp/sample.apk",
            "workspace": "/tmp/runs",
            "force": False,
        }
        input_identity = {"fingerprint": "input-fingerprint"}
        with (
            patch("apk_pipeline.run_context._external_tool_versions", return_value={}),
            patch(
                "apk_pipeline.run_context._git_revision",
                return_value={"commit": "abc123", "dirty": False},
            ),
            patch(
                "apk_pipeline.run_context._source_tree_hash",
                return_value="source-hash",
            ),
        ):
            first = build_run_context(
                config=config,
                workspace=Path("/tmp/runs/sample"),
                input_identity=input_identity,
                pipeline_version="test",
                repo_root=Path("/tmp/repo"),
                workspace_mode="isolated",
            )
            second = build_run_context(
                config=config,
                workspace=Path("/tmp/runs/sample"),
                input_identity=input_identity,
                pipeline_version="test",
                repo_root=Path("/tmp/repo"),
                workspace_mode="isolated",
            )
        self.assertEqual(first["analysis_id"], second["analysis_id"])
        self.assertNotEqual(first["run_id"], second["run_id"])

    def test_run_context_preserves_per_execution_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            context = {"run_id": "sample-run", "execution_status": "running"}
            write_run_context(workspace, context)
            context["execution_status"] = "completed"
            write_run_context(workspace, context)
            history = json.loads(
                (workspace / "run_records" / "sample-run.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(history["execution_status"], "completed")

    def test_workspace_rejects_different_input_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            safe_write_json(
                workspace / "run_context.json",
                {"input": {"fingerprint": "old"}},
            )
            with self.assertRaises(WorkspaceIdentityMismatchError):
                assert_workspace_identity(workspace, {"fingerprint": "new"})

    def test_workspace_rejects_different_source_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            safe_write_json(
                workspace / "run_context.json",
                {"input": {"original": {"sha256": "old"}}},
            )
            with self.assertRaises(WorkspaceIdentityMismatchError):
                assert_workspace_original_input(workspace, {"sha256": "new"})

    def test_isolated_workspace_is_content_addressed(self) -> None:
        path = isolated_workspace_path(Path("/tmp/runs"), Path("Adobe Reader.apk"), "a" * 64)
        self.assertEqual(path.name, "a" * 12)
        self.assertEqual(path.parent.name, "Adobe_Reader")

    def test_bundle_cache_refreshes_when_source_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bundle = root / "sample.apks"
            workspace = root / "workspace"

            with zipfile.ZipFile(bundle, "w") as zf:
                zf.writestr("base.apk", b"first")
            first = resolve_apk_input(bundle, workspace)
            self.assertEqual(first.primary_apk.read_bytes(), b"first")

            with zipfile.ZipFile(bundle, "w") as zf:
                zf.writestr("base.apk", b"second")
            second = resolve_apk_input(bundle, workspace)
            self.assertEqual(second.primary_apk.read_bytes(), b"second")

    def test_bundle_cache_restores_missing_split_and_accepts_uppercase_apk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bundle = root / "sample.apks"
            workspace = root / "workspace"
            with zipfile.ZipFile(bundle, "w") as zf:
                zf.writestr("BASE.APK", b"base")
                zf.writestr("splits/config.ARM64_V8A.APK", b"abi")

            first = resolve_apk_input(bundle, workspace)
            self.assertEqual(first.primary_apk.name, "BASE.APK")
            self.assertEqual(len(first.all_apks), 2)
            split = next(path for path in first.all_apks if path.name != "BASE.APK")
            split.unlink()

            second = resolve_apk_input(bundle, workspace)
            self.assertEqual(len(second.all_apks), 2)
            self.assertTrue(
                any(path.name == "config.ARM64_V8A.APK" for path in second.all_apks)
            )

    def test_regular_apk_is_not_reclassified_by_nested_apk_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk = root / "sample.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"manifest")
                zf.writestr("assets/archive.apk", b"not-a-split")
            resolved = resolve_apk_input(apk, root / "workspace")
            self.assertEqual(resolved.input_type, "apk")
            self.assertEqual(resolved.primary_apk, apk.resolve())

    def test_zip_member_validation_rejects_cross_platform_traversal(self) -> None:
        self.assertFalse(is_safe_zip_member("../escape"))
        self.assertFalse(is_safe_zip_member("..\\escape"))
        self.assertFalse(is_safe_zip_member("/absolute/path"))
        self.assertFalse(is_safe_zip_member("C:/absolute/path"))
        self.assertTrue(is_safe_zip_member("splits/base.apk"))

    def test_phase0_rejects_bad_primary_apk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "broken.apk"
            apk_path.write_bytes(b"not-an-apk")
            result = run_phase0([apk_path], apk_path, root / "workspace")
            self.assertEqual(result.status, "failed")
            self.assertFalse(result.success)

    def test_phase2_failed_tool_setup_writes_a_validated_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "sample.apk"
            workspace = root / "workspace"
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("classes.dex", b"dex\n035\x00")
            with patch(
                "apk_pipeline.phase2_jadx._ensure_jadx",
                side_effect=RuntimeError("jadx unavailable"),
            ):
                first = run_phase2_multi(
                    apk_path,
                    [apk_path],
                    workspace,
                    no_jadx_download=True,
                )
            self.assertEqual(first.status, "failed")
            self.assertTrue(
                (workspace / "phase2_jadx" / "cache_manifest.json").is_file()
            )
            with patch(
                "apk_pipeline.phase2_jadx._ensure_jadx",
                side_effect=AssertionError("validated cache should be restored"),
            ):
                second = run_phase2_multi(
                    apk_path,
                    [apk_path],
                    workspace,
                    no_jadx_download=True,
                )
            self.assertEqual(second.status, "failed")
            self.assertTrue(second.details["cached"])

    def test_phase5_empty_workspace_is_failed_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            result = run_phase5_evidence(workspace)
            packet = json.loads(
                (workspace / "phase5_evidence" / "review_packet.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result.status, "failed")
            self.assertFalse(result.success)
            self.assertEqual(packet["completeness"]["status"], "incomplete")
            self.assertGreater(len(packet["completeness"]["missing_sources"]), 0)

    def test_phase5_propagates_partial_upstream_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            required_payloads = {
                "phase0_split_inventory/split_inventory.json": {},
                "phase1_manifest/manifest_summary.json": {},
                "phase2_jadx/code_index.json": {},
                "phase2_jadx/java_evidence_units.json": [],
                "phase3_native/native_analysis.json": {},
                "phase3_native/native_evidence_units.json": [],
            }
            for relative_path, payload in required_payloads.items():
                safe_write_json(workspace / relative_path, payload)
            upstream = [
                PhaseResult(name="phase0_split_inventory", success=True),
                PhaseResult(
                    name="phase1_manifest",
                    success=False,
                    status="partial",
                ),
                PhaseResult(name="phase2_jadx", success=True),
                PhaseResult(name="phase3_native", success=True),
            ]
            result = run_phase5_evidence(
                workspace,
                upstream_results=upstream,
                require_resources=False,
            )
            packet = json.loads(
                (workspace / "phase5_evidence" / "review_packet.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result.status, "partial")
            self.assertEqual(
                packet["completeness"]["non_success_upstream"],
                {"phase1_manifest": "partial"},
            )

    def test_phase5_treats_missing_upstream_status_as_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            required_payloads = {
                "phase0_split_inventory/split_inventory.json": {},
                "phase1_manifest/manifest_summary.json": {},
                "phase2_jadx/code_index.json": {},
                "phase2_jadx/java_evidence_units.json": [],
                "phase3_native/native_analysis.json": {},
                "phase3_native/native_evidence_units.json": [],
            }
            for relative_path, payload in required_payloads.items():
                safe_write_json(workspace / relative_path, payload)
            result = run_phase5_evidence(workspace, require_resources=False)
            packet = json.loads(
                (workspace / "phase5_evidence" / "review_packet.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result.status, "partial")
            self.assertEqual(
                set(packet["completeness"]["non_success_upstream"].values()),
                {"unknown"},
            )

    def test_phase5_ignores_skipped_optional_resource_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            required_payloads = {
                "phase0_split_inventory/split_inventory.json": {},
                "phase1_manifest/manifest_summary.json": {},
                "phase2_jadx/code_index.json": {},
                "phase2_jadx/java_evidence_units.json": [],
                "phase3_native/native_analysis.json": {},
                "phase3_native/native_evidence_units.json": [],
            }
            for relative_path, payload in required_payloads.items():
                safe_write_json(workspace / relative_path, payload)
            upstream = [
                PhaseResult(name="phase0_split_inventory", success=True),
                PhaseResult(name="phase1_manifest", success=True),
                PhaseResult(name="phase2_jadx", success=True),
                PhaseResult(name="phase3_native", success=True),
                PhaseResult(name="phase4_resources", success=False, status="skipped"),
            ]
            result = run_phase5_evidence(
                workspace,
                upstream_results=upstream,
                require_resources=False,
            )
            self.assertEqual(result.status, "success")


if __name__ == "__main__":
    unittest.main()
