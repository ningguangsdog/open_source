# APK Research Pipeline

This repository contains a staged pipeline for extracting research evidence from Android app packages. It supports regular `.apk` files and split/bundle formats such as `.apkm`, `.apks`, and `.xapk`.

The pipeline is designed for app-level capability review across many Android applications. It is not tied to a single vendor or sample.

## Pipeline Stages

1. `phase0_split_inventory`
   - Resolves APK bundles into concrete APK files.
   - Classifies base APKs, ABI splits, density splits, language/config splits, and dynamic feature modules.
   - Records hashes, dex presence, native libraries, model files, and high-value resource candidates.

2. `phase1_manifest`
   - Extracts package identity, version metadata, SDK levels, permissions, and Android components.
   - Writes a base manifest summary and a split-level manifest summary.

3. `phase2_jadx`
   - Runs JADX on all dex-bearing splits by default.
   - Builds a code index with capability signals, native method declarations, `System.loadLibrary` calls, URLs, imports, and short source snippets.
   - Emits Java evidence units and a package-level index for downstream review.

4. `phase3_native`
   - Extracts native `.so` libraries from all native-bearing APK splits.
   - Collects strings, exported symbols, JNI symbols, URLs, and capability signals.
   - Ranks high-value native targets automatically and writes a native function index.
   - Writes a native toolchain preflight, decompile plan, function-level feature stream, string/xref view, and lightweight call graph.
   - In the default `--native-depth auto` mode, optional pseudocode and function features are attempted only when high-value targets and a supported native decompiler are available.

5. `phase4_resources`
   - Inventories local models, rule files, dictionaries, OCR assets, and other high-value resources.
   - Extracts conservative model metadata from visible file content, including TFLite magic markers, operator/name hints, and string samples.
   - Emits separate model and resource evidence units.

6. `phase5_evidence`
   - Produces a compact review packet from the previous stages.
   - Emits a JSONL evidence-unit stream, an app-level evidence graph, a Java/native bridge map, and a similarity-ready packet.
   - Similarity scoring is intentionally left out of this stage.

## Quick Start

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Run the pipeline:

```bash
python scripts/run_pipeline.py \
  --apk path/to/app.apk \
  --workspace ./apk_workspace \
  --force
```

For APK bundles:

```bash
python scripts/run_pipeline.py \
  --apk path/to/app.apkm \
  --workspace ./apk_workspace \
  --force
```

Check native deep-analysis tool availability without running an APK:

```bash
python scripts/run_pipeline.py --native-preflight-only
```

For Colab-style environments, install or check native tools before the main run:

```bash
bash scripts/setup_native_tools_colab.sh
python scripts/run_pipeline.py --native-preflight-only
```

## Useful Options

- `--no-decompile-all-splits`: only run JADX on the primary APK.
- `--native-depth none`: skip native target ranking and optional native decompiler calls.
- `--native-depth basic`: extract native metadata and ranked targets without decompiler attempts.
- `--native-depth targeted`: extract native metadata, rank targets, and emit native evidence units.
- `--native-depth auto`: default mode; rank native targets and automatically attempt pseudocode/function-feature extraction only when the target score and local tool availability justify it.
- `--native-depth deep`: force a pseudocode/function-feature attempt for selected native targets if a supported tool is available.
- `--native-decompiler auto|none|rizin|radare2|ghidra|retdec`: select the optional native decompiler adapter.
- `--native-preflight-only`: print native tool availability and exit.
- `--native-max-libraries`: cap the number of native libraries selected for deeper review.
- `--native-max-decompile-targets`: cap the number of native targets sent to the optional decompiler.
- `--native-target-capabilities`: prioritize one or more capability names during native target selection.
- `--no-resource-scan`: skip raw model/resource inventory.
- `--no-evidence-packets`: skip the final review packet.
- `--no-jadx-download`: require a preinstalled `jadx` binary instead of downloading it.

## Main Outputs

After a successful run, the workspace contains:

```text
apk_workspace/
  phase0_split_inventory/split_inventory.json
  phase1_manifest/manifest_summary.json
  phase1_manifest/split_manifest_summary.json
  phase2_jadx/jadx_summary.json
  phase2_jadx/code_index.json
  phase2_jadx/java_evidence_units.json
  phase2_jadx/java_package_index.json
  phase3_native/native_analysis.json
  phase3_native/native_targets.json
  phase3_native/native_toolchain.json
  phase3_native/native_decompile_plan.json
  phase3_native/native_decompilation.json
  phase3_native/native_function_index.json
  phase3_native/native_function_features.jsonl
  phase3_native/native_string_xrefs.json
  phase3_native/native_callgraph.json
  phase3_native/probes/<profile>/native_probe_summary.json
  phase3_native/probes/<profile>/native_probe_review_units.jsonl
  phase3_native/native_evidence_units.json
  phase3_native/native_deep_summary.json
  phase4_resources/resource_inventory.json
  phase4_resources/model_evidence_units.json
  phase4_resources/resource_evidence_units.json
  phase5_evidence/review_packet.md
  phase5_evidence/review_packet.json
  phase5_evidence/review_prompt.md
  phase5_evidence/evidence_units.jsonl
  phase5_evidence/evidence_graph.json
  phase5_evidence/java_native_bridge_map.json
  phase5_evidence/similarity_ready_packet.json
  run_manifest.json
  pipeline_summary.json
```

The most useful files for review are usually:

- `phase5_evidence/review_packet.md`
- `phase5_evidence/evidence_units.jsonl`
- `phase5_evidence/similarity_ready_packet.json`
- `phase2_jadx/code_index.json`
- `phase2_jadx/java_evidence_units.json`
- `phase3_native/native_targets.json`
- `phase3_native/native_function_index.json`
- `phase3_native/native_toolchain.json`
- `phase3_native/native_decompile_plan.json`
- `phase3_native/native_function_features.jsonl`
- `phase3_native/native_string_xrefs.json`
- `phase3_native/native_callgraph.json`
- `phase3_native/probes/<profile>/native_probe_summary.json`
- `phase3_native/probes/<profile>/native_probe_review_units.jsonl`
- `phase4_resources/resource_inventory.json`
- `phase5_evidence/java_native_bridge_map.json`

## Native Deep Analysis

JADX decompiles Dalvik bytecode and does not decompile native `.so` libraries. Native code requires a binary analysis tool. The automated native-deep adapter currently supports `rizin` and `radare2`.

In `--native-depth auto`, the pipeline first ranks high-value native targets, writes `phase3_native/native_decompile_plan.json`, and attempts native pseudocode/function-feature extraction only when an automated adapter is available. If no adapter is available, the run still records the missing tool in `phase3_native/native_toolchain.json` and keeps the ranked target plan for follow-up.

Function-level outputs include normalized instruction features, pseudocode fingerprints, basic block counts, string references, call targets, and a lightweight call graph. These are intended as evidence for downstream review and later similarity preparation, not as a complete source reconstruction.

## Focused Native Probes

After a full pipeline run has produced `phase3_native/native_function_index.json`, a focused native-only probe can re-use the workspace and run deeper target selection without rerunning manifest, JADX, or resource extraction.

The initial focused profile is `adobe_acrobat_deep`. It is an experiment profile for Adobe Acrobat samples and is kept separate from the default general pipeline.

```bash
python scripts/run_native_deep_probe.py \
  --workspace ./apk_workspace \
  --profile adobe_acrobat_deep \
  --force
```

The probe writes its results under:

```text
phase3_native/probes/adobe_acrobat_deep/
```

Key probe outputs:

- `native_probe_targets.json`: profile-selected seed targets.
- `native_probe_decompile_plan.json`: decompiler plan and budgets.
- `native_probe_decompilation.json`: target-level decompiler results.
- `native_probe_function_features.jsonl`: function-level features from successful outputs.
- `native_probe_review_units.jsonl`: per-target outcome classification for review.
- `native_probe_summary.json`: summary counts and output paths.

When the probe completes, phase 5 evidence packets are refreshed by default so the probe review units are included in `phase5_evidence/evidence_units.jsonl` and `phase5_evidence/similarity_ready_packet.json`.

## External Tools

The Python dependency list is intentionally small. Some stages use external command-line tools when available:

- `jadx`: Java/Kotlin decompilation. If not installed, the runner can download the configured JADX release.
- `strings`: native string extraction.
- `readelf`, `llvm-readelf`, or `nm`: native symbol extraction.
- `rizin` or `radare2`: optional targeted native pseudocode and function-feature output.

If optional tools are missing, the pipeline records the missing capability in the phase output instead of stopping the whole run.
