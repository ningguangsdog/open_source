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

4. `phase3_native`
   - Extracts native `.so` libraries from all native-bearing APK splits.
   - Collects strings, exported symbols, JNI symbols, URLs, and capability signals.
   - Ranks high-value native targets automatically. If a supported native decompiler is installed, targeted pseudocode output is attempted.

5. `phase4_resources`
   - Inventories local models, rule files, dictionaries, OCR assets, and other high-value resources.
   - Extracts conservative model metadata from visible file content, including TFLite magic markers, operator/name hints, and string samples.

6. `phase5_evidence`
   - Produces a compact review packet from the previous stages.
   - The packet is intended for manual review and downstream research triage. Similarity scoring is intentionally left out of this stage.

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

## Useful Options

- `--no-decompile-all-splits`: only run JADX on the primary APK.
- `--native-depth none`: skip native target ranking and optional native decompiler calls.
- `--native-depth basic`: extract native metadata and ranked targets without decompiler attempts.
- `--native-depth targeted`: extract native metadata, rank targets, and attempt targeted native pseudocode if a supported tool is available.
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
  phase3_native/native_analysis.json
  phase3_native/native_targets.json
  phase4_resources/resource_inventory.json
  phase5_evidence/review_packet.md
  phase5_evidence/review_packet.json
  phase5_evidence/review_prompt.md
  pipeline_summary.json
```

The most useful files for review are usually:

- `phase5_evidence/review_packet.md`
- `phase2_jadx/code_index.json`
- `phase3_native/native_targets.json`
- `phase4_resources/resource_inventory.json`

## External Tools

The Python dependency list is intentionally small. Some stages use external command-line tools when available:

- `jadx`: Java/Kotlin decompilation. If not installed, the runner can download the configured JADX release.
- `strings`: native string extraction.
- `readelf`, `llvm-readelf`, or `nm`: native symbol extraction.
- `rizin` or `radare2`: optional targeted native pseudocode output.

If optional tools are missing, the pipeline records the missing capability in the phase output instead of stopping the whole run.
