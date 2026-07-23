# APK Research Pipeline

This repository contains a staged pipeline for extracting research evidence from Android app packages. It supports regular `.apk` files and split/bundle formats such as `.apkm`, `.apks`, and `.xapk`.

The pipeline is designed for app-level capability review across many Android applications. It is not tied to a single vendor or sample.

## Pipeline Stages

1. `phase0_split_inventory`
   - Resolves APK bundles into concrete APK files.
   - Classifies base APKs, ABI splits, density splits, language/config splits, and dynamic feature modules.
   - Validates each APK archive and its manifest before later phases consume it.
   - Records hashes, dex presence, native libraries, model files, and every matching high-value resource label.

2. `phase1_manifest`
   - Extracts package identity, version metadata, SDK levels, permissions, and Android components.
   - Records field-level parse status, warnings, critical failures, and a weighted completeness score.
   - Writes a base manifest summary and a split-level manifest summary.

3. `phase2_jadx`
   - Runs JADX on all dex-bearing splits by default.
   - Enforces a per-APK timeout while retaining usable partial output from interrupted or non-zero JADX runs.
   - Records generated source counts, diagnostic counts, DEX class counts, and a reproducible coverage proxy.
   - Builds a complete, chunked code index with capability signals, native method declarations, `System.loadLibrary` calls, URLs, imports, and short source snippets.
   - Classifies Java/Kotlin code as first-party, third-party, platform, or unknown. Decompiled XML remains in the complete discovery index but is excluded from Java/Kotlin implementation counts.
   - Complete source metadata remains in the index; snippet limits apply only to the compact review layer.
   - Emits Java evidence units, a package-level index, exact normalized fingerprints, and compact token-shingle signatures for later comparison work.

4. `phase3_native`
   - Extracts native `.so` libraries from all native-bearing APK splits.
   - Collects strings, exported/JNI symbols, ELF addresses and sizes, URLs, and capability signals.
   - Ranks high-value native targets with ABI priority, Java/JNI relationships, model dependencies, call-graph centrality, and conservative wrapper penalties.
   - Keeps the complete callable candidate inventory while building a library-diversified manual review queue.
   - Adds a hash-bound discovery task for every selected library so internal implementations reached from exported JNI wrappers can be returned without pretending they were exported symbols.
   - Writes a native toolchain preflight, decompile plan, function-level feature stream, string/xref view, and lightweight call graph.
   - Produces an identity-bound IDA Classroom task manifest and a portable `ida_handoff.zip` containing a bounded set of ranked binaries.
   - Re-hashes the current extracted binary before accepting manually exported pseudocode and matches the submitted task ID, ABI, symbol, and address.
   - Stores automated `rizin`/`radare2` evidence separately from manual IDA evidence. Producing pseudocode does not by itself establish that a core algorithm was recovered.
   - Attributes native libraries using application JNI prefixes, conservative known-runtime names, and optional SHA-256 registries. Ambiguous product-specific names remain `unknown` and stay in comparison evidence.
   - In the recommended `--profile ida-handoff` workflow, target ranking runs without invoking an automated native decompiler.

5. `phase4_resources`
   - Inventories local models, rule files, dictionaries, OCR assets, and other high-value resources.
   - Ranks resource candidates before applying compact-output limits and records discovered, selected, and excluded counts.
   - Parses visible TFLite graph structure when possible, including subgraphs, operators, tensors, inputs, outputs, and a deterministic graph fingerprint.
   - Emits separate model and resource evidence units.

6. `phase5_evidence`
   - Produces a compact review packet from the previous stages.
   - Emits a JSONL evidence-unit stream, an app-level evidence graph, a Java/native bridge map, and a similarity-preparation packet.
   - Keeps capability counts separated by phase because Java files, native strings, model resources, and split tags use different denominators.
   - Excludes third-party and platform Java/native evidence from comparison-facing capability counts by default while reporting dependency evidence separately.
   - Similarity scoring is intentionally left out of this stage.

## Quick Start

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Run the complete extraction and IDA handoff workflow:

```bash
python scripts/run_pipeline.py \
  --apk path/to/app.apk \
  --workspace ./runs \
  --isolated-workspace \
  --profile ida-handoff \
  --force
```

`--isolated-workspace` treats `--workspace` as a run root and stores results under
`<workspace>/<input-name>/<input-sha-prefix>/`. This mode is recommended when
processing multiple apps or app versions. Without the flag, `--workspace`
continues to refer to an exact output directory. An exact workspace cannot be
reused for different APK content.

For APK bundles:

```bash
python scripts/run_pipeline.py \
  --apk path/to/app.apkm \
  --workspace ./runs \
  --isolated-workspace \
  --profile ida-handoff \
  --force
```

The `ida-handoff` profile does not require `rizin` or `radare2`. It completes
Phase 0-5, ranks native targets, and writes
`phase3_native/ida_handoff.zip` for manual IDA Classroom review.

## Useful Options

- `--no-decompile-all-splits`: only run JADX on the primary APK.
- `--jadx-timeout-per-apk`: set the timeout for each dex-bearing APK or split; partial source is retained.
- `--isolated-workspace`: create a content-addressed workspace for each APK or bundle.
- `--profile ida-handoff`: run the formal extraction and manual IDA handoff workflow without automated native decompilation.
- `--native-depth none`: skip native target ranking and optional native decompiler calls.
- `--native-depth basic`: extract native metadata and ranked targets without decompiler attempts.
- `--native-depth targeted`: extract native metadata, rank targets, and emit native evidence units.
- `--native-depth auto`: default mode; rank native targets and automatically attempt pseudocode/function-feature extraction only when the target score and local tool availability justify it.
- `--native-depth deep`: force a pseudocode/function-feature attempt for selected native targets if a supported tool is available.
- `--native-decompiler auto|none|rizin|radare2|ghidra|retdec`: select the optional native decompiler adapter.
- `--native-preflight-only`: print native tool availability and exit.
- `--native-max-libraries`: cap the number of native libraries selected for deeper review.
- `--native-max-decompile-targets`: cap the number of native targets sent to the optional decompiler.
- `--ida-review-limit`: cap the priority IDA review queue; the complete candidate inventory remains in the manifest.
- `--ida-handoff-max-libraries`: cap the number of unique library/ABI binaries copied into `ida_handoff.zip`.
- `--native-target-capabilities`: prioritize one or more capability names during native target selection.
- `--no-resource-scan`: skip raw model/resource inventory.
- `--no-evidence-packets`: skip the final review packet.
- `--no-jadx-download`: require a preinstalled `jadx` binary instead of downloading it.
- `--first-party-prefixes`: add comma-separated first-party Java/Kotlin package prefixes.
- `--third-party-prefixes`: add comma-separated dependency package prefixes.
- `--first-party-native-hashes`: add comma-separated first-party native SHA-256 values.
- `--third-party-native-hashes`: add comma-separated dependency native SHA-256 values.

## Main Outputs

After a successful run, the workspace contains:

```text
apk_workspace/
  run_context.json
  run_manifest.json
  pipeline_summary.json
  run_records/<run-id>.json
  phase0_split_inventory/cache_manifest.json
  phase0_split_inventory/split_inventory.json
  phase1_manifest/cache_manifest.json
  phase1_manifest/manifest_summary.json
  phase1_manifest/split_manifest_summary.json
  phase2_jadx/cache_manifest.json
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
  phase3_native/ida_target_manifest.json
  phase3_native/ida_handoff.zip
  phase3_native/ida_handoff/ida_handoff_manifest.json
  phase3_native/ida_handoff/review_queue.csv
  phase3_native/manual_ida/README.txt
  phase3_native/manual_ida/result_template.json
  phase3_native/manual_ida/results/
  phase3_native/manual_ida/import_summary.json
  phase3_native/manual_ida/evidence_units.json
  phase3_native/probes/<profile>/native_probe_summary.json
  phase3_native/probes/<profile>/native_probe_review_units.jsonl
  phase3_native/native_evidence_units.json
  phase3_native/native_deep_summary.json
  phase4_resources/cache_manifest.json
  phase4_resources/resource_inventory.json
  phase4_resources/model_evidence_units.json
  phase4_resources/resource_evidence_units.json
  phase5_evidence/review_packet.md
  phase5_evidence/review_packet.json
  phase5_evidence/review_prompt.md
  phase5_evidence/evidence_units.jsonl
  phase5_evidence/evidence_graph.json
  phase5_evidence/java_native_bridge_map.json
  phase5_evidence/similarity_preparation_packet.json
  phase5_evidence/similarity_ready_packet.json
  phase5_evidence/cache_manifest.json
```

`run_context.json` records the current execution ID, stable analysis ID, input
hashes, analysis configuration hash, pipeline revision, Python/package versions,
and detected external toolchain. `run_records/` preserves one status record for
each invocation, including runs that were interrupted after initialization.
Each phase cache manifest binds its outputs to the input, relevant configuration,
upstream artifacts, and output hashes. A cached phase is reused only when all of
those values still match.

Phase results use four statuses:

- `success`: required work completed and outputs passed validation.
- `partial`: usable artifacts were produced, but some required work or inputs failed.
- `failed`: the phase could not produce a complete required result.
- `skipped`: the phase was intentionally not run.

Phase 5 includes an evidence-completeness section. Missing, invalid, or
non-success upstream evidence prevents the final packet from being marked
successful.

`phase2_jadx/code_index.json` is the complete source metadata index. It records
all discovered Java, Kotlin, and decompiled XML files, including read failures
and explicit snippet-selection telemetry. `phase5_evidence/review_packet.json`
is intentionally compact. For comparison preparation, first-party and unknown
code are included by default; third-party and platform signals are retained in
separate attribution and dependency sections. The compact similarity-preparation
packet uses stratified sampling across phases, evidence kinds, and capabilities;
its selection telemetry points back to the complete JSONL evidence stream.
`similarity_ready_packet.json` remains as a compatibility alias for existing
notebooks.

The most useful files for review are usually:

- `phase5_evidence/review_packet.md`
- `phase5_evidence/evidence_units.jsonl`
- `phase5_evidence/similarity_preparation_packet.json`
- `phase2_jadx/code_index.json`
- `phase2_jadx/java_evidence_units.json`
- `phase3_native/native_targets.json`
- `phase3_native/native_function_index.json`
- `phase3_native/native_toolchain.json`
- `phase3_native/native_decompile_plan.json`
- `phase3_native/native_function_features.jsonl`
- `phase3_native/native_string_xrefs.json`
- `phase3_native/native_callgraph.json`
- `phase3_native/ida_target_manifest.json`
- `phase3_native/ida_handoff.zip`
- `phase3_native/manual_ida/import_summary.json`
- `phase3_native/manual_ida/evidence_units.json`
- `phase3_native/probes/<profile>/native_probe_summary.json`
- `phase3_native/probes/<profile>/native_probe_review_units.jsonl`
- `phase4_resources/resource_inventory.json`
- `phase5_evidence/java_native_bridge_map.json`

## Optional Native Deep Analysis

JADX decompiles Dalvik bytecode and does not decompile native `.so` libraries. Native code requires a binary analysis tool. The automated native-deep adapter currently supports `rizin` and `radare2`.

In `--native-depth auto`, the pipeline first ranks high-value native targets, writes `phase3_native/native_decompile_plan.json`, and attempts native pseudocode/function-feature extraction only when an automated adapter is available. If no adapter is available, the run still records the missing tool in `phase3_native/native_toolchain.json` and keeps the ranked target plan for follow-up.

Function-level outputs include normalized instruction features, pseudocode fingerprints, basic block counts, string references, call targets, and a lightweight call graph. These are intended as evidence for downstream review and later similarity preparation, not as a complete source reconstruction.

## Manual IDA Classroom Review

Start with `phase3_native/ida_handoff.zip`. It contains the selected `.so`
files, `review_queue.csv`, a handoff manifest, and the complete task manifest.
ARM64 production libraries are prioritized; x86 and x86_64 variants are
retained for cross-validation. The complete candidate inventory remains in
`phase3_native/ida_target_manifest.json`.

For each reviewed function:

1. Save the pseudocode as UTF-8 text under
   `phase3_native/manual_ida/results/`.
2. Create a JSON metadata file from
   `phase3_native/manual_ida/result_template.json`.
3. Copy the exact task ID, library SHA-256, ABI, function address, symbol, and
   IDA version from the task and IDA database.
4. Import and refresh the final evidence packet:

```bash
python scripts/import_ida_results.py \
  --workspace ./apk_workspace \
  --refresh-phase5
```

The importer re-hashes the current extracted library and rejects results whose
task ID, ABI, symbol, or address does not match the handoff. A
`library_discovery` task may be used for an internal function found while
following an exported wrapper; its binary hash, ABI, task ID, and internal
address are still required. Accepted functions are labeled independently as
`wrapper`, `orchestration`, `algorithm`,
`model_runtime`, `utility`, or `uncertain`. `decompiled=true` records
pseudocode production. `algorithm_body_candidate=true` is a heuristic flag;
`algorithm_recovered` remains false until research review confirms that the
body is substantive.

## Experimental Focused Native Probes

After a full pipeline run has produced `phase3_native/native_function_index.json`, a focused native-only probe can re-use the workspace and run deeper target selection without rerunning manifest, JADX, or resource extraction.

The initial focused profile is `adobe_acrobat_deep`. It is an experiment profile for Adobe Acrobat samples and is kept separate from the default general pipeline.

```bash
python scripts/run_native_deep_probe.py \
  --workspace ./apk_workspace \
  --profile adobe_acrobat_deep \
  --force
```

Focused probes print live progress by default. The Adobe profile starts with `pseudocode` detail, which runs one native decompiler pass per selected target before refreshing the phase 5 evidence packet. Use `--native-feature-detail standard` or `--native-feature-detail full` when more disassembly, CFG, or xref detail is needed after the first pass.

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

When the probe completes, phase 5 evidence packets are refreshed by default so
the probe review units are included in `phase5_evidence/evidence_units.jsonl`
and the similarity-preparation packet.

## External Tools

The Python dependency list includes Androguard and the generated TFLite schema
package. Some stages use external command-line tools when available:

- `jadx`: Java/Kotlin decompilation. If not installed, the runner can download the configured JADX release.
- `strings`: native string extraction.
- `readelf`, `llvm-readelf`, or `nm`: native symbol extraction.
- `rizin` or `radare2`: optional targeted native pseudocode and function-feature output.

The `ida-handoff` profile uses `strings` and an ELF symbol utility when
available; these are normally present in standard Colab runtimes. If symbol
tools are unavailable, the library-level discovery tasks remain usable.
Optional decompiler tools are not installed or invoked by that profile.
