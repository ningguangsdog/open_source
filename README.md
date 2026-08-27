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
   - Writes `java_method_index.jsonl`, a method-level index over every Java/Kotlin body recovered by JADX. Read errors and JADX coverage limits remain explicit.

4. `phase3_native`
   - Extracts native `.so` libraries from all native-bearing APK splits.
   - Collects strings, exported/JNI symbols, ELF addresses and sizes, URLs, and capability signals.
   - Ranks high-value native targets with ABI priority, Java/JNI relationships, model dependencies, call-graph centrality, and conservative wrapper penalties.
   - Keeps the complete callable candidate inventory while building a library-diversified manual review queue.
   - Adds a hash-bound discovery task for every selected library so internal implementations reached from exported JNI wrappers can be returned without pretending they were exported symbols.
   - Writes a native toolchain preflight, decompile plan, function-level feature stream, string/xref view, and lightweight call graph.
   - Can run IDA 9.x through IDALib and Hex-Rays in one isolated subprocess per selected library. Each worker uses a separate `IDAUSR` directory, enforces a hard timeout, writes checkpoints, and can resume completed functions.
   - Expands from ranked Java/JNI and exported-symbol seeds into nearby callers and callees, then ranks internal functions before decompilation. An opened library or generated pseudocode is not labeled as a recovered core algorithm without separate semantic evidence.
   - Produces an identity-bound IDA Classroom task manifest and a portable `ida_handoff.zip` containing a bounded set of ranked binaries.
   - Re-hashes the current extracted binary before accepting manually exported pseudocode and matches the submitted task ID, ABI, symbol, and address.
   - Stores automated IDA, `rizin`, and `radare2` evidence separately from manual IDA evidence. Producing pseudocode does not by itself establish that a core algorithm was recovered.
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

After the phases finish, `pipeline_validation.json` checks whether required IDA jobs completed, whether usable pseudocode was produced, whether library hashes still match the Phase 3 inventory, and whether successful IDA functions reached the Phase 5 evidence stream.

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

## Automated IDA Classroom Run

IDA Classroom 9.4 can be used through its bundled IDALib and Python package. Run the preflight from the machine where IDA is installed and activated:

```bash
python scripts/run_pipeline.py \
  --profile ida-classroom \
  --native-preflight-only \
  --log-level WARNING
```

Then run the complete automated workflow locally:

```bash
python scripts/run_pipeline.py \
  --profile ida-classroom \
  --apk path/to/app.apkm \
  --workspace ./runs \
  --isolated-workspace \
  --log-level WARNING
```

The `ida-classroom` profile selects up to 20 ranked native libraries and distributes a 120-function pseudocode budget across them. It starts from Phase 3 seeds, follows callers and callees to a depth of two, and reports a heartbeat every 20 seconds while a library worker is active. If one Hex-Rays function call exceeds `--native-timeout-per-function`, the watchdog terminates that worker, records the timed-out function, and resumes the remaining functions from checkpoints in a fresh process. Individual function failures are retained in the result. A missing backend, a library identity mismatch, zero usable pseudocode, or failure to propagate IDA evidence into Phase 5 prevents the validation report from declaring the run ready for similarity analysis.

Do not add `--force` when resuming an interrupted IDA run with the same APK and configuration. The worker reuses hash-bound checkpoints and skips completed functions. Use `--force` only when a clean recomputation is intended.

Google Colab cannot invoke an IDA installation running on a Mac. Use `--profile ida-handoff` in Colab, or run the complete `ida-classroom` profile locally. Depending on the license, Classroom decompilers may be cloud based; review the Hex-Rays license and data-handling terms before analyzing binaries that cannot be sent to that service.

## Open-Source Reuse Search

`reuse-search` is an opt-in research profile. It leaves the existing
`standard`, `ida-handoff`, and `ida-classroom` presets unchanged. The profile
builds a lightweight index over all JADX-recovered methods, all methods parsed
directly from the selected DEX files, and every function discovered in each
content-unique native library. Native indexing uses IDA disassembly metadata
and bounded instruction features without calling Hex-Rays for every function.

The complete lightweight index is retained, while known third-party and
platform functions are excluded from proprietary reuse retrieval. First-party
and unattributed functions are searched against a frozen open-source function
corpus. Hex-Rays is then reserved for retrieved native candidates and their
configured caller/callee neighborhood. A run with zero retrieved candidates
is a valid negative retrieval result. Retrieval scores only prioritize review;
they are not copying probabilities or final implementation-similarity scores.
Trivial exact matches in very small functions remain visible in the candidate
file, but are marked as low-information and cannot consume Hex-Rays or OSS
build-queue budget by themselves.

Native ownership uses an auditable precedence order: explicit hash overrides,
platform/runtime rules, high-confidence component rules, the dependency
registry, application JNI namespaces, and finally unknown. Confirmed SDK and
platform libraries remain in dependency and usage evidence but cannot enter an
adaptation claim or targeted IDA queue. A conditional component rule requires
cross-layer corroboration; otherwise it remains an unconfirmed clue rather than
a dependency assignment.

Candidate retention separates three research claims. The `usage` lane records
possible bundled or externally maintained open-source code, the `adaptation`
lane retains project-owned upstream implementations for deeper comparison, and
the `control` lane calibrates common methods, dependencies, siblings, tests,
and demos. Each lane is split again into managed and native representations so
a large Java candidate population cannot displace all native candidates from
the bounded review set. Native Hex-Rays targets are selected from the complete
candidate stream with per-project, per-library, and per-function diversity
constraints; they do not compete with Java methods for one global Top-K.
Managed Java/Kotlin and DEX candidates use a separate bounded deep-comparison
pass over their retained source- and bytecode-level fingerprints. They do not
consume IDA or native-library budget. Audited managed SDK namespaces are
attributed before candidate selection. Confirmed dependencies, platform code,
generated accessors, and low-information methods such as uncorroborated
`hashCode` or `toString` implementations cannot consume the managed deep-review
budget. Project, commercial-class, source-family, and commercial-function caps
are hard limits; the pass leaves budget unused instead of refilling it with
repeated or low-information observations.

Inventory jobs are checkpointed per content-unique library and reused only
when the job configuration and library SHA-256 still match. Retrieval is also
checkpointed, writes its complete audit trail incrementally, and can resume
after interruption. Source projects are shortlisted before function scoring;
duplicate ABI layers and redundant DEX/JADX representations are excluded from
the retrieval projection without deleting their full indexes.

Run locally on the machine with activated IDA Classroom:

```bash
python scripts/run_pipeline.py \
  --profile reuse-search \
  --apk path/to/app.apkm \
  --workspace ./runs \
  --isolated-workspace \
  --oss-function-index ../research/oss_provenance/source_index/output/function_index.jsonl \
  --log-level WARNING
```

The default corpus path is the same `research/oss_provenance` location next
to this repository. Use `--oss-function-index` when the frozen corpus is
stored elsewhere. Primary outputs are:

- `phase2_jadx/java_method_index.jsonl`
- `phase2_jadx/java_method_index_summary.json`
- `phase2_jadx/dex_method_index.jsonl`
- `phase2_jadx/dex_method_index_summary.json`
- `phase3_native/native_full_function_index.jsonl`
- `phase3_native/native_full_callgraph.jsonl`
- `phase3_native/native_full_index_summary.json`
- `phase3_native/reuse_candidates.jsonl`
- `phase3_native/reuse_candidates_review.jsonl`
- `phase3_native/reuse_candidate_selection_summary.json`
- `phase3_native/reuse_candidate_targets.json`
- `phase3_native/reuse_candidate_summary.json`
- `phase3_native/reuse_canonical_implementations.jsonl`
- `phase3_native/reuse_deep_comparisons.jsonl`
- `phase3_native/reuse_deep_comparison_summary.json`
- `phase3_native/managed_reuse_deep_comparisons.jsonl`
- `phase3_native/managed_reuse_deep_comparison_summary.json`

Source rows preserve both the repository that carried the observed file and
the implementation's attributed upstream owner. The fields
`carrier_project`, `canonical_upstream_project`, `canonical_component`, and
`source_origin_rule` prevent generated SDK bindings or vendored dependencies
inside demo applications from being counted as independent project matches.
The attribution rules are deliberately conservative: an unrecognized source
remains attached to its carrier project instead of being reassigned by name
similarity alone.

Phase 2 also records `managed_code_coverage` in `code_index.json`. Conservative
loader-shell signatures mark JADX-visible business-logic coverage as likely
incomplete without failing the run. This boundary does not invalidate native,
DEX, resource, or runtime evidence; it prevents a protected Java/Kotlin shell
from being described as complete application logic.

Candidate-retrieval changes can be checked against an external, frozen set of
known positives and optional negative controls. Start from
`profiles/reuse_regression_labels.example.json`, replace the placeholder
patterns with independently established labels, and run:

```bash
python scripts/run_pipeline.py \
  --profile reuse-search \
  --apk path/to/app.apkm \
  --workspace ./runs \
  --isolated-workspace \
  --oss-function-index ../research/oss_provenance/source_index/output/function_index.jsonl \
  --reuse-regression-labels path/to/frozen_labels.json \
  --strict-reuse-regression \
  --log-level WARNING
```

The optional check runs after retrieval and before Phase 5. In strict mode, a
missing labeled positive blocks research-readiness validation. It measures
retrieval coverage only: a retrieved pair still needs third-party attribution
and deep comparison before it can support a usage or adaptation claim. Normal
APK runs do not load or execute this regression unless the label option is
explicitly supplied.

Before changing production retrieval or deep-comparison rules, evaluate the
four frozen APK workspaces with the cross-APK release gate. Copy
`profiles/reuse_release_gate.example.json`, keep only independently verified
positive and negative conditions, and map each case to an existing completed
workspace:

```bash
python scripts/check_reuse_release_gate.py \
  --contract path/to/reuse_release_gate.json \
  --workspace xodo=path/to/xodo/run \
  --workspace mobipdf=path/to/mobipdf/run \
  --workspace camscanner=path/to/camscanner/run \
  --workspace adobe=path/to/adobe/run \
  --output reuse_release_gate_report.json
```

The gate checks pipeline validity, preservation of known source candidates,
native component attribution, managed dependency leakage, generic-method
leakage, IDA budget boundaries, and copying-conclusion boundaries. It does not
rerun an APK or create new similarity evidence. After all frozen cases pass,
production selection rules should change only for a hard failure, loss of a
known positive, or a documented false positive reproduced by a frozen case.

`reuse_candidates.jsonl` is the complete streamed audit trail.
`reuse_candidates_review.jsonl` contains the bounded, representation-aware
usage, adaptation, and control cohorts used by Phase 5.
`reuse_candidate_selection_summary.json` reports available and retained counts
for every cohort and records whether eligible native candidates were starved.
`reuse_candidate_targets.json` is the authoritative downstream identity ledger
for the bounded IDA queue. It preserves each selected candidate pair, analysis
lane, commercial function, source function, and source project through Phase 5.
Eligible native targets are drawn independently from the complete retrieval
stream for targeted Hex-Rays follow-up.
Every resolved retrieval seed is reserved before call-graph or inventory
context is added. The configured target limit may expand to preserve those
seeds; the IDA summary records requested, resolved, selected, unresolved, and
unselected seed counts. Call-graph neighbors retain a link to the seed that
discovered them, but they are compared under their own function identity.

`reuse_canonical_implementations.jsonl` keeps the original retrieval seed as
the audit entry while recording the substantive comparison body reached through
the saved call graph. Short wrappers and JNI entry points therefore remain
traceable without being mistaken for the algorithm implementation. Unresolved
wrappers remain explicit coverage boundaries. They stay in the audit trail but
cannot expand source families or support usage/adaptation implementation claims.

`reuse_deep_comparisons.jsonl` reranks the bounded candidates after actual
Hex-Rays decompilation. It may expand a seed to project-owned source
implementations using distinctive names or strings, then collapses repeated
seed entries and build/ABI variants into one canonical implementation/source
family row. Generic names, dependency wrappers, tests, and vendored source do
not qualify for that expansion by themselves. Exact compiled identity may
qualify a candidate for usage review.
Corroborated usage review may also pass with one independent binary signal plus
one supporting semantic signal when comparable evidence is sufficient.
Adaptation review requires at least two independent implementation signals and
excludes platform or attributed third-party code. Neither result is a copying
conclusion.

Existing runs can replay only the bounded cohort and native-target selection,
without repeating extraction, JADX, native inventory, or candidate retrieval:

```bash
python scripts/reselect_reuse_candidates.py \
  --workspace path/to/existing/run \
  --review-limit 5000 \
  --native-target-limit 140
```

By default, replay artifacts are written under
`phase3_native/reselection/`; canonical pipeline outputs are not overwritten.

After changing only post-IDA comparison or claim-review rules, reuse the saved
Hex-Rays results instead of rerunning extraction, JADX, retrieval, or IDA:

```bash
python scripts/replay_post_ida_comparison.py \
  --workspace path/to/existing/run
```

The command is non-destructive by default and writes an independent review
under `reanalysis/post_ida/`. After checking that report, promote the result and
rebuild only Phase 5 plus final validation with:

```bash
python scripts/replay_post_ida_comparison.py \
  --workspace path/to/existing/run \
  --apply
```

This replay command is a supported recovery and research-audit path. It is not
part of a normal fresh pipeline run, which already performs the same post-IDA
comparison before Phase 5.

Evaluate retrieval against project-specific labels without changing pipeline
code:

```bash
python scripts/evaluate_reuse_retrieval.py \
  --candidates ./runs/app/hash/phase3_native/reuse_candidates.jsonl \
  --labels ./known_reuse_labels.json \
  --output ./retrieval_evaluation.json \
  --strict
```

The label file contains `known_positives` and optional `negative_controls`.
Each row supplies `id`, `commercial_pattern`, and `source_pattern` regular
expressions. This measures candidate recall and control hits, not copying.

Temporary compiled-corpus experiments should use a dedicated cache directory.
Cache cleanup is dry-run by default and refuses deletion outside a marked
cache root:

```bash
python scripts/manage_reuse_cache.py \
  --cache-dir ./reuse_cache \
  --max-gb 20 \
  --initialize

python scripts/manage_reuse_cache.py \
  --cache-dir ./reuse_cache \
  --max-gb 20 \
  --apply
```

Stage an initial 10--15 project build queue from one APK run. This command
detects native build surfaces in frozen snapshots but does not execute
untrusted or heterogeneous repository build scripts. Upstream candidates and
method-specific candidates such as ED_Lib/LSD are eligible; dependency and
sibling controls remain retrieval evidence but do not consume this build queue:

```bash
python scripts/prepare_oss_build_queue.py \
  --candidates ./runs/app/hash/phase3_native/reuse_candidates.jsonl \
  --snapshot-manifest ../research/oss_provenance/source_snapshots/snapshot_manifest.jsonl \
  --snapshot-root ../research/oss_provenance/source_snapshots \
  --output ./reuse_cache/oss_build_queue.jsonl \
  --limit 15
```

After reviewed recipes have produced fixed `.so` and/or `.apk` artifacts,
record one JSON object per artifact. Required fields are `binary_path`,
`repository_full_name`, and `commit_sha`. Research runs should also record
`corpus_id`, `candidate_role`, `build_variant`, `compiler`,
`compiler_version`, `build_recipe_id`, ABI, and first-party package prefixes
where applicable. Index the artifacts with:

```bash
python scripts/index_oss_binaries.py \
  --manifest ./reuse_cache/oss_build_manifest.jsonl \
  --output-dir ./reuse_cache/compiled_index \
  --ida-install-dir "/Applications/IDA Classroom 9.4.app/Contents/MacOS"
```

The combined output is
`compiled_index/oss_compiled_function_index.jsonl`. Native functions are
indexed from standalone binaries and every `lib/<abi>/*.so` packaged in a
compiled APK. DEX methods and packaged native functions from the same APK are
both retained. If an identical binary hash occurs in more than one project or
build record, each provenance record remains represented instead of being
collapsed to one source. Native functions are represented as
`oss_compiled_binary_function`; methods from built APKs are
represented as `oss_compiled_dex_method`. Opcode, CFG, size, and exact
structural channels are scored only when both sides use compatible
representations. Source-to-source channels are also kept separate. This
prevents cross-language or source-to-binary evidence from receiving an
unsupported structural score.

Add this compiled index to later APK runs with
`--oss-compiled-function-index ./reuse_cache/compiled_index/oss_compiled_function_index.jsonl`.

## Useful Options

- `--no-decompile-all-splits`: only run JADX on the primary APK.
- `--jadx-timeout-per-apk`: set the timeout for each dex-bearing APK or split; partial source is retained.
- `--isolated-workspace`: create a content-addressed workspace for each APK or bundle.
- `--profile ida-handoff`: run the formal extraction and manual IDA handoff workflow without automated native decompilation.
- `--profile ida-classroom`: run the complete pipeline with the isolated IDALib/Hex-Rays adapter.
- `--profile reuse-search`: index all recoverable commercial functions, retrieve open-source candidates, and deep-decompile only selected native candidates and call-graph neighbors.
- `--native-depth none`: skip native target ranking and optional native decompiler calls.
- `--native-depth basic`: extract native metadata and ranked targets without decompiler attempts.
- `--native-depth targeted`: extract native metadata, rank targets, and emit native evidence units.
- `--native-depth auto`: default mode; rank native targets and automatically attempt pseudocode/function-feature extraction only when the target score and local tool availability justify it.
- `--native-depth deep`: force a pseudocode/function-feature attempt for selected native targets if a supported tool is available.
- `--native-decompiler auto|none|ida|rizin|radare2|ghidra|retdec`: select the optional native decompiler adapter.
- `--native-preflight-only`: print native tool availability and exit.
- `--native-max-libraries`: cap the number of native libraries selected for deeper review.
- `--native-max-decompile-targets`: cap the number of native targets sent to the optional decompiler.
- `--ida-review-limit`: cap the priority IDA review queue; the complete candidate inventory remains in the manifest.
- `--ida-handoff-max-libraries`: cap the number of unique library/ABI binaries copied into `ida_handoff.zip`.
- `--ida-install-dir`: override automatic IDA 9.x installation discovery.
- `--ida-python-executable`: select the Python executable used by isolated IDALib workers.
- `--ida-max-retries`: retry a failed or timed-out library worker while retaining completed function checkpoints.
- `--ida-callgraph-depth`: set caller/callee expansion depth around Phase 3 seed targets.
- `--full-native-index-timeout-per-library`: cap one all-function lightweight native indexing job.
- `--full-native-index-timeout-per-app`: cap full native indexing across one app.
- `--full-native-index-max-instructions`: bound instruction features sampled per native function.
- `--oss-function-index`: select the frozen open-source source-function corpus.
- `--oss-compiled-function-index`: add reproducibly built OSS native and/or DEX functions. `--oss-binary-function-index` remains an alias.
- `--reuse-candidate-top-k`: retain at most this many source candidates per commercial function.
- `--reuse-candidate-min-score`: set the candidate-retrieval threshold; this is not a copying probability.
- `--reuse-candidate-decompile-limit`: cap native retrieval candidates allowed to consume Hex-Rays budget.
- `--reuse-regression-labels`: run retrieval coverage checks against an external frozen label file.
- `--strict-reuse-regression`: block research-readiness validation when a labeled known positive is missed.
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
  pipeline_validation.json
  run_records/<run-id>.json
  phase0_split_inventory/cache_manifest.json
  phase0_split_inventory/split_inventory.json
  phase1_manifest/cache_manifest.json
  phase1_manifest/manifest_summary.json
  phase1_manifest/split_manifest_summary.json
  phase2_jadx/cache_manifest.json
  phase2_jadx/jadx_summary.json
  phase2_jadx/code_index.json
  phase2_jadx/java_method_index.jsonl
  phase2_jadx/java_method_index_summary.json
  phase2_jadx/dex_method_index.jsonl
  phase2_jadx/dex_method_index_summary.json
  phase2_jadx/java_evidence_units.json
  phase2_jadx/java_package_index.json
  phase3_native/native_analysis.json
  phase3_native/native_targets.json
  phase3_native/native_toolchain.json
  phase3_native/native_decompile_plan.json
  phase3_native/native_decompilation.json
  phase3_native/ida_automated_summary.json
  phase3_native/decompiled_targets/ida_auto/ida_backend_summary.json
  phase3_native/decompiled_targets/ida_auto/libraries/<library>/functions.jsonl
  phase3_native/decompiled_targets/ida_auto/libraries/<library>/pseudocode/*.c
  phase3_native/native_function_index.json
  phase3_native/native_full_function_index.jsonl
  phase3_native/native_full_callgraph.jsonl
  phase3_native/native_full_index_summary.json
  phase3_native/reuse_candidates.jsonl
  phase3_native/reuse_candidates_review.jsonl
  phase3_native/reuse_candidate_selection_summary.json
  phase3_native/reuse_candidate_summary.json
  phase3_native/reuse_canonical_implementations.jsonl
  phase3_native/reuse_deep_comparisons.jsonl
  phase3_native/reuse_deep_comparison_summary.json
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

`pipeline_validation.json` is the final automation gate. Its `status` is
`passed`, `partial`, or `failed`, and `ready_for_similarity` is true only after
every required check passes. Reuse-search runs additionally expose
`ready_for_dependency_analysis`, `ready_for_usage_analysis`,
`ready_for_adaptation_analysis`, and `ready_for_copying_review`. Dependency
readiness only means component attribution is available. Adaptation readiness
requires a completed native or managed implementation comparison, while
copying-review readiness requires at least one review-ready candidate. These
fields do not assert that reuse or copying occurred.
`copying_conclusion_supported` remains false because attribution and independent
corroboration are outside the automated gate. `pipeline_summary.json` includes
the same validation result, so a process exit code of zero means both the phase
contract and the required validation checks passed.

`phase2_jadx/code_index.json` is the complete source metadata index. It records
all discovered Java, Kotlin, and decompiled XML files, including read failures
and explicit snippet-selection telemetry. `phase5_evidence/review_packet.json`
is intentionally compact. For comparison preparation, first-party and unknown
code are included by default; third-party and platform signals are retained in
separate attribution and dependency sections. The compact similarity-preparation
packet uses stratified sampling across phases, evidence kinds, and capabilities;
its selection telemetry points back to the complete JSONL evidence stream.
Automated IDA selection prefers unique primary-ABI first-party or unattributed
libraries before duplicate ABI variants and known dependencies. Successful
pseudocode is comparison-eligible; failed attempts remain in the audit stream
without entering the similarity candidate set.
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
- `phase3_native/ida_automated_summary.json`
- `phase3_native/reuse_deep_comparison_summary.json`
- `phase3_native/reuse_deep_comparisons.jsonl`
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

JADX decompiles Dalvik bytecode and does not decompile native `.so` libraries. Native code requires a binary analysis tool. The automated native-deep adapter supports IDA 9.x through IDALib/Hex-Rays, plus `rizin` and `radare2`.

In `--native-depth auto`, the pipeline first ranks high-value native targets, writes `phase3_native/native_decompile_plan.json`, and attempts native pseudocode/function-feature extraction only when an automated adapter is available. If no adapter is available, the run still records the missing tool in `phase3_native/native_toolchain.json` and keeps the ranked target plan for follow-up.

Function-level outputs include normalized instruction features, pseudocode fingerprints, basic block counts, string references, call targets, and a lightweight call graph. These are intended as evidence for downstream review and later similarity preparation, not as a complete source reconstruction.

The IDA adapter copies each selected library into a pipeline-owned job directory, verifies its SHA-256 hash before analysis, and closes the database without saving an IDB. Pseudocode is stored as per-function UTF-8 `.c` files with a JSONL result stream and library-level summary. The original extracted library is never modified.

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
- IDA 9.x with IDALib and a compatible Hex-Rays decompiler: optional automated native pseudocode, internal-function discovery, call-graph expansion, and function-feature output.

The `ida-handoff` profile uses `strings` and an ELF symbol utility when
available; these are normally present in standard Colab runtimes. If symbol
tools are unavailable, the library-level discovery tasks remain usable.
Optional decompiler tools are not installed or invoked by that profile.
