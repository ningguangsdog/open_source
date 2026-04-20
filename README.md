# APK Pipeline (Engineered Version)

This repository contains a modular APK reverse-engineering pipeline with three phases:

1. **Phase I** — Manifest-level semantic extraction
2. **Phase II** — Java decompilation via JADX
3. **Phase III** — Native library extraction and lightweight auditing

## Design goals

- Engineering-ready structure for GitHub
- Phase outputs persisted as JSON for reproducibility
- Success/failure detection for each phase
- Automatic chaining through a unified pipeline runner
- Placeholder for future LLM/API integration

## Quick start

```bash
pip install -r requirements.txt
python scripts/run_pipeline.py --apk /path/to/app.apk --workspace ./apk_workspace
```

## Output structure

```text
workspace/
├── phase1_manifest/
│   ├── AndroidManifest_decoded.xml
│   └── manifest_summary.json
├── phase2_jadx/
│   ├── decompiled/
│   ├── jadx_stdout.txt
│   ├── jadx_stderr.txt
│   └── jadx_summary.json
├── phase3_native/
│   ├── native_libs/
│   └── native_analysis.json
└── pipeline_summary.json
```

## Notes

- Phase II requires JADX; the pipeline can download it automatically.
- Phase III currently implements lightweight native auditing based on `.so` extraction and `strings` analysis.
- API / LLM integration is intentionally left as a placeholder and is not activated by default.
