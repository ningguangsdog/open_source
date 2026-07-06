#!/usr/bin/env bash
set -euo pipefail

echo "[native-tools] Checking native decompiler/disassembler tools..."

if command -v rizin >/dev/null 2>&1; then
  echo "[native-tools] rizin already available: $(rizin -v | head -n 1)"
  exit 0
fi

if command -v r2 >/dev/null 2>&1; then
  echo "[native-tools] radare2 already available: $(r2 -v | head -n 1)"
  exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
  echo "[native-tools] Trying apt-get install for radare2/rizin..."
  sudo apt-get update -y
  sudo apt-get install -y radare2 rizin || true
fi

if command -v rizin >/dev/null 2>&1; then
  echo "[native-tools] rizin installed: $(rizin -v | head -n 1)"
  exit 0
fi

if command -v r2 >/dev/null 2>&1; then
  echo "[native-tools] radare2 installed: $(r2 -v | head -n 1)"
  exit 0
fi

if command -v mamba >/dev/null 2>&1; then
  echo "[native-tools] Trying mamba install from conda-forge..."
  mamba install -y -c conda-forge rizin || true
elif command -v conda >/dev/null 2>&1; then
  echo "[native-tools] Trying conda install from conda-forge..."
  conda install -y -c conda-forge rizin || true
fi

if command -v rizin >/dev/null 2>&1; then
  echo "[native-tools] rizin installed: $(rizin -v | head -n 1)"
  exit 0
fi

if command -v r2 >/dev/null 2>&1; then
  echo "[native-tools] radare2 installed: $(r2 -v | head -n 1)"
  exit 0
fi

echo "[native-tools] No automated native decompiler was installed."
echo "[native-tools] Install rizin or radare2, then rerun:"
echo "  python scripts/run_pipeline.py --native-preflight-only"
exit 1
