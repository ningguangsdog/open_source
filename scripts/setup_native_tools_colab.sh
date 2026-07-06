#!/usr/bin/env bash
set -euo pipefail

echo "[native-tools] Checking native decompiler/disassembler tools..."

check_installed() {
  if command -v rizin >/dev/null 2>&1; then
    echo "[native-tools] rizin available: $(rizin -v | head -n 1)"
    exit 0
  fi

  if command -v r2 >/dev/null 2>&1; then
    echo "[native-tools] radare2 available: $(r2 -v | head -n 1)"
    exit 0
  fi
}

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

check_installed

if command -v mamba >/dev/null 2>&1; then
  echo "[native-tools] Trying mamba install from conda-forge..."
  mamba install -y -c conda-forge rizin || true
elif command -v conda >/dev/null 2>&1; then
  echo "[native-tools] Trying conda install from conda-forge..."
  conda install -y -c conda-forge rizin || true
fi

check_installed

if command -v apt-get >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
  echo "[native-tools] Package install did not provide rizin/radare2."
  echo "[native-tools] Trying radare2 source install. This can take several minutes in Colab."
  sudo apt-get install -y git make gcc g++ pkg-config autoconf automake libtool || true
  rm -rf /tmp/radare2
  git clone --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2
  (
    cd /tmp/radare2
    sys/install.sh
  ) || true
fi

check_installed

echo "[native-tools] No automated native decompiler was installed."
echo "[native-tools] Install rizin or radare2, then rerun:"
echo "  python scripts/run_pipeline.py --native-preflight-only"
exit 1
