#!/usr/bin/env bash
# Cross-compile the TV-native RO-exchange artifact (32-bit ARM):
#
#   dist/ncg_native.node  N-API addon: binds the TV's libncg_agent.so
#                         for tv/ro-exchange.js
#
# The addon is a shared object linked against the TV's glibc (it must run
# natively on the TV). The ubuntu:20.04 toolchain (Dockerfile, glibc 2.31) is
# deliberate; see ncg_native.c.
#
# Usage:
#   ncg/build.sh
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null 2>&1 || {
  echo "error: docker not found (needed for the ARM cross-compiler)" >&2
  exit 1
}

ADDON_IMAGE="${NCG_ADDON_IMAGE:-}"
if [ -z "$ADDON_IMAGE" ]; then
  if docker image inspect ncgaddon:20 >/dev/null 2>&1; then
    ADDON_IMAGE=ncgaddon:20
  else
    docker build -q -t ncgaddon:20 -f Dockerfile .
    ADDON_IMAGE=ncgaddon:20
  fi
fi

mkdir -p dist

# Compile as the host user so the outputs in dist/ are owned by the caller
# (a root-owned output inside a bind mount would make the chmod below fail).
run_as_user() { docker run --rm --user "$(id -u):$(id -g)" "$@"; }

echo "== addon (glibc 2.31 toolchain) =="
run_as_user -v "$PWD:/work" -w /work "$ADDON_IMAGE" \
  arm-linux-gnueabi-gcc -O2 -shared -fPIC -I . \
  -o /work/dist/ncg_native.node /work/ncg_native.c -ldl
chmod 755 dist/ncg_native.node
file dist/ncg_native.node 2>/dev/null || true
run_as_user -v "$PWD:/work" -w /work "$ADDON_IMAGE" \
  arm-linux-gnueabi-readelf -V dist/ncg_native.node \
  | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1 \
  | { read -r maxv; echo "   addon references up to: $maxv (TV firmware .so needs >= GLIBC_2.33)"; }

echo "built into dist/ (image: $ADDON_IMAGE)"
