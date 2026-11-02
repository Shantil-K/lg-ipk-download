#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

for file in bin/*.js tv/*.js ncg/*.js test/*.js; do
  node --check "$file"
done

for file in lib/*.sh ncg/*.sh scripts/*.sh; do
  bash -n "$file"
done
