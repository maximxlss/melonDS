#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
afl_dir="${root_dir}/third_party/aflplusplus"

if [[ ! -d "${afl_dir}" ]]; then
  echo "AFL++ clone not found at ${afl_dir}"
  exit 1
fi

cd "${afl_dir}"

if [[ ! -f "afl-clang-fast" ]]; then
  echo "Building AFL++ (source-only PERFORMANCE=1)..."
  make source-only PERFORMANCE=1
fi

echo "AFL++ build complete."
