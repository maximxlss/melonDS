#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
afl_dir="${root_dir}/third_party/aflplusplus"

preset="${1:-headless-afl-asan-ubsan}"
seed_dir="${2:-${root_dir}/afl_seeds}"
out_dir="${3:-${root_dir}/afl_out}"

if [[ ! -d "${afl_dir}" ]]; then
  echo "AFL++ clone not found at ${afl_dir}"
  exit 1
fi

mkdir -p "${seed_dir}" "${out_dir}"

cmake --preset "${preset}"
cmake --build --preset "${preset}" --target headless_afl

target="${root_dir}/build/${preset}/headless_afl"
if [[ ! -x "${target}" ]]; then
  echo "Fuzz target not found at ${target}"
  exit 1
fi

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

"${afl_dir}/afl-fuzz" -i "${seed_dir}" -o "${out_dir}" -- "${target}"
