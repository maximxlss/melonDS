#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
afllib_dir="${root_dir}/third_party/aflplusplus"

preset="headless-afl-asan-ubsan"
seed_dir="${root_dir}/seeds"
out_dir="${root_dir}/afl_out"
instances=""
target=""
no_build=0
base_rom=""
no_seed_build=0
output_mode="master"
log_dir=""

usage() {
  cat <<USAGE >&2
Usage: $0 [--preset NAME] [--seed-dir DIR] [--out-dir DIR] [--instances N] [--target PATH] [--base-rom PATH] [--no-build] [--no-seed-build] [--output-mode MODE] [--log-dir DIR] -- [target args...]

Defaults:
  --preset    headless-afl-asan-ubsan
  --seed-dir  \\${repo}/seeds
  --out-dir   \\${repo}/afl_out
  --target    build/\\${preset}/headless_afl_arm9_blob
  --output-mode master|all|silent (default: master)

Examples:
  $0 --instances 8
  $0 --base-rom ./tools/blocksds/jit_seeds/build/seed_arith.nds
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preset)
      preset="$2"; shift 2 ;;
    --seed-dir)
      seed_dir="$2"; shift 2 ;;
    --out-dir)
      out_dir="$2"; shift 2 ;;
    --instances)
      instances="$2"; shift 2 ;;
    --target)
      target="$2"; shift 2 ;;
    --base-rom)
      base_rom="$2"; shift 2 ;;
    --no-build)
      no_build=1; shift ;;
    --no-seed-build)
      no_seed_build=1; shift ;;
    --output-mode)
      output_mode="$2"; shift 2 ;;
    --log-dir)
      log_dir="$2"; shift 2 ;;
    --help|-h)
      usage; exit 0 ;;
    --)
      shift; break ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

target_args=("$@")

if [[ ! -d "${afllib_dir}" ]]; then
  echo "AFL++ clone not found at ${afllib_dir}" >&2
  exit 1
fi

if [[ -z "${target}" ]]; then
  target="${root_dir}/build/${preset}/headless_afl_arm9_blob"
fi

if [[ -z "${instances}" ]]; then
  if command -v nproc >/dev/null 2>&1; then
    instances="$(nproc)"
  else
    instances="4"
  fi
fi

if [[ "${instances}" -lt 1 ]]; then
  echo "--instances must be >= 1" >&2
  exit 1
fi

mkdir -p "${seed_dir}" "${out_dir}"
if [[ -z "${log_dir}" ]]; then
  log_dir="${out_dir}/logs"
fi
mkdir -p "${log_dir}"

if [[ "${no_build}" -eq 0 ]]; then
  cmake --preset "${preset}"
  if [[ -z "${target}" || "${target}" == "${root_dir}/build/${preset}/headless_afl_arm9_blob" ]]; then
    cmake --build --preset "${preset}" --target headless_afl_arm9_blob
  fi
fi

if [[ ! -x "${target}" ]]; then
  echo "Fuzz target not found/executable: ${target}" >&2
  exit 1
fi

if [[ -z "${base_rom}" && ${#target_args[@]} -eq 0 ]]; then
  if [[ "${no_seed_build}" -eq 0 ]]; then
    make -C "${root_dir}/tools/blocksds/jit_seeds" seeds
  fi
  base_rom="${root_dir}/tools/blocksds/jit_seeds/build/seed_arith.nds"
fi

if [[ -n "${base_rom}" && ${#target_args[@]} -eq 0 ]]; then
  target_args=("${base_rom}")
fi

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

pids=()
cleanup() {
  for pid in "${pids[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

for i in $(seq 1 "${instances}"); do
  if [[ "${i}" -eq 1 ]]; then
    role=(-M master)
  else
    role=(-S "slave${i}")
  fi

  cmd=("${afllib_dir}/afl-fuzz" -i "${seed_dir}" -o "${out_dir}" "${role[@]}" -- "${target}")
  if [[ ${#target_args[@]} -gt 0 ]]; then
    cmd+=("${target_args[@]}")
  fi

  case "${output_mode}" in
    all)
      "${cmd[@]}" &
      ;;
    silent)
      "${cmd[@]}" >/dev/null 2>&1 &
      ;;
    master)
      if [[ "${i}" -eq 1 ]]; then
        "${cmd[@]}" &
      else
        "${cmd[@]}" >"${log_dir}/afl_slave${i}.log" 2>&1 &
      fi
      ;;
    *)
      echo "Unknown --output-mode: ${output_mode}" >&2
      exit 1
      ;;
  esac
  pids+=("$!")
  sleep 0.1

done

wait
