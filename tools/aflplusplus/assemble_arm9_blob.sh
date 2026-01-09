#!/usr/bin/env bash
set -euo pipefail

base_rom="${1:-}"
blob_path="${2:-}"
out_path="${3:-}"

if [[ -z "${base_rom}" || -z "${blob_path}" ]]; then
  echo "Usage: $0 <base_rom.nds> <arm9_blob.bin> [out_rom.nds]" >&2
  exit 2
fi

if [[ ! -f "${base_rom}" ]]; then
  echo "Base ROM not found: ${base_rom}" >&2
  exit 1
fi

if [[ ! -f "${blob_path}" ]]; then
  echo "ARM9 blob not found: ${blob_path}" >&2
  exit 1
fi

if [[ -z "${out_path}" ]]; then
  out_path="out/repacked.nds"
fi

if [[ -d "${out_path}" ]]; then
  out_path="${out_path%/}/repacked.nds"
fi

ndstool_path=""

if [[ -n "${BLOCKSDS:-}" && -x "${BLOCKSDS}/tools/ndstool/ndstool" ]]; then
  ndstool_path="${BLOCKSDS}/tools/ndstool/ndstool"
elif [[ -x "/opt/wonderful/thirdparty/blocksds/core/tools/ndstool/ndstool" ]]; then
  ndstool_path="/opt/wonderful/thirdparty/blocksds/core/tools/ndstool/ndstool"
elif [[ -x "/opt/blocksds/core/tools/ndstool/ndstool" ]]; then
  ndstool_path="/opt/blocksds/core/tools/ndstool/ndstool"
fi

if [[ -z "${ndstool_path}" ]]; then
  echo "ndstool not found. Set BLOCKSDS or install BlocksDS SDK." >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

"${ndstool_path}" -x "${base_rom}" \
  -9 "${tmpdir}/arm9.bin" \
  -7 "${tmpdir}/arm7.bin" \
  -y9 "${tmpdir}/y9.bin" \
  -y7 "${tmpdir}/y7.bin" \
  -t "${tmpdir}/banner.bin" \
  -h "${tmpdir}/header.bin" \
  -d "${tmpdir}/data"

cp "${blob_path}" "${tmpdir}/arm9.bin"

mkdir -p "$(dirname "${out_path}")"

"${ndstool_path}" -c "${out_path}" \
  -9 "${tmpdir}/arm9.bin" \
  -7 "${tmpdir}/arm7.bin" \
  -y9 "${tmpdir}/y9.bin" \
  -y7 "${tmpdir}/y7.bin" \
  -t "${tmpdir}/banner.bin" \
  -h "${tmpdir}/header.bin" \
  -d "${tmpdir}/data"

echo "Wrote repacked ROM to: ${out_path}"
