#!/usr/bin/env bash
set -euo pipefail

rom_path="${1:-}"
out_path="${2:-}"

if [[ -z "${rom_path}" ]]; then
  echo "Usage: $0 <base_rom.nds> [out_file_or_dir]" >&2
  exit 2
fi

if [[ ! -f "${rom_path}" ]]; then
  echo "Base ROM not found: ${rom_path}" >&2
  exit 1
fi

if [[ -z "${out_path}" ]]; then
  out_path="seeds/arm9.bin"
fi

if [[ -d "${out_path}" ]]; then
  out_path="${out_path%/}/arm9.bin"
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

mkdir -p "$(dirname "${out_path}")"

"${ndstool_path}" -x "${rom_path}" -9 "${out_path}"

# Trim trailing zero padding to keep the seed small (harness zero-fills the rest).
python3 - <<'PY' "${out_path}"
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = path.read_bytes()
trimmed = data.rstrip(b"\x00")
if not trimmed:
    trimmed = b"\x00"
path.write_bytes(trimmed)
print(f"Trimmed ARM9 blob: {len(data)} -> {len(trimmed)} bytes")
PY

echo "Wrote ARM9 blob to: ${out_path}"
