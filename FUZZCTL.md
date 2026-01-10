# fuzzctl

Single entry‑point tool for ARM9 JIT fuzzing workflows.

## Quick start
```bash
./tools/fuzzctl calibrate --runs 5
./tools/fuzzctl fuzz --instances 8
./tools/fuzzctl repro --input ./afl_out/crashes/id:000000*
./tools/fuzzctl qt --profile fast --sanitizer asan-ubsan
```

## Commands
### `fuzzctl seeds`
Builds BlocksDS seeds before calibration or fuzzing.
- Uses `/opt/blocksds` (assumed present).
- `--rebuild` rebuild even if seeds exist.
- `--profile fast|lto|auto` (auto = detect from last fuzz run or fuzzer_stats; fallback fast)
- `--sanitizer none|asan-ubsan|msan|cfi|auto` (auto = detect from last fuzz run or fuzzer_stats; fallback none)

### `fuzzctl calibrate`
Preflight seeds + timing report (CPU ms now; cycles when available).
- Builds seeds automatically first.
- Verifies each seed runs without immediate crash.
- Emits table + CSV under `out/fuzzctl/calibration/`.
- Automatically prunes stale seed ROMs without matching blobs.
- Disables ASan leak detection when using `asan-ubsan`.

Flags:
- `--runs N` (default: 3)
- `--time-limit-ms N` (default: 500)
- `--profile fast|lto|auto` (auto = detect from last fuzz run or fuzzer_stats; fallback fast)
- `--sanitizer none|asan-ubsan|msan|cfi|auto` (auto = detect from last fuzz run or fuzzer_stats; fallback none)

### `fuzzctl fuzz`
Coordinated AFL++ master + slaves.
- `--instances N` (default: number of cores)
- `--out-dir PATH` (default: `out/fuzzctl/fuzz`)
- `--seed-dir PATH` (default: `seeds/`)
- `--base-rom PATH` (default: BlocksDS `seed_arith.nds`)
- `--cycle-limit N` (default: 300000)
- `--afl-timeout-ms N` (default: 2000)
- `--sand list` (optional; comma list or `all`, adds `-w` sanitizer binaries without changing instance count)
- `--profile fast|lto|auto` (auto = detect from last fuzz run or fuzzer_stats; fallback fast)
- `--sanitizer none|asan-ubsan|msan|cfi|auto` (auto = detect from last fuzz run or fuzzer_stats; fallback none)

### `fuzzctl repro`
Reproduce AFL++ inputs using a clean build (no AFL compiler) to surface traces.
- `--input PATH` (required)
- `--base-rom PATH` (optional; auto-detected from AFL output if possible)
- `--time-limit-ms N` (default: 500)
- `--clean-build` (force rebuild)
- `--profile fast|lto|auto` (auto = detect from last fuzz run or fuzzer_stats; fallback fast)
- `--sanitizer none|asan-ubsan|msan|cfi|auto` (auto = detect from last fuzz run or fuzzer_stats; fallback none)

### `fuzzctl qt`
Build the full Qt/SDL frontend.
- `--profile fast|lto`
- `--sanitizer none|asan-ubsan|msan|cfi`

### `fuzzctl pack`
Package an ARM9 blob or testcase into a ROM using `ndstool`.
- `--input PATH` (ARM9 `.bin`)
- `--rom-out PATH` (output `.nds`)
Uses ` /opt/blocksds/core/tools/ndstool/ndstool ` (assumed present).

## Defaults and convenience
- Auto‑detect last fuzzing profile/sanitizer from `fuzzer_stats` if not provided.
- Only rebuild if target binary is missing (use `--rebuild` to force).
- Build steps are invoked automatically for fuzzing, calibration, repro, and Qt commands.
- Default outputs go under `out/fuzzctl/`.
- `--dry-run` and `--verbose` are available on all commands.

## Preset mapping
`fuzzctl` maps `{toolchain,profile,sanitizer}` to CMake presets:
- AFL toolchain: `headless-afl*` presets.
- Clean toolchain: `headless-harness*` presets.
- Qt: `qt*` presets.
