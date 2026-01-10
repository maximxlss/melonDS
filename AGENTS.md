# AGENTS

Notes to help agents ramp quickly on fuzzing + harness work in this repo.

## Fuzzing harness entry points
- ARM9 blob harness (primary): `src/frontend/headless/afl_harness_arm9_blob.cpp`
  - Persistent AFL++ loop.
  - Per-input: restore savestate, reset JIT, write ARM9 blob, execute ARM9 JIT.
  - Timeout via cycle budget (`--cycle-limit` or `--time-limit-ms` → cycles).
  - Timing mode exits early when the seed triggers a CPU stop (PowerOff/BadExceptionRegion).
  - Harness aborts the input if the emulated console stops
    (`Platform::Headless_StopRequested()` + `StopReason`).
  - Stop state is cleared per input with `Platform::Headless_ResetStop()`.
  - Warn-once logs (MP/Wi-Fi/Mic) are suppressed for fuzzing via
    `Platform::Headless_SuppressWarnOnce(true)` to avoid AFL stability noise.
  - Threaded GPU/renderer paths are not used or considered in this fuzzing project;
    keep render threading disabled in headless runs.

## Build targets / presets
- CMake harness targets are declared in `src/frontend/headless/CMakeLists.txt`.
- AFL presets in `CMakePresets.json`: `headless-afl*` (asan/ubsan/msan/cfi).
- TSAN and LSAN are out of scope for this project; do not add them to fuzzing presets.

## Tooling scripts (current, messy)
- `tools/fuzzctl`: unified launcher for seeds, calibration, fuzzing, repro, Qt builds, packing.
- `tools/aflplusplus/run_fuzz_multi.sh`: multi-instance AFL++ for ARM9 harness.
- `tools/aflplusplus/time_harnesses.py`: timing table for ARM9 harness.
- `AFLPLUSPLUS.md`: docs for ARM9 harness.

## Seeds
- BlocksDS seeds generator: `tools/blocksds/jit_seeds` (use `make -C ... seeds`).
- Output:
  - ROMs: `tools/blocksds/jit_seeds/build/seed_*.nds`
  - ARM9 blobs: `seeds/arm9_*.bin`
- Seeds should terminate by triggering a CPU stop (PowerOff/BadExceptionRegion), not by
  writing a completion flag. See `tools/blocksds/jit_seeds/sources/seed_common.c`.
  - Current mechanism: SPI PowerMan power‑off in `seed_poweroff()`.
  - The fuzz harness builds with `MELON_FUZZ_FAST=1` so:
    - SPI transfers complete immediately (no `RunSystem` scheduling), and
    - ARM9 MMIO writes to 0x040001C0/0x040001C2 are forwarded to `SPI.Write*`
      for the power‑off sequence.

## Major slowdowns (audit findings)
- `nds->JIT.ResetBlockCache()` per input (heavy, clears full JIT structures and logs).
  - See `src/ARMJIT.cpp` and `src/frontend/headless/afl_harness_arm9_blob.cpp`.
- Redundant per-16-byte invalidation in `WriteArm9Blob()` after full reset.
- Full savestate load every iteration.
  - Profiling: savestate restore is >80% of a 200k-cycle timing run.
  - `NDS::DoSavestate()` copies MainRAM (16 MiB) + VRAM (~576 KiB) each time.
  - `CP15::DoSavestate()` copies ARM9 ITCM (32 KiB) + DTCM (16 KiB).
  - `JIT.ResetBlockCache()` clears large lookup tables (MainRAM / 2 entries).

## Instability sources (audit findings)
- SIGVTALRM + siglongjmp timeout from within JIT execution can corrupt allocator/JIT state.
- Signal is process-directed; any extra threads increase risk of longjmp on the wrong thread.
- `KeyInput` is not serialized in savestates; harness now forces a deterministic
  baseline (`0x007F03FF`) after each load.

## Suggested direction (from plan)
- Remove ROM harness entirely and simplify docs/scripts.
- Replace async signal timeouts with cooperative cycle budgets.
- Add cycle-based timing to size a safe budget.
- Centralize tooling into one launcher (build/run/timing/repro).
- Avoid kernel dirty-page tracking; prefer tracing execution paths to decide minimal restore.
- Forkserver methodology: likely not beneficial with ARM9 JIT (large state, JIT/shm, possible threads).
  Defer unless minimal-restore work fails to bring costs down.

## Quick file map
- Harness: `src/frontend/headless/afl_harness_arm9_blob.cpp`
- JIT reset: `src/ARMJIT.cpp`
- Savestate: `src/Savestate.cpp`
- Headless platform: `src/frontend/headless/Platform.cpp`
- Docs: `AFLPLUSPLUS.md`

## Environment constraints
- In this shell, `shm_open`/`ftruncate` can fail under default sandboxing.
  Some JIT fast-memory paths require elevated permissions to run.
  Use an escalated command if you see `Failed to open memory using shm_open`.
