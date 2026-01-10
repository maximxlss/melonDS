# EXECPLAN

Living execution plan for fuzzing harness + tooling improvements in melonDS.
Update as decisions are made or work lands.

## Scope
- Primary target: ARM9 JIT subsystem fuzzing (headless ARM9 blob harness).
- Secondary: tooling and seed quality that directly affects ARM9 JIT fuzzing throughput.
- Non-goals: ROM fuzzing, GUI/frontends, non-ARM9 subsystems unless they are on the
  critical path for ARM9 JIT execution.

## Goals
- Make fuzzing harness stable under time limits (no process poisoning, fewer hangs).
- Improve throughput (reduce per-input overhead).
- Remove ROM-mode fuzzing entirely.
- Simplify tooling into a centralized launcher for build/run/timing/triage.
- Add cycle-based timing measurements to size a reliable budget.
- Audit and improve seed corpus quality and coverage.

## Current state (as of 2026-01-09)
- ARM9 blob harness is the only supported AFL++ headless target.
- ARM9 harness uses a cycle budget (`--cycle-limit` / `--time-limit-ms`) rather than async signals.
- ARM9 harness resets full savestate and JIT cache per input.
- Scripts are spread across `tools/aflplusplus/*` with overlapping responsibilities.

## Findings (from audit)
- Previous instability source: async signal + `siglongjmp` from JIT execution could bypass cleanup
  and poison state. This is now addressed by the cycle budget.
- Slowness: per-input `ResetBlockCache()` is heavy (clears large structures) and logs
  per-iteration; followed by a per-16-byte invalidation loop that is redundant when
  the full reset already happened.
- Slowness: full savestate load every input is expensive.
- Potential mismatch: fallback AFL testcase buffer is 1 MiB but max input allows 16 MiB.
  Large ARM9 blobs may be truncated unless AFL shared memory size is increased.
- Fuzzing-related CMake lists and presets are spread across multiple presets and
  targets; should be audited and simplified for the ARM9 JIT fuzzing path.

## Plan (phased)

### Phase 0: Documentation + scope cleanup
1) Remove ROM fuzzing references and targets.
   - Delete `src/frontend/headless/afl_harness_rom.cpp`.
   - Drop `headless_afl` from `src/frontend/headless/CMakeLists.txt` and deps.
   - Replace `tools/aflplusplus/run_fuzz.sh` with an ARM9-only launcher or delete it.
   - Rewrite `AFLPLUSPLUS.md` to describe only ARM9 blob harness.

2) Add living docs:
   - This `EXECPLAN.md`.
   - `AGENTS.md` (quick-start notes + hazards + hotspots).
3) Decision: ARM9 JIT fuzzing is the sole supported harness going forward.
4) Audit and clean up fuzzing-only CMake lists/presets:
   - Review `src/frontend/headless/CMakeLists.txt` fuzz targets.
   - Review `CMakePresets.json` `headless-afl*` presets.
   - Remove/rename redundant fuzz presets and align to `fuzzctl` profiles.
Status: completed.

### Phase 0b: Centralize tooling (new launcher, top priority after Phase 0)
Create a single tool (e.g., `tools/fuzzctl.py`) to orchestrate all day‑to‑day tasks.
No legacy compatibility layer; new tool becomes the supported entry point.

Proposed commands (clarified, keep at top for quick testing):
- `fuzzctl seeds --rebuild [--profile fast|lto] [--sanitizer asan|ubsan|...|none]`
- `fuzzctl calibrate --runs N [--profile ...] [--sanitizer ...] [--report csv|table]`
- `fuzzctl fuzz --instances N --out-dir ... --base-rom ... [--profile ...] [--sanitizer ...]`
- `fuzzctl repro --input ./crashes/id:... [--clean-build] [--profile ...] [--sanitizer ...]`
- `fuzzctl qt --profile ... [--sanitizer ...]`
- `fuzzctl pack --input ./seeds/arm9_x.bin --rom-out ./out.nds`

UX requirements (must feel obvious and convenient):
- Single entry command: `fuzzctl <verb>` with clear, consistent flags.
- Sensible defaults: run from repo root, auto-detect paths, build only if missing.
- Dry‑run + verbose modes for clarity (`--dry-run`, `--verbose`).
- Friendly error messages with next steps (e.g., “Run `fuzzctl seeds --rebuild`”).
- Predictable output layout (reports/logs under `out/` by default).
- `fuzzctl help` and `fuzzctl <verb> --help` with short examples.

Required capabilities (from a clean repo; AFL++ already cloned/built; BlocksDS installed):
1) Seeds calibration (preflight + timing):
   - Build seeds (BlocksDS) before calibration.
   - Run each seed to verify no immediate crashes.
   - Measure timing (CPU ms now; cycles once available).
   - Output a table + CSV and recommended budgets.

2) Cooperative multiprocessing AFL++:
   - Launch master + N slaves on ARM9 harness.
   - Support base ROM selection and seed corpus selection.

3) Repro AFL++ test cases in a clean build:
   - Rebuild without AFL compiler instrumentation.
   - Run crashing inputs and surface stack traces/ASan/UBSan output clearly.

4) Full Qt builds:
   - Build Qt frontend presets as a separate subcommand.

5) Packaging utilities:
   - Package seeds or test cases into ROMs via `ndstool` (assume `/opt/blocksds/core`).

Compilation options for every subcommand:
- Speed profile: `fast` vs `lto`.
- Sanitizers: selectable (asan/ubsan/msan/cfi/none). (TSan/LSan are out of scope.)
Status: completed (initial implementation).

### Phase 1: Stabilize time limits (remove async longjmp)
1) Replace SIGVTALRM + siglongjmp with a cooperative budget:
   - Introduce `--cycle-limit` (ARM9 timestamp units) to the ARM9 harness.
   - Set `ARM9Target = ARM9Timestamp + budget` instead of `max`.
   - Let `ARM9.Execute<...>()` return naturally.
   - Convert `--time-limit-ms` into a budget using a calibration step or explicit
     `--cycles-per-ms` from timing measurements.
   - Decide unit: confirm whether `ARM9Timestamp` counts ARM9 cycles or shifted
     system cycles (see `ARM9ClockShift` usage). Document conversion clearly.

2) If a signal-based watchdog is still required (interim):
   - Block the signal in any auxiliary threads.
   - Use a thread-targeted timer (Linux: `SIGEV_THREAD_ID`) to ensure delivery to
     the execution thread only.
   - Never `longjmp` across JIT/allocator frames; instead set a flag and poll.
3) Decision: eliminate async signal timeouts for the default fuzz path.
4) Stop on CPU faults:
   - If `NDS::Stop()` is triggered (e.g., bad exception), detect it via
     `Platform::Headless_StopRequested()` and abort the current input immediately.
   - Log `StopReason` for debugging/triage (BadExceptionRegion vs others).
Status: completed (cycle budget + stop-on-fault hooks).

### Phase 1b: Cycle-based timing calibration (supports budget sizing)
1) Update timing harness to report cycles and CPU ms for each seed.
   - Add a harness mode that runs ARM9 for a fixed number of cycles and reports
     elapsed CPU ms + final cycle count (or delta).
   - Or add instrumentation in the harness to expose `ARM9Timestamp` before/after.
   - Early-exit timing runs when the seed triggers a CPU stop (PowerOff/BadExceptionRegion).
   - Seeds use SPI PowerMan power-off in `seed_common.c` to force the stop.
     - Harness builds define `MELON_FUZZ_FAST=1` so SPI transfers complete without
       `RunSystem` scheduling and ARM9 SPI MMIO writes are forwarded to `SPI.Write*`
       (required for fast power-off in ARM9-only execution).

2) Extend timing tool to compute:
   - cycles-per-ms for each seed
   - worst-case cycles-per-ms to set safe budgets
   - recommended `--cycle-limit` for a target ms cutoff
   - recommended `--time-limit-ms` for a chosen cycle budget
   - Decision: default `--cycle-limit` ≈ 1.5x of the max observed seed cycles
     (from calibration) to avoid false timeouts.

3) Output a CSV/table for easy tracking.
Status: completed (cycles and cycles/ms now reported).

### Phase 2: Throughput improvements
1) Remove redundant invalidation:
   - Either keep `ResetBlockCache()` and remove per-16-byte invalidation, or
     add a range-based invalidation API and remove the full reset.
   - Decision: Stage 1 = keep full reset, remove per-16B invalidation.
     Stage 2 = add range invalidation and remove full reset once validated.
   - Status: per-16B invalidation is skipped when `ResetBlockCache()` is used.
   - Note: `ResetBlockCache()` calls `Memory.Reset()` and memsets the full
     `FastBlockLookupRegions` tables (MainRAM/2 entries); avoid when possible.

2) Reduce per-input restore cost:
   - Avoid full `DoSavestate()` every iteration; restore only the minimal RAM/regs
     needed for ARM9 execution.
   - Consider keeping a pre-initialized ARM9-only snapshot and memcpy state in.
   - Decision: first quantify savestate restore cost vs. JIT reset cost, then
     optimize the dominant path.
   - Profiling note: savestate restore dominates timing (>80% in a 200k-cycle run).
   - Decision: do NOT rely on kernel dirty-page tracking (high overhead, portability and
     privilege issues); instead trace execution paths and determine a minimal restore set.
   - Execution path audit (current findings):
     - `NDS::DoSavestate()` always copies: MainRAM (16 MiB), Shared WRAM (32 KiB),
       ARM7 WRAM (64 KiB), plus GPU VRAM (~576 KiB) and palette/OAM (4 KiB each).
     - `CP15::DoSavestate()` also copies ARM9 ITCM (32 KiB) and DTCM (16 KiB).
     - GPU3D and matrix stacks add extra ~tens of KiB.
     - `JIT.ResetBlockCache()` clears large lookup tables (MainRAM / 2 entries) and
       iterates every compiled block; heavy even if no blocks exist.
   - Next: trace execution paths to identify which state can be left intact between inputs.
     - Instrument ARM9 memory writes to build a per-run dirty-page bitset
       (software tracking in `ARMJIT_Memory` write paths).
     - Limit restore to dirty pages for MainRAM/SharedWRAM/ARM7WRAM and any mapped VRAM.
     - Identify and skip untouched subsystems (GPU/SPU/Wifi/SPI/RTC) in a
       fuzz-only restore path if safe for ARM9 blob execution.
     - Add simple “touched” flags on MMIO reads/writes to confirm which subsystems
       are exercised by the seed corpus and early fuzz runs.
   - Keep a fallback to full restore for correctness/regression bisects.
   - Forkserver note: likely not a win for ARM9 JIT (large state, JIT memory, shm/threads).
     Measure anyway with a simple forkserver harness to validate.
     - Compare persistent vs forkserver using the same seed set:
       `AFL_NO_PERSISTENT=1` (or compile-time `__AFL_LOOP(1)`), measure execs/sec
       and crash determinism; record per-input wall time and memory RSS.

3) Reduce per-iteration logging:
   - Silence `ResetBlockCache()` debug log or guard behind a verbosity flag.

4) Determinism: thorough reset of non-serialized state
   - Identify state not covered by savestates (e.g., `KeyInput`, any latent
     frontend flags, pending stop reason) and force deterministic values per input.
   - Ensure touch/RTC/wifi/etc. do not leak cross‑input state unless serialized.
   - Add a quick “determinism checklist” for future harness edits.

5) Seed audit + rework (new)
   - Verify seeds are valid, diverse, and match the current harness input limits.
   - Prune stale/duplicate seeds and re-generate blobs when ROM seeds change.
   - Add a seed quality report (coverage deltas, size distribution, timeout rate).
   - Ensure seed corpus is compatible with cycle-budget execution (no systemic timeouts).
   - Decision: keep seed ROMs/blobs in sync by default; stale blobs are pruned.
   - Decision: seeds trigger a CPU stop (PowerOff/BadExceptionRegion) so timing runs can exit early.

## Verification checklist (per phase)
### Phase 0
- Build with `headless-afl*` presets after removing ROM harness.
- `AFLPLUSPLUS.md` contains only ARM9 harness docs.

### Phase 0b
- `fuzzctl` can build seeds, calibrate, fuzz, repro, and build Qt with profile/sanitizer flags.
- `fuzzctl calibrate` validates seeds and emits timing report.
- `fuzzctl pack` produces a ROM via `ndstool` (assume `/opt/blocksds/core`).

### Phase 1
- No SIGVTALRM or `siglongjmp` in the default fuzz path.
- Harness honors `--cycle-limit` and exits deterministically.
- Timing mode outputs cycle counts + CPU ms.

### Phase 1b
- Timing report includes cycles/ms and recommended budgets.
- Cycle budget chosen produces similar timeout behavior to previous ms limit,
  but without instability.

### Phase 2
- Inputs/sec improved over baseline (track in timing report).
- No regressions in determinism: same input yields same coverage/path.
- JIT reset/invalidation changes do not break correctness for fixed seeds.

## Risks / open questions
- How much ARM9 state can be safely restored without full savestate?
- Any hidden dependencies on thread-based rendering in headless mode?
- Does JIT need a structured “invalidate range” API to avoid full resets?
- Do existing seeds bias execution into long-running loops that skew timing/budgeting?
- What is the canonical unit for `ARM9Timestamp` and how does it map to cycles/ms?

## Success criteria
- No crashes/hangs from timeout handling across long fuzz runs.
- Measurable input/s (>2x in JIT harness builds) compared to baseline.
- A single, documented launcher for builds + fuzz runs + timing.
- Cycle-based timing numbers available for choosing budgets.
