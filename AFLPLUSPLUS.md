# AFL++ (Headless Harness)

This repo includes a headless AFL++ harness target:
- **ARM9 blob input**: `headless_afl_arm9_blob` (fuzzes ARM9 code with a fixed base ROM)
  - Source: `src/frontend/headless/afl_harness_arm9_blob.cpp`

The harness uses AFL++ persistent mode (`__AFL_LOOP`) and shared-memory test cases
(`__AFL_FUZZ_INIT`) to minimize process startup overhead.

## Quick start (ARM9 blob fuzzing)

1) Build AFL++ in `third_party/aflplusplus`:
```
tools/aflplusplus/build_aflplusplus.sh
```

2) Configure/build the ARM9 blob harness:
```
cmake --preset headless-afl-asan-ubsan
cmake --build --preset headless-afl-asan-ubsan --target headless_afl_arm9_blob
```

3) Run multiple coordinated AFL++ instances (master + slaves) in one line:
```
tools/aflplusplus/run_fuzz_multi.sh --instances 8
```

To control output noise (default is master-only):
```
tools/aflplusplus/run_fuzz_multi.sh --instances 8 --output-mode master
```

## ARM9 blob / JIT harness

This harness keeps a fixed base ROM and fuzzes only the ARM9 code segment. It is
useful for JIT-focused fuzzing.

1) Build the harness:
```
cmake --preset headless-afl-asan-ubsan
cmake --build --preset headless-afl-asan-ubsan --target headless_afl_arm9_blob
```

2) Build base ROMs and ARM9 blob seeds (BlocksDS jit seeds):
```
make -C tools/blocksds/jit_seeds seeds
```
This generates:
- Base ROMs: `tools/blocksds/jit_seeds/build/seed_*.nds`
- ARM9 blobs: `seeds/arm9_*.bin`

3) Run AFL++ (pick any generated ROM as the base):
```
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
third_party/aflplusplus/afl-fuzz -i ./seeds -o ./out -- \
  ./build/headless-afl-asan-ubsan/headless_afl_arm9_blob tools/blocksds/jit_seeds/build/seed_arith.nds
```

## Timing mode (sanity + tuning)

Run all seeds through the ARM9 blob harness a few times and report a timing table (useful for tuning the ARM9 blob time limit):
```
cmake --build --preset headless-afl-asan-ubsan --target time_harnesses
```

Manual timing runs:
```
./build/headless-afl-asan-ubsan/headless_afl_arm9_blob \
  tools/blocksds/jit_seeds/build/seed_arith.nds \
  --timing seeds/arm9_arith.bin \
  --time-limit-ms 5
```

Notes:
- The ARM9 harness now uses a cycle budget (not an async timer). `--time-limit-ms`
  is converted to a cycle limit using a default cycles-per-ms value; you can override
  with `--cycles-per-ms` or pass `--cycle-limit` directly.
- Timing output includes `cycles` and `cycle_limit` for calibration.

## Presets

The CMake presets configured for AFL++ are:
- `headless-afl`: instrumentation only
- `headless-afl-asan-ubsan`: ASan + UBSan
- `headless-afl-msan`: MSan (separate build)
- `headless-afl-cfi`: CFI (separate build)

These sanitizer builds are separate because the sanitizers are not generally
compatible with each other in a single binary.

## JIT on/off

The harness uses `NDSArgs` defaults, which include JIT when the build supports it.
To force JIT on/off in the build, set:
```
cmake --preset headless-afl-asan-ubsan -DENABLE_JIT=ON
cmake --build --preset headless-afl-asan-ubsan --target headless_afl_arm9_blob
```

Notes:
- JIT is available on x86_64 builds.
- If you see crashes related to executable memory under sanitizers, try a non‑sanitized
  preset first (`headless-afl`), then add sanitizers incrementally.

## Priority runs for critical vulnerabilities (RCE / file read/write)

If you’re specifically hunting for high‑impact bugs, run these in order:

1) **AFL++ ASan+UBSan, JIT on**
```
cmake --preset headless-afl-asan-ubsan -DENABLE_JIT=ON
cmake --build --preset headless-afl-asan-ubsan --target headless_afl_arm9_blob
tools/aflplusplus/run_fuzz_multi.sh --instances 8 --out-dir ./out-asan-ubsan
```

2) **AFL++ (no sanitizers), JIT on**
```
cmake --preset headless-afl -DENABLE_JIT=ON
cmake --build --preset headless-afl --target headless_afl_arm9_blob
tools/aflplusplus/run_fuzz_multi.sh --instances 8 --out-dir ./out-fast --preset headless-afl
```

3) **AFL++ ASan+UBSan, JIT off**
```
cmake --preset headless-afl-asan-ubsan -DENABLE_JIT=OFF
cmake --build --preset headless-afl-asan-ubsan --target headless_afl_arm9_blob
tools/aflplusplus/run_fuzz_multi.sh --instances 8 --out-dir ./out-asan-ubsan-nojit
```

4) **AFL++ MSan (JIT off)**
```
cmake --preset headless-afl-msan -DENABLE_JIT=OFF
cmake --build --preset headless-afl-msan --target headless_afl_arm9_blob
tools/aflplusplus/run_fuzz_multi.sh --instances 8 --out-dir ./out-msan --preset headless-afl-msan
```

5) **AFL++ CFI (JIT off)**
```
cmake --preset headless-afl-cfi -DENABLE_JIT=OFF
cmake --build --preset headless-afl-cfi --target headless_afl_arm9_blob
tools/aflplusplus/run_fuzz_multi.sh --instances 8 --out-dir ./out-cfi --preset headless-afl-cfi
```

## Further improvements (targeted fuzzing)

For deeper bug discovery, consider adding focused harnesses for:
- **ROM parsing and cart handling** (NDS/DSi headers, secure area, save types)
- **Save formats** (SRAM/EEPROM/FLASH loaders)
- **Firmware parsing and settings** (SPI firmware structures)
- **Networking packet processing** (Wifi/LAN packet paths)
- **DSP/AAC paths** (if enabled and linked)

Targeted harnesses improve coverage and triage for specific security goals.
