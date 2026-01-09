# AFL++ (Headless Harness)

This repo includes headless AFL++ harness targets:
- **ROM input**: `headless_afl` (fuzzes entire `.nds` files)
  - Source: `src/frontend/headless/afl_harness_rom.cpp`
- **ARM9 blob input**: `headless_afl_arm9_blob` (fuzzes ARM9 code segment using a fixed base ROM)
  - Source: `src/frontend/headless/afl_harness_arm9_blob.cpp`

Both harnesses use AFL++ persistent mode (`__AFL_LOOP`) and shared-memory test
cases (`__AFL_FUZZ_INIT`) to minimize process startup overhead.

## Setup

1) Build AFL++ in `third_party/aflplusplus`:
```
tools/aflplusplus/build_aflplusplus.sh
```

2) Configure/build the AFL++ harness (ROM input):
```
cmake --preset headless-afl-asan-ubsan
cmake --build --preset headless-afl-asan-ubsan --target headless_afl
```

3) Run AFL++ (ROM input):
```
tools/aflplusplus/run_fuzz.sh headless-afl-asan-ubsan ./seeds ./out
```

## Presets

The CMake presets configured for AFL++ are:
- `headless-afl`: instrumentation only
- `headless-afl-asan-ubsan`: ASan + UBSan
- `headless-afl-msan`: MSan (separate build)
- `headless-afl-tsan`: TSan (separate build)
- `headless-afl-cfi`: CFI (separate build)

These sanitizer builds are separate because the sanitizers are not generally
compatible with each other in a single binary.

## Notes

- Seeds are required. Use small valid `.nds` samples to reach deeper code paths.
- The harness boots the ROM directly and executes a single frame per input.
- The ARM9 blob harness restores a savestate checkpoint each iteration and
  overwrites the ARM9 code segment before execution using a fixed CPU budget.

## ARM9 blob / JIT harness

This harness keeps a fixed base ROM and fuzzes only the ARM9 code segment. It
is useful for JIT-focused fuzzing.

1) Build the harness:
```
cmake --preset headless-afl-asan-ubsan
cmake --build --preset headless-afl-asan-ubsan --target headless_afl_arm9_blob
```

2) Build a base ROM (BlocksDS example):
```
cd tools/blocksds/hello_jit
make
```

3) Extract an ARM9 blob seed using BlocksDS `ndstool`:
```
tools/aflplusplus/extract_arm9_blob.sh tools/blocksds/hello_jit/hello_jit.nds ./seeds
```

4) Run AFL++:
```
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
third_party/aflplusplus/afl-fuzz -i ./seeds -o ./out -- \\
  ./build/headless-afl-asan-ubsan/headless_afl_arm9_blob tools/blocksds/hello_jit/hello_jit.nds
```

## Fuzzing with JIT enabled

The harness uses `NDSArgs` defaults, which include JIT when the build supports it.
To force JIT on in the build, set:
```
cmake --preset headless-afl-asan-ubsan -DENABLE_JIT=ON
cmake --build --preset headless-afl-asan-ubsan --target headless_afl
```

Notes:
- JIT is available on x86_64 builds.
- If you see crashes related to executable memory under sanitizers, try a non‑sanitized
  preset first (`headless-afl`), then add sanitizers incrementally.

## Priority runs for critical vulnerabilities (RCE / file read/write)

If you’re specifically hunting for high‑impact bugs, run these in order:

1) **AFL++ ASan+UBSan, JIT on**  
   Broad memory safety coverage with JIT active.  
   ```
   cmake --preset headless-afl-asan-ubsan -DENABLE_JIT=ON
   cmake --build --preset headless-afl-asan-ubsan --target headless_afl
   tools/aflplusplus/run_fuzz.sh headless-afl-asan-ubsan ./seeds ./out-asan-ubsan
   ```

2) **AFL++ (no sanitizers), JIT on**  
   Faster throughput and may find logic/edge issues that ASan slows down.  
   ```
   cmake --preset headless-afl -DENABLE_JIT=ON
   cmake --build --preset headless-afl --target headless_afl
   tools/aflplusplus/run_fuzz.sh headless-afl ./seeds ./out-fast
   ```

3) **AFL++ ASan+UBSan, JIT off**  
   Isolate core logic paths when JIT introduces noise.  
   ```
   cmake --preset headless-afl-asan-ubsan -DENABLE_JIT=OFF
   cmake --build --preset headless-afl-asan-ubsan --target headless_afl
   tools/aflplusplus/run_fuzz.sh headless-afl-asan-ubsan ./seeds ./out-asan-ubsan-nojit
   ```

4) **AFL++ MSan (JIT off)**  
   Uninitialized read detection; MSan generally conflicts with JIT and other sanitizers.  
   ```
   cmake --preset headless-afl-msan -DENABLE_JIT=OFF
   cmake --build --preset headless-afl-msan --target headless_afl
   tools/aflplusplus/run_fuzz.sh headless-afl-msan ./seeds ./out-msan
   ```

5) **AFL++ CFI (JIT off)**  
   Useful for control‑flow integrity issues in non‑JIT paths.  
   ```
   cmake --preset headless-afl-cfi -DENABLE_JIT=OFF
   cmake --build --preset headless-afl-cfi --target headless_afl
   tools/aflplusplus/run_fuzz.sh headless-afl-cfi ./seeds ./out-cfi
   ```

## Further improvements (targeted fuzzing)

For deeper bug discovery, consider adding focused harnesses for:
- **ROM parsing and cart handling** (NDS/DSi headers, secure area, save types)
- **Save formats** (SRAM/EEPROM/FLASH loaders)
- **Firmware parsing and settings** (SPI firmware structures)
- **Networking packet processing** (Wifi/LAN packet paths)
- **DSP/AAC paths** (if enabled and linked)

Targeted harnesses improve coverage and triage for specific security goals.
