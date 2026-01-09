# hello_jit (BlocksDS)

Minimal ARM9 ROM intended as a base ROM for the ARM9 blob harness.

Build (example):
```
make
```

If BlocksDS is not installed at `/opt/blocksds/core`, set `BLOCKSDS`:
```
BLOCKSDS=/opt/wonderful/thirdparty/blocksds/core make
```

The resulting `.nds` can be used as the base ROM for `headless_afl_arm9_blob`,
and `tools/aflplusplus/extract_arm9_blob.sh` can extract the ARM9 segment into
`seeds/arm9.bin`. After rebuilding, re-run the extract script to refresh a
smaller seed.
