# jit_seeds (BlocksDS)

Minimal ARM9 ROMs for the ARM9 blob harness. These avoid the BlocksDS runtime
and provide small, focused code patterns to exercise JIT paths.

Seeds:
- `seed_arith`: ALU, shifts, multiply, mix/rotate patterns.
- `seed_branches`: branches, switch/jumptable, state-machine style flow.
- `seed_memory`: byte/halfword/word memory traffic and pointer arithmetic.
- `seed_table`: indirect calls via function pointer table.
- `seed_smc`: self-modifying code stub in RAM.
- `seed_thumb_branches`: Thumb-heavy control flow and gotos.
- `seed_thumb_calls`: Thumb function pointer dispatch.
- `seed_thumb_stack`: Thumb stack usage (locals + push/pop).
- `seed_thumb_shifts`: Thumb shifts/rotates and bit twiddling.
- `seed_thumb_unaligned`: unaligned byte/halfword/word memory traffic.
- `seed_arm_cond`: ARM conditional instructions and flag behavior.
- `seed_arm_ldm`: ARM load/store multiple (ldm/stm) patterns.

Build all ROMs:
```
make
```

Build and extract ARM9 blobs into `seeds/`:
```
make seeds
```

If BlocksDS is not installed at `/opt/blocksds/core`, set `BLOCKSDS`:
```
BLOCKSDS=/opt/wonderful/thirdparty/blocksds/core make seeds
```
