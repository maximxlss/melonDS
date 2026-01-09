// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

static SEED_NOINLINE uint32_t f0(uint32_t v) { return seed_mix32(v + 0x10u); }
static SEED_NOINLINE uint32_t f1(uint32_t v) { return seed_rotl32(v ^ 0x20u, 3); }
static SEED_NOINLINE uint32_t f2(uint32_t v) { return (v + (v << 1)) ^ 0x30u; }
static SEED_NOINLINE uint32_t f3(uint32_t v) { return (v >> 2) + 0x40u; }

typedef uint32_t (*OpFn)(uint32_t);

__attribute__((used))
void seed_main(void)
{
    static const OpFn ops[] = { f0, f1, f2, f3 };
    uint32_t v = 0x2468ACE0u;

    for (unsigned i = 0; i < 16; i++)
    {
        v = ops[i & 3u](v);
        if (v & 1u)
            v = ops[(i + 1u) & 3u](v);
        g_mem[i] = v;
    }

    g_sink = v ^ seed_sum_mem(g_mem, 16);
}
