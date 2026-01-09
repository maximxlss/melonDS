// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

static SEED_NOINLINE uint32_t op0(uint32_t v)
{
    return seed_mix32(v + 0x11111111u);
}

static SEED_NOINLINE uint32_t op1(uint32_t v)
{
    return seed_rotl32(v ^ 0x22222222u, 5);
}

static SEED_NOINLINE uint32_t op2(uint32_t v)
{
    return v + (v << 3) + 0x33333333u;
}

static SEED_NOINLINE uint32_t op3(uint32_t v)
{
    return (v ^ (v >> 7)) + 0x44444444u;
}

typedef uint32_t (*OpFn)(uint32_t);

__attribute__((used))
void seed_main(void)
{
    static const OpFn ops[] = { op0, op1, op2, op3 };
    uint32_t v = 0x0BADF00Du;

    for (unsigned i = 0; i < 16; i++)
    {
        v = ops[i & 3u](v);
        g_mem[i] = v;
    }

    v ^= seed_sum_mem(g_mem, 16);
    g_sink = v;
}
