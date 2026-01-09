// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

static SEED_NOINLINE uint32_t cond_ops(uint32_t v)
{
    uint32_t out;
    __asm__ volatile(
        "cmp %1, #0\n"
        "addeq %0, %1, #1\n"
        "addne %0, %1, #2\n"
        "tst %1, #1\n"
        "eorne %0, %0, #0x10\n"
        "tst %1, #0x10\n"
        "addeq %0, %0, #0x20\n"
        : "=&r"(out)
        : "r"(v)
        : "cc"
    );
    return out;
}

__attribute__((used))
void seed_main(void)
{
    uint32_t v = 0x10101010u;
    for (unsigned i = 0; i < 16; i++)
    {
        v = cond_ops(v + i);
        v ^= seed_rotl32(v, (i & 7u) + 1u);
    }

    g_sink = v;
}
