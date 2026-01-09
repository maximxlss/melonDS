// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

typedef uint32_t (*Thunk)(void);

__attribute__((used))
void seed_main(void)
{
    static volatile uint16_t code_buf[2] __attribute__((aligned(2))) = {
        0x2001, // movs r0, #1
        0x4770  // bx lr
    };

    Thunk fn = (Thunk)((uintptr_t)code_buf | 1u);

    uint32_t r0 = fn();

    code_buf[0] = 0x2002; // movs r0, #2
    seed_barrier();
    uint32_t r1 = fn();

    code_buf[0] = 0x2003; // movs r0, #3
    seed_barrier();
    uint32_t r2 = fn();

    g_sink = r0 | (r1 << 4) | (r2 << 8);
}
