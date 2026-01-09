// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#pragma once

#include <stdint.h>
#include <stdbool.h>

#define SEED_NOINLINE __attribute__((noinline))

extern volatile uint32_t g_sink;
extern volatile uint32_t g_mem[64];

static inline void seed_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

static inline uint32_t seed_rotl32(uint32_t v, unsigned s)
{
    s &= 31u;
    if (s == 0)
        return v;
    return (v << s) | (v >> (32u - s));
}

static inline uint32_t seed_mix32(uint32_t v)
{
    v ^= v << 13;
    v ^= v >> 17;
    v ^= v << 5;
    return v;
}

static inline uint32_t seed_xorshift32(uint32_t *state)
{
    uint32_t v = *state;
    v ^= v << 13;
    v ^= v >> 17;
    v ^= v << 5;
    *state = v;
    return v;
}

static inline uint32_t seed_sum_mem(const volatile uint32_t *p, unsigned n)
{
    uint32_t sum = 0;
    for (unsigned i = 0; i < n; i++)
        sum += p[i];
    return sum;
}

static inline void seed_fill_mem(uint32_t seed)
{
    for (unsigned i = 0; i < 64; i++)
        g_mem[i] = seed ^ (i * 0x9E3779B9u);
}

