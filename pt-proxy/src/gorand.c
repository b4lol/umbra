/* See gorand.h for the contract. */

#include "gorand.h"

#include <sodium.h>

#include <string.h>

/* One DRBG step: absorb the previous OFB block, digest the accumulated
 * stream (lyrebird hash_drbg.go NextBlock). */
static void gorand_next_block(GoRand *r)
{
    siphash24_absorb(&r->sip, r->ofb, SIPHASH24_OUT_LEN);
    siphash24_digest(&r->sip, r->ofb);
}

void gorand_init(GoRand *r, const uint8_t seed[GORAND_SEED_LEN])
{
    siphash24_init(&r->sip, seed);
    memcpy(r->ofb, seed + SIPHASH24_KEY_LEN, SIPHASH24_OUT_LEN);
}

int64_t gorand_int63(GoRand *r)
{
    uint64_t v = 0;
    unsigned int i;

    gorand_next_block(r);
    for (i = 0; i < 8u; i++) {
        v = (v << 8) | (uint64_t)r->ofb[i];
    }
    v &= (((uint64_t)1u) << 63) - 1u;
    return (int64_t)v;
}

int32_t gorand_int31(GoRand *r)
{
    return (int32_t)((uint64_t)gorand_int63(r) >> 32);
}

int32_t gorand_int31n(GoRand *r, int32_t n)
{
    int32_t v;

    if ((n & (n - 1)) == 0) { /* power of two: mask */
        return gorand_int31(r) & (n - 1);
    }
    {
        uint32_t max =
            (((uint32_t)1u) << 31) - 1u - ((((uint32_t)1u) << 31) % (uint32_t)n);
        v = gorand_int31(r);
        while ((uint32_t)v > max) {
            v = gorand_int31(r);
        }
    }
    return v % n;
}

int32_t gorand_intn(GoRand *r, int32_t n)
{
    return gorand_int31n(r, n);
}

double gorand_float64(GoRand *r)
{
    double f;

    for (;;) {
        /* 2^63 as a double is exact; the division rounds to nearest,
         * matching float64(Int63()) / (1 << 63) in Go. */
        f = (double)(uint64_t)gorand_int63(r) / 9223372036854775808.0;
        if (f != 1.0) {
            return f;
        }
        /* Rounded up to exactly 1.0: Go resamples (O(never)). */
    }
}

void gorand_perm(GoRand *r, int32_t *out, int32_t n)
{
    int32_t i;

    memset(out, 0, (size_t)n * sizeof(*out));
    for (i = 0; i < n; i++) {
        int32_t j = gorand_intn(r, i + 1);
        out[i] = out[j];
        out[j] = i;
    }
}

void gorand_wipe(GoRand *r)
{
    if (r != NULL) {
        siphash24_wipe(&r->sip);
        sodium_memzero(r->ofb, sizeof(r->ofb));
    }
}
