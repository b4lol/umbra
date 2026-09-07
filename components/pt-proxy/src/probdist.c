/* See probdist.h for the contract and the parity notes. */

#include "probdist.h"

#include <sodium.h>

#include <string.h>

/* Go's genValues: Perm over the FULL [0, max] range (the permutation
 * consumes RNG state even for entries that are later dropped), then
 * n = Intn(100)+1 entries are kept. The full permutation needs
 * (max+1) ints on the stack — 1449 * 4 B ≈ 5.8 KiB, fine. */
#define PROBDIST_PERM_CAP 1449

void probdist_reset(Obfs4Dist *d, int32_t max,
                    const uint8_t seed[GORAND_SEED_LEN])
{
    int32_t full[PROBDIST_PERM_CAP];
    GoRand rng;
    double sum = 0.0;
    double scaled[OBFS4_DIST_MAX_VALUES];
    /* FIFO worklists (Go container/list PushBack + Remove(Front)). */
    int32_t small[OBFS4_DIST_MAX_VALUES];
    int32_t large[OBFS4_DIST_MAX_VALUES];
    size_t small_head = 0u, small_tail = 0u;
    size_t large_head = 0u, large_tail = 0u;
    int32_t i;

    d->min_value = 0;
    gorand_init(&rng, seed);

    gorand_perm(&rng, full, max + 1);
    d->n = gorand_intn(&rng, OBFS4_DIST_MAX_VALUES) + 1;
    memcpy(d->values, full, (size_t)d->n * sizeof(*full));
    sodium_memzero(full, sizeof(full));

    /* Uniform weights (the obfs4 client never sets the bias flag). */
    for (i = 0; i < d->n; i++) {
        d->weights[i] = gorand_float64(&rng);
    }
    gorand_wipe(&rng);

    /* Vose's alias method, worklist order exactly as the Go code. */
    memset(d->alias, 0, sizeof(d->alias));
    memset(d->prob, 0, sizeof(d->prob));
    for (i = 0; i < d->n; i++) {
        sum += d->weights[i];
    }
    for (i = 0; i < d->n; i++) {
        scaled[i] = d->weights[i] * (double)d->n / sum;
        if (scaled[i] < 1.0) {
            small[small_tail++] = i;
        } else {
            large[large_tail++] = i;
        }
    }
    while (small_head < small_tail && large_head < large_tail) {
        int32_t l = small[small_head++];
        int32_t g = large[large_head++];

        d->prob[l] = scaled[l];
        d->alias[l] = g;
        scaled[g] = (scaled[g] + scaled[l]) - 1.0;
        if (scaled[g] < 1.0) {
            small[small_tail++] = g;
        } else {
            large[large_tail++] = g;
        }
    }
    while (large_head < large_tail) {
        d->prob[large[large_head++]] = 1.0;
    }
    /* Reachable only through floating-point instability; Go parity. */
    while (small_head < small_tail) {
        d->prob[small[small_head++]] = 1.0;
    }
    sodium_memzero(scaled, sizeof(scaled));
}

/* CSPRNG double in [0,1), same construction as Go's Float64 over a
 * crypto source (csrand): Int63 / 2^63, resampled on a 1.0 round-up. */
static double probdist_csprng_float64(void)
{
    uint8_t buf[8];
    uint64_t v;
    double f;

    for (;;) {
        unsigned int i;
        randombytes_buf(buf, sizeof(buf));
        v = 0;
        for (i = 0; i < 8u; i++) {
            v = (v << 8) | (uint64_t)buf[i];
        }
        v &= (((uint64_t)1u) << 63) - 1u;
        f = (double)v / 9223372036854775808.0;
        if (f != 1.0) {
            break;
        }
    }
    sodium_memzero(buf, sizeof(buf));
    return f;
}

int32_t probdist_sample(Obfs4Dist *d)
{
    int32_t i = (int32_t)randombytes_uniform((uint32_t)d->n);
    int32_t idx;

    if (probdist_csprng_float64() <= d->prob[i]) {
        idx = i;
    } else {
        idx = d->alias[i];
    }
    return d->min_value + d->values[idx];
}

void probdist_wipe(Obfs4Dist *d)
{
    if (d != NULL) {
        sodium_memzero(d, sizeof(*d));
    }
}
