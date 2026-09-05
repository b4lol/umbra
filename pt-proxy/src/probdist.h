/*
 * umbra-pt-proxy — weighted probability distribution for obfs4 traffic
 * shaping (lyrebird common/probdist/weighted_dist.go).
 *
 * The table (values/weights/alias/prob) is SEED-DETERMINISTIC and
 * replicated bit-exact via gorand (pinned by tests/vectors.c against
 * fixtures dumped from the Go reference). Sampling is CSPRNG-driven —
 * Go's own Sample() uses csrand (crypto/rand), so determinism ends at
 * the table by design, in both implementations.
 *
 * Scope: the obfs4 client uses UNIFORM weights (lyrebird's `-bias`
 * ScrambleSuit-style flag defaults to off and is never set by bridge
 * lines), so only the uniform generator is implemented.
 *
 * Invariants:
 *  1. At most OBFS4_DIST_MAX_VALUES table entries (Go clamps
 *     Intn(maxValues)+1 with maxValues=100); buffers are fixed-size.
 *  2. Sampling is constant-work and CSPRNG-driven; the table itself is
 *     public-quality (it leaks through the traffic shape by design).
 */

#ifndef UMBRA_PT_PROBDIST_H
#define UMBRA_PT_PROBDIST_H

#include "gorand.h"

#include <stdint.h>

#define OBFS4_DIST_MAX_VALUES 100

typedef struct {
    int32_t min_value;
    int32_t n;
    int32_t values[OBFS4_DIST_MAX_VALUES];
    int32_t alias[OBFS4_DIST_MAX_VALUES];
    double weights[OBFS4_DIST_MAX_VALUES];
    double prob[OBFS4_DIST_MAX_VALUES];
} Obfs4Dist;

/* (Re)builds the table for values in [0, max] from a 24-byte DRBG seed
 * (Go probdist.New/Reset with min=0, biased=false). `max` must be in
 * [1, 1448]; the callers pass framing.MaximumSegmentLength (1448) and
 * maxIATDelay (100). */
void probdist_reset(Obfs4Dist *d, int32_t max,
                    const uint8_t seed[GORAND_SEED_LEN]);

/* Draws one sample in [0, max] (Vose alias over the table; CSPRNG die
 * + coin, Go csrand parity). */
int32_t probdist_sample(Obfs4Dist *d);

/* Wipes the table. */
void probdist_wipe(Obfs4Dist *d);

#endif /* UMBRA_PT_PROBDIST_H */
