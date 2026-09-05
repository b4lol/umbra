/*
 * umbra-pt-proxy — Go math/rand.Rand semantics over the obfs4
 * SipHash-2-4-OFB DRBG (lyrebird common/drbg + math/rand/rand.go).
 *
 * Why this exists: probdist's table generation is seed-deterministic
 * via rand.New(drbg) — the DRBG is the same SipHash construction the
 * framing layer uses, so replicating Go's Rand helper semantics on top
 * of it reproduces the Go distribution tables BIT-EXACT (pinned by the
 * vectors in tests/vectors.c). The Go 1 compatibility promise freezes
 * these semantics.
 *
 * Only the deterministic generation path lives here; sampling uses the
 * CSPRNG (Go's csrand does the same).
 */

#ifndef UMBRA_PT_GORAND_H
#define UMBRA_PT_GORAND_H

#include "siphash24.h"

#include <stddef.h>
#include <stdint.h>

#define GORAND_SEED_LEN 24 /* 16-byte SipHash key + 8-byte OFB IV */

typedef struct {
    SipHash24 sip;
    uint8_t ofb[SIPHASH24_OUT_LEN];
} GoRand;

/* Initializes the generator from a 24-byte DRBG seed (key | IV). */
void gorand_init(GoRand *r, const uint8_t seed[GORAND_SEED_LEN]);

/* Go drbg.Int63: next OFB block, big-endian, top bit masked. */
int64_t gorand_int63(GoRand *r);

/* Go Rand.Int31: int32(Int63() >> 32). */
int32_t gorand_int31(GoRand *r);

/* Go Rand.Int31n: mask for powers of two, rejection otherwise
 * (max = (1<<31)-1 - (1<<31)%n). `n` must be > 0. */
int32_t gorand_int31n(GoRand *r, int32_t n);

/* Go Rand.Intn (n <= 2^31-1 domain — all we need). `n` must be > 0. */
int32_t gorand_intn(GoRand *r, int32_t n);

/* Go Rand.Float64: float64(Int63()) / (1<<63), resampled if the
 * division rounds up to exactly 1.0. */
double gorand_float64(GoRand *r);

/* Go Rand.Perm: inside-out Fisher–Yates over a ZERO-initialized buffer
 * (m[i] = m[j]; m[j] = i with j = Intn(i+1); the i=0 iteration is a
 * no-op that still consumes RNG state — Go 1 compat). `out` holds `n`
 * ints, zeroed by this function first. */
void gorand_perm(GoRand *r, int32_t *out, int32_t n);

/* Wipes the generator state. */
void gorand_wipe(GoRand *r);

#endif /* UMBRA_PT_GORAND_H */
