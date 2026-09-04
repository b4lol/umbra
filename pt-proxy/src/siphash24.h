/*
 * umbra-pt-proxy — streaming SipHash-2-4 (obfs4 length-mask DRBG).
 *
 * Why our own implementation: the obfs4 link layer derives the frame
 * length mask from a SipHash-2-4 hash object whose state PERSISTS
 * across frames (lyrebird common/drbg/hash_drbg.go): each 8-byte block
 * is absorbed into the same running hash and the digest is taken from
 * the accumulated input, i.e.
 *
 *     block[n] = SipHash24(key, block[0] | block[1] | ... | block[n-1])
 *
 * libsodium exposes only a one-shot SipHash-2-4, which cannot express
 * that. The reference algorithm (Aumasson & Bernstein, "SipHash: a fast
 * short-input PRF") is small and public; this implementation is pinned
 * down three ways in tests/vectors.c:
 *  1. byte-exact against vectors dumped from the Go reference,
 *  2. cross-checked against libsodium's one-shot siphash24 over the
 *     accumulated input for random inputs,
 *  3. round-tripped through the frame encoder/decoder.
 *
 * Constant-time: the rounds are pure arithmetic on the state; the
 * message length is public (frame lengths are visible on the wire).
 */

#ifndef UMBRA_PT_SIPHASH24_H
#define UMBRA_PT_SIPHASH24_H

#include <stddef.h>
#include <stdint.h>

#define SIPHASH24_KEY_LEN 16
#define SIPHASH24_OUT_LEN 8

typedef struct {
    uint64_t v[4];        /* running state */
    uint8_t tail[8];      /* partial block buffer */
    uint64_t total_len;   /* bytes absorbed so far (mod 2^64) */
} SipHash24;

/* Initializes the hash with a 16-byte key. */
void siphash24_init(SipHash24 *h, const uint8_t key[SIPHASH24_KEY_LEN]);

/* Absorbs msg into the running state (Go hash.Hash Write semantics). */
void siphash24_absorb(SipHash24 *h, const uint8_t *msg, size_t len);

/* Writes the digest of everything absorbed so far WITHOUT disturbing
 * the running state (Go hash.Hash Sum semantics). */
void siphash24_digest(const SipHash24 *h, uint8_t out[SIPHASH24_OUT_LEN]);

/* Wipes the state. */
void siphash24_wipe(SipHash24 *h);

#endif /* UMBRA_PT_SIPHASH24_H */
