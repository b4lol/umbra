/*
 * umbra-pt-proxy — streaming SipHash-2-4. See siphash24.h for why this
 * exists (Go's obfs4 length DRBG keeps ONE accumulating hash object)
 * and how it is pinned down in tests.
 *
 * The compression/decompression rounds below follow the public
 * reference algorithm exactly (Aumasson & Bernstein).
 */

#include "siphash24.h"

#include <sodium.h>

#include <string.h>

static uint64_t rotl64(uint64_t x, unsigned int b)
{
    return (x << b) | (x >> (64u - b));
}

static uint64_t load64_le(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned int i = 0; i < 8u; i++) {
        v |= (uint64_t)p[i] << (8u * i);
    }
    return v;
}

static void store64_le(uint8_t *p, uint64_t v)
{
    for (unsigned int i = 0; i < 8u; i++) {
        p[i] = (uint8_t)(v >> (8u * i));
    }
}

static void sipround(uint64_t v[4])
{
    v[0] += v[1];
    v[1] = rotl64(v[1], 13u);
    v[1] ^= v[0];
    v[0] = rotl64(v[0], 32u);
    v[2] += v[3];
    v[3] = rotl64(v[3], 16u);
    v[3] ^= v[2];
    v[0] += v[3];
    v[3] = rotl64(v[3], 21u);
    v[3] ^= v[0];
    v[2] += v[1];
    v[1] = rotl64(v[1], 17u);
    v[1] ^= v[2];
    v[2] = rotl64(v[2], 32u);
}

/* One full 8-byte message block: 2 rounds (SipHash-2-4). */
static void absorb_block(uint64_t v[4], uint64_t m)
{
    v[3] ^= m;
    sipround(v);
    sipround(v);
    v[0] ^= m;
}

void siphash24_init(SipHash24 *h, const uint8_t key[SIPHASH24_KEY_LEN])
{
    uint64_t k0 = load64_le(key);
    uint64_t k1 = load64_le(key + 8);

    h->v[0] = k0 ^ UINT64_C(0x736f6d6570736575);
    h->v[1] = k1 ^ UINT64_C(0x646f72616e646f6d);
    h->v[2] = k0 ^ UINT64_C(0x6c7967656e657261);
    h->v[3] = k1 ^ UINT64_C(0x7465646279746573);
    memset(h->tail, 0, sizeof(h->tail));
    h->total_len = 0;
}

void siphash24_absorb(SipHash24 *h, const uint8_t *msg, size_t len)
{
    size_t tail_len = (size_t)(h->total_len & 7u);
    size_t off = 0;

    if (tail_len > 0u) {
        /* Complete the pending partial block first. */
        size_t need = 8u - tail_len;
        size_t take = len < need ? len : need;
        memcpy(h->tail + tail_len, msg, take);
        tail_len += take;
        off += take;
        h->total_len += take;
        if (tail_len == 8u) {
            absorb_block(h->v, load64_le(h->tail));
        }
    }
    while (off + 8u <= len) {
        absorb_block(h->v, load64_le(msg + off));
        off += 8u;
        h->total_len += 8u;
    }
    if (off < len) {
        memcpy(h->tail, msg + off, len - off);
        h->total_len += len - off;
    }
}

void siphash24_digest(const SipHash24 *h, uint8_t out[SIPHASH24_OUT_LEN])
{
    SipHash24 tmp = *h; /* finalize a COPY: the caller's state runs on */
    uint64_t tail_len = tmp.total_len & 7u;
    uint64_t last = tmp.total_len << 56;
    uint64_t digest;
    uint64_t i;

    for (i = 0; i < tail_len; i++) {
        last |= (uint64_t)tmp.tail[i] << (8u * i);
    }
    absorb_block(tmp.v, last);

    tmp.v[2] ^= UINT64_C(0xff);
    for (i = 0; i < 4u; i++) {
        sipround(tmp.v);
    }
    digest = tmp.v[0] ^ tmp.v[1] ^ tmp.v[2] ^ tmp.v[3];
    store64_le(out, digest);
    sodium_memzero(&tmp, sizeof(tmp));
}

void siphash24_wipe(SipHash24 *h)
{
    sodium_memzero(h, sizeof(*h));
}
