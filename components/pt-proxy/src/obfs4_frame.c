/*
 * umbra-pt-proxy — obfs4 link framing. See obfs4_frame.h for the wire
 * format and the security invariants.
 */

#include "obfs4_frame.h"

#include <sodium.h>

#include <string.h>

/* The DRBG per frame: absorb the previous block into the RUNNING hash,
 * digest the accumulated input (Go common/drbg NextBlock). */
static void drbg_next_block(SipHash24 *drbg, uint8_t block[SIPHASH24_OUT_LEN])
{
    siphash24_absorb(drbg, block, SIPHASH24_OUT_LEN);
    siphash24_digest(drbg, block);
}

static void state_init(uint8_t *key_out, uint8_t *prefix_out,
                       uint64_t *counter_out, SipHash24 *drbg,
                       uint8_t block[SIPHASH24_OUT_LEN],
                       const Obfs4DirKeys *keys)
{
    memcpy(key_out, keys->secretbox_key, OBFS4_SECRETBOX_KEY_LEN);
    memcpy(prefix_out, keys->nonce_prefix, OBFS4_NONCE_PREFIX_LEN);
    *counter_out = 1u;
    siphash24_init(drbg, keys->siphash_key);
    memcpy(block, keys->siphash_iv, SIPHASH24_OUT_LEN);
}

/* nonce = prefix | counter BE64; returns OBFS4_ERR on counter wrap. */
static Obfs4Status nonce_bytes(const uint8_t prefix[OBFS4_NONCE_PREFIX_LEN],
                               uint64_t counter,
                               uint8_t out[OBFS4_NONCE_LEN])
{
    uint64_t be = counter;
    unsigned int i;

    if (counter == 0u) {
        return OBFS4_ERR; /* wrapped: nonce reuse would break Poly1305 */
    }
    memcpy(out, prefix, OBFS4_NONCE_PREFIX_LEN);
    for (i = 0; i < 8u; i++) {
        out[OBFS4_NONCE_PREFIX_LEN + i] =
            (uint8_t)(be >> (56u - 8u * i));
    }
    return OBFS4_OK;
}

void obfs4_frame_encoder_init(Obfs4FrameEncoder *enc,
                              const Obfs4DirKeys *keys)
{
    state_init(enc->key, enc->nonce_prefix, &enc->counter, &enc->drbg,
               enc->drbg_block, keys);
}

void obfs4_frame_decoder_init(Obfs4FrameDecoder *dec,
                              const Obfs4DirKeys *keys)
{
    state_init(dec->key, dec->nonce_prefix, &dec->counter, &dec->drbg,
               dec->drbg_block, keys);
    dec->next_len = 0u;
    dec->next_len_invalid = 0;
    memset(dec->next_nonce, 0, sizeof(dec->next_nonce));
}

Obfs4Status obfs4_frame_encode(Obfs4FrameEncoder *enc,
                               const uint8_t *payload, size_t payload_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len)
{
    uint8_t nonce[OBFS4_NONCE_LEN];
    uint16_t body_len;
    uint16_t mask;

    if (enc == NULL || payload == NULL || out == NULL || out_len == NULL) {
        return OBFS4_ERR;
    }
    if (payload_len > OBFS4_MAX_FRAME_PAYLOAD ||
        out_cap < payload_len + OBFS4_FRAME_OVERHEAD) {
        return OBFS4_ERR;
    }
    if (nonce_bytes(enc->nonce_prefix, enc->counter, nonce) != OBFS4_OK) {
        return OBFS4_ERR;
    }

    crypto_secretbox_easy(out + 2u, payload, payload_len, nonce, enc->key);
    body_len = (uint16_t)(payload_len + 16u);

    drbg_next_block(&enc->drbg, enc->drbg_block);
    mask = (uint16_t)(((uint16_t)enc->drbg_block[0] << 8u) |
                      (uint16_t)enc->drbg_block[1]);
    body_len ^= mask;
    out[0] = (uint8_t)(body_len >> 8u);
    out[1] = (uint8_t)(body_len & 0xffu);

    enc->counter += 1u;
    *out_len = payload_len + OBFS4_FRAME_OVERHEAD;
    sodium_memzero(nonce, sizeof(nonce));
    return OBFS4_OK;
}

Obfs4Status obfs4_frame_decode(Obfs4FrameDecoder *dec, uint8_t *buf,
                               size_t *buf_len, uint8_t *out,
                               size_t *out_len)
{
    uint8_t box[OBFS4_MAX_FRAME_BODY];

    if (dec == NULL || buf == NULL || buf_len == NULL || out == NULL ||
        out_len == NULL) {
        return OBFS4_ERR;
    }

    if (dec->next_len == 0u) {
        uint16_t obfs_len;
        uint16_t mask;
        uint16_t length;

        if (*buf_len < 2u) {
            return OBFS4_AGAIN;
        }
        /* Snapshot the nonce NOW (the counter only advances after a
         * successful decode, but the peer used the current value). */
        if (nonce_bytes(dec->nonce_prefix, dec->counter,
                        dec->next_nonce) != OBFS4_OK) {
            return OBFS4_ERR;
        }
        obfs_len = (uint16_t)(((uint16_t)buf[0] << 8u) | (uint16_t)buf[1]);
        drbg_next_block(&dec->drbg, dec->drbg_block);
        mask = (uint16_t)(((uint16_t)dec->drbg_block[0] << 8u) |
                          (uint16_t)dec->drbg_block[1]);
        length = (uint16_t)(obfs_len ^ mask);
        if (length < OBFS4_MIN_FRAME_BODY || length > OBFS4_MAX_FRAME_BODY) {
            /* Bider countermeasure: consume a RANDOM in-range length
             * and let the tag check fail afterwards, so a length-flip
             * attack gets no early-abort signal. */
            length = (uint16_t)(OBFS4_MIN_FRAME_BODY +
                                randombytes_uniform(OBFS4_MAX_FRAME_BODY -
                                                    OBFS4_MIN_FRAME_BODY + 1u));
            dec->next_len_invalid = 1;
        }
        dec->next_len = length;
        memmove(buf, buf + 2u, *buf_len - 2u);
        *buf_len -= 2u;
    }

    if (*buf_len < dec->next_len) {
        return OBFS4_AGAIN;
    }

    memcpy(box, buf, dec->next_len);
    memmove(buf, buf + dec->next_len, *buf_len - dec->next_len);
    *buf_len -= dec->next_len;

    if (dec->next_len_invalid != 0 ||
        crypto_secretbox_open_easy(out, box, dec->next_len,
                                   dec->next_nonce, dec->key) != 0) {
        sodium_memzero(box, sizeof(box));
        return OBFS4_ERR; /* tag mismatch (or the armed Bider path) */
    }
    sodium_memzero(box, sizeof(box));

    *out_len = (size_t)dec->next_len - 16u;
    dec->next_len = 0u;
    dec->next_len_invalid = 0;
    dec->counter += 1u;
    return OBFS4_OK;
}

void obfs4_frame_encoder_wipe(Obfs4FrameEncoder *enc)
{
    if (enc != NULL) {
        siphash24_wipe(&enc->drbg);
        sodium_memzero(enc, sizeof(*enc));
    }
}

void obfs4_frame_decoder_wipe(Obfs4FrameDecoder *dec)
{
    if (dec != NULL) {
        siphash24_wipe(&dec->drbg);
        sodium_memzero(dec, sizeof(*dec));
    }
}
