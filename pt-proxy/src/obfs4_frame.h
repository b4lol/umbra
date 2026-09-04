/*
 * umbra-pt-proxy — obfs4 link framing (XSalsa20-Poly1305 secretbox
 * frames with SipHash-2-4-DRBG-obfuscated lengths).
 *
 * Wire format (lyrebird transports/obfs4/framing, the deployed
 * definition):
 *
 *     uint16 BE  obfsLen = (16 + payload_len) XOR mask16
 *     uint8[16]  Poly1305 tag
 *     uint8[]    ciphertext
 *
 * mask16 is the first two bytes (big-endian) of the next length-DRBG
 * block; the DRBG is the accumulating SipHash-2-4 construction from
 * siphash24.h (ONE block consumed per frame, at length-read time).
 *
 * The secretbox nonce is `prefix[16] | counter uint64 BE`; the counter
 * starts at 1, increments per successfully processed frame, and a wrap
 * is FATAL (a reused nonce breaks Poly1305).
 *
 * Security invariants:
 *  1. Fixed-size buffers only; payload ≤ 1430, frame body ≤ 1446.
 *  2. Decode enforces the length range [16, 1446]; an out-of-range
 *     length triggers the Bider countermeasure (consume a RANDOM
 *     in-range length, then fail with a forced tag mismatch) so an
 *     attacker flipping length bits learns nothing from early aborts.
 *  3. Keys and state are wiped on teardown (sodium_memzero).
 */

#ifndef UMBRA_PT_OBFS4_FRAME_H
#define UMBRA_PT_OBFS4_FRAME_H

#include "obfs4.h"
#include "siphash24.h"

#include <stddef.h>
#include <stdint.h>

#define OBFS4_FRAME_OVERHEAD 18u          /* 2 length + 16 tag */
#define OBFS4_MAX_SEGMENT_LEN 1448u       /* 1500 - (40 + 12) */
#define OBFS4_MAX_FRAME_PAYLOAD 1430u     /* segment - overhead */
#define OBFS4_MAX_FRAME_BODY 1446u        /* segment - 2 (tag+ct) */
#define OBFS4_MIN_FRAME_BODY 16u          /* tag only */
#define OBFS4_NONCE_LEN 24u

typedef struct {
    uint8_t key[OBFS4_SECRETBOX_KEY_LEN];
    uint8_t nonce_prefix[OBFS4_NONCE_PREFIX_LEN];
    uint64_t counter;
    SipHash24 drbg;
    uint8_t drbg_block[SIPHASH24_OUT_LEN];
} Obfs4FrameEncoder;

typedef struct {
    uint8_t key[OBFS4_SECRETBOX_KEY_LEN];
    uint8_t nonce_prefix[OBFS4_NONCE_PREFIX_LEN];
    uint64_t counter;
    SipHash24 drbg;
    uint8_t drbg_block[SIPHASH24_OUT_LEN];
    uint16_t next_len;                    /* 0 = length not yet read */
    int next_len_invalid;                 /* Bider countermeasure armed */
    uint8_t next_nonce[OBFS4_NONCE_LEN];
} Obfs4FrameDecoder;

/* Splits a per-direction key block (obfs4.h Obfs4DirKeys) into the
 * encoder/decoder state. */
void obfs4_frame_encoder_init(Obfs4FrameEncoder *enc,
                              const Obfs4DirKeys *keys);
void obfs4_frame_decoder_init(Obfs4FrameDecoder *dec,
                              const Obfs4DirKeys *keys);

/* Encodes one frame. `payload_len` must be ≤ OBFS4_MAX_FRAME_PAYLOAD;
 * `out` must hold payload_len + OBFS4_FRAME_OVERHEAD bytes. */
Obfs4Status obfs4_frame_encode(Obfs4FrameEncoder *enc,
                               const uint8_t *payload, size_t payload_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len);

/* Attempts to decode ONE frame from the caller-owned accumulation
 * buffer `buf` (holding `*buf_len` bytes). On OBFS4_OK the payload is
 * in `out` (capacity OBFS4_MAX_FRAME_PAYLOAD) and the frame's bytes are
 * consumed from `buf`. OBFS4_AGAIN: need more bytes. OBFS4_ERR: fatal
 * (tag mismatch, counter wrap, or the armed Bider path firing). */
Obfs4Status obfs4_frame_decode(Obfs4FrameDecoder *dec, uint8_t *buf,
                               size_t *buf_len, uint8_t *out,
                               size_t *out_len);

void obfs4_frame_encoder_wipe(Obfs4FrameEncoder *enc);
void obfs4_frame_decoder_wipe(Obfs4FrameDecoder *dec);

#endif /* UMBRA_PT_OBFS4_FRAME_H */
