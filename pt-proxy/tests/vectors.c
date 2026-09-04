/*
 * umbra-pt-proxy — byte-exact vector tests for the obfs4 handshake.
 *
 * The fixtures in vectors_fixtures.h were dumped from the Go reference
 * implementation (lyrebird) with fixed private keys, tweaks, padding
 * and epoch — see tests/govectors/README.md for regeneration. If this
 * file passes, the C handshake is byte-compatible with the deployed
 * obfs4 implementation for the covered paths.
 */

#include "../src/obfs4.h"

#include "../src/obfs4_frame.h"
#include "../src/obfs4_packet.h"
#include "../src/siphash24.h"

#include <sodium.h>

#include <stdio.h>
#include <string.h>

#include "vectors_fixtures.h"

static unsigned int failures;

#define CHECK(cond, name)                          \
    do {                                           \
        if (cond) {                                \
            printf("ok   %s\n", (name));           \
        } else {                                   \
            printf("FAIL %s\n", (name));           \
            failures++;                            \
        }                                          \
    } while (0)

static void test_elligator(void)
{
    static const uint8_t *const privs[4] = {
        vec_ell0_priv, vec_ell1_priv, vec_ell2_priv, vec_ell3_priv
    };
    static const uint8_t tweaks[4] = {
        VEC_ELL0_TWEAK, VEC_ELL1_TWEAK, VEC_ELL2_TWEAK, VEC_ELL3_TWEAK
    };
    static const int oks[4] = {
        VEC_ELL0_OK, VEC_ELL1_OK, VEC_ELL2_OK, VEC_ELL3_OK
    };
    static const uint8_t *const pubs[4] = {
        NULL, NULL, vec_ell2_pub, vec_ell3_pub
    };
    static const uint8_t *const reprs[4] = {
        NULL, NULL, vec_ell2_repr, vec_ell3_repr
    };
    char name[64];
    int i;

    for (i = 0; i < 4; i++) {
        Obfs4Keypair kp;
        Obfs4Status st = obfs4_keypair_from_seed(&kp, privs[i], tweaks[i]);
        int expect_ok = oks[i];

        snprintf(name, sizeof(name), "elligator keygen #%d status", i);
        CHECK((st == OBFS4_OK) == (expect_ok != 0), name);
        if (st != OBFS4_OK) {
            continue;
        }
        snprintf(name, sizeof(name), "elligator keygen #%d public", i);
        CHECK(memcmp(kp.pub, pubs[i], OBFS4_PUBLIC_LEN) == 0, name);
        snprintf(name, sizeof(name), "elligator keygen #%d representative", i);
        CHECK(memcmp(kp.repr, reprs[i], OBFS4_REPRESENTATIVE_LEN) == 0, name);
        obfs4_client_wipe((Obfs4ClientHandshake *)NULL); /* no-op guard */
        sodium_memzero(&kp, sizeof(kp));
    }

    /* Representative -> public round trip. */
    {
        uint8_t pub[OBFS4_PUBLIC_LEN];
        obfs4_representative_to_public(pub, vec_ell2_repr);
        CHECK(memcmp(pub, vec_ell2_pub, OBFS4_PUBLIC_LEN) == 0,
              "elligator map round trip");
        sodium_memzero(pub, sizeof(pub));
    }
}

static void test_cert(void)
{
    Obfs4BridgeCert cert;

    CHECK(obfs4_cert_parse(&cert, VEC_CERT_B64) == OBFS4_OK, "cert parse");
    CHECK(memcmp(cert.node_id, vec_node_id, OBFS4_NODE_ID_LEN) == 0,
          "cert node id");
    CHECK(memcmp(cert.server_public, vec_server_id_pub,
                 OBFS4_PUBLIC_LEN) == 0,
          "cert server public");

    CHECK(obfs4_cert_parse(&cert, "too-short") == OBFS4_ERR,
          "cert rejects short input");
    CHECK(obfs4_cert_parse(&cert, NULL) == OBFS4_ERR,
          "cert rejects NULL");
    {
        /* Valid length, invalid base64 character. */
        char bad[OBFS4_CERT_B64_LEN + 1];
        memcpy(bad, VEC_CERT_B64, sizeof(bad));
        bad[0] = '!';
        CHECK(obfs4_cert_parse(&cert, bad) == OBFS4_ERR,
              "cert rejects invalid base64");
    }
}

static void test_handshake(void)
{
    Obfs4BridgeCert cert;
    Obfs4ClientHandshake hs;
    Obfs4SessionKeys keys;
    uint8_t out[OBFS4_CLIENT_MIN_HANDSHAKE_LEN + OBFS4_CLIENT_MAX_PAD_LEN];
    size_t out_len = 0u;
    size_t consumed = 0u;
    uint8_t okm[OBFS4_OKM_LEN];

    if (obfs4_cert_parse(&cert, VEC_CERT_B64) != OBFS4_OK) {
        CHECK(0, "handshake setup: cert parse");
        return;
    }

    /* Deterministic keypair injection: init for the cert, then replace
     * the random keypair with the fixture one. */
    if (obfs4_client_init(&hs, &cert) != OBFS4_OK) {
        CHECK(0, "handshake setup: client init");
        return;
    }
    if (obfs4_keypair_from_seed(&hs.keypair, vec_client_priv,
                                VEC_CLIENT_TWEAK) != OBFS4_OK) {
        CHECK(0, "handshake setup: fixture keypair");
        obfs4_client_wipe(&hs);
        return;
    }

    /* The client request must equal the Go reference byte-for-byte. */
    CHECK(obfs4_client_request_with(&hs, vec_pad_c, sizeof(vec_pad_c),
                                    VEC_EPOCH, out, sizeof(out),
                                    &out_len) == OBFS4_OK,
          "client request builds");
    CHECK(out_len == sizeof(vec_request), "client request length");
    CHECK(out_len == sizeof(vec_request) &&
              memcmp(out, vec_request, out_len) == 0,
          "client request bytes match Go reference");

    /* Incomplete responses must yield AGAIN. */
    CHECK(obfs4_client_finish(&hs, vec_response, 10u, &keys,
                              &consumed) == OBFS4_AGAIN,
          "finish: tiny response is AGAIN");
    CHECK(obfs4_client_finish(&hs, vec_response,
                              sizeof(vec_response) - 1u, &keys,
                              &consumed) == OBFS4_AGAIN,
          "finish: truncated response is AGAIN");

    /* The full response completes the handshake with byte-exact keys. */
    CHECK(obfs4_client_finish(&hs, vec_response, sizeof(vec_response),
                              &keys, &consumed) == OBFS4_OK,
          "finish: full response accepted");
    CHECK(consumed == sizeof(vec_response), "finish: consumed length");
    CHECK(memcmp(keys.key_seed, vec_key_seed, OBFS4_KEY_SEED_LEN) == 0,
          "KEY_SEED matches Go reference");

    memcpy(okm, keys.send.secretbox_key, OBFS4_SECRETBOX_KEY_LEN);
    memcpy(okm + OBFS4_SECRETBOX_KEY_LEN, keys.send.nonce_prefix,
           OBFS4_NONCE_PREFIX_LEN);
    memcpy(okm + OBFS4_SECRETBOX_KEY_LEN + OBFS4_NONCE_PREFIX_LEN,
           keys.send.siphash_key, OBFS4_SIPHASH_KEY_LEN);
    memcpy(okm + OBFS4_SECRETBOX_KEY_LEN + OBFS4_NONCE_PREFIX_LEN +
               OBFS4_SIPHASH_KEY_LEN,
           keys.send.siphash_iv, OBFS4_SIPHASH_IV_LEN);
    memcpy(okm + OBFS4_DIR_KEY_LEN, keys.recv.secretbox_key,
           OBFS4_SECRETBOX_KEY_LEN);
    memcpy(okm + OBFS4_DIR_KEY_LEN + OBFS4_SECRETBOX_KEY_LEN,
           keys.recv.nonce_prefix, OBFS4_NONCE_PREFIX_LEN);
    memcpy(okm + OBFS4_DIR_KEY_LEN + OBFS4_SECRETBOX_KEY_LEN +
               OBFS4_NONCE_PREFIX_LEN,
           keys.recv.siphash_key, OBFS4_SIPHASH_KEY_LEN);
    memcpy(okm + OBFS4_DIR_KEY_LEN + OBFS4_SECRETBOX_KEY_LEN +
               OBFS4_NONCE_PREFIX_LEN + OBFS4_SIPHASH_KEY_LEN,
           keys.recv.siphash_iv, OBFS4_SIPHASH_IV_LEN);
    CHECK(memcmp(okm, vec_okm, OBFS4_OKM_LEN) == 0,
          "144-byte HKDF key block matches Go reference");

    /* Negative: flip one MAC_S bit -> fatal. */
    {
        uint8_t bad[sizeof(vec_response)];
        memcpy(bad, vec_response, sizeof(bad));
        bad[sizeof(bad) - 1u] ^= 0x01u;
        CHECK(obfs4_client_finish(&hs, bad, sizeof(bad), &keys,
                                  &consumed) == OBFS4_ERR,
              "finish: corrupted MAC_S rejected");
    }

    /* Negative: flip one AUTH bit -> fatal. */
    {
        uint8_t bad[sizeof(vec_response)];
        memcpy(bad, vec_response, sizeof(bad));
        bad[OBFS4_REPRESENTATIVE_LEN] ^= 0x01u;
        CHECK(obfs4_client_finish(&hs, bad, sizeof(bad), &keys,
                                  &consumed) == OBFS4_ERR,
              "finish: corrupted AUTH rejected");
    }

    /* Negative: a full-length buffer without the mark -> fatal. */
    {
        static uint8_t huge[OBFS4_MAX_HANDSHAKE_LEN];
        memset(huge, 0x5a, sizeof(huge));
        CHECK(obfs4_client_finish(&hs, huge, sizeof(huge), &keys,
                                  &consumed) == OBFS4_ERR,
              "finish: 8192 bytes without mark rejected");
    }

    obfs4_session_keys_wipe(&keys);
    obfs4_client_wipe(&hs);
    sodium_memzero(out, sizeof(out));
    sodium_memzero(okm, sizeof(okm));
}

/* Splits the fixture's 72-byte direction block into Obfs4DirKeys. */
static void dir_keys_from_vec(Obfs4DirKeys *dk)
{
    memcpy(dk->secretbox_key, vec_dir_keys, OBFS4_SECRETBOX_KEY_LEN);
    memcpy(dk->nonce_prefix, vec_dir_keys + OBFS4_SECRETBOX_KEY_LEN,
           OBFS4_NONCE_PREFIX_LEN);
    memcpy(dk->siphash_key,
           vec_dir_keys + OBFS4_SECRETBOX_KEY_LEN + OBFS4_NONCE_PREFIX_LEN,
           OBFS4_SIPHASH_KEY_LEN);
    memcpy(dk->siphash_iv,
           vec_dir_keys + OBFS4_SECRETBOX_KEY_LEN + OBFS4_NONCE_PREFIX_LEN +
               OBFS4_SIPHASH_KEY_LEN,
           OBFS4_SIPHASH_IV_LEN);
}

static void test_siphash(void)
{
    /* Byte-exact against the Go DRBG: seed = key|IV, then 16 rounds of
     * absorb(previous block) + digest-of-accumulated-input. */
    {
        SipHash24 h;
        uint8_t block[SIPHASH24_OUT_LEN];
        uint8_t all[16u * SIPHASH24_OUT_LEN];
        size_t i;

        siphash24_init(&h, vec_drbg_seed); /* first 16 bytes = key */
        memcpy(block, vec_drbg_seed + SIPHASH24_KEY_LEN,
               SIPHASH24_OUT_LEN);
        for (i = 0; i < 16u; i++) {
            siphash24_absorb(&h, block, SIPHASH24_OUT_LEN);
            siphash24_digest(&h, block);
            memcpy(all + i * SIPHASH24_OUT_LEN, block,
                   SIPHASH24_OUT_LEN);
        }
        CHECK(memcmp(all, vec_drbg_blocks, sizeof(all)) == 0,
              "siphash DRBG matches Go reference (16 blocks)");
        siphash24_wipe(&h);
        sodium_memzero(all, sizeof(all));
    }

    /* Property cross-check: our streaming digest over arbitrary input
     * must equal libsodium's one-shot SipHash-2-4, including odd tail
     * lengths and split absorbs. */
    {
        unsigned int iter;
        int ok = 1;

        for (iter = 0u; iter < 200u && ok; iter++) {
            uint8_t key[SIPHASH24_KEY_LEN];
            uint8_t msg[300];
            uint8_t want[SIPHASH24_OUT_LEN];
            uint8_t got[SIPHASH24_OUT_LEN];
            size_t len = randombytes_uniform(sizeof(msg) + 1u);
            size_t split = len == 0u ? 0u : randombytes_uniform(
                                               (unsigned int)len + 1u);
            SipHash24 h;

            randombytes_buf(key, sizeof(key));
            randombytes_buf(msg, len);
            crypto_shorthash_siphash24(want, msg, len, key);

            siphash24_init(&h, key);
            siphash24_absorb(&h, msg, split);   /* split absorb */
            siphash24_absorb(&h, msg + split, len - split);
            siphash24_digest(&h, got);
            if (memcmp(want, got, SIPHASH24_OUT_LEN) != 0) {
                ok = 0;
            }
            /* The digest must not disturb the running state: absorb
             * more and compare against the one-shot of msg|more. */
            if (ok) {
                uint8_t more[37];
                uint8_t joined[sizeof(msg) + sizeof(more)];

                randombytes_buf(more, sizeof(more));
                siphash24_absorb(&h, more, sizeof(more));
                siphash24_digest(&h, got);
                memcpy(joined, msg, len);
                memcpy(joined + len, more, sizeof(more));
                crypto_shorthash_siphash24(want, joined,
                                           len + sizeof(more), key);
                if (memcmp(want, got, SIPHASH24_OUT_LEN) != 0) {
                    ok = 0;
                }
            }
            siphash24_wipe(&h);
            sodium_memzero(msg, sizeof(msg));
        }
        CHECK(ok, "siphash streaming == libsodium one-shot (200 random)");
    }
}

static void test_framing(void)
{
    Obfs4DirKeys dk;
    Obfs4FrameEncoder enc;
    Obfs4FrameDecoder dec;
    uint8_t out[OBFS4_MAX_SEGMENT_LEN];
    uint8_t wire[sizeof(vec_frames_wire)];
    size_t out_len = 0u;
    size_t wire_len = 0u;

    dir_keys_from_vec(&dk);

    /* Encode: byte-exact wire equality with the Go reference. */
    obfs4_frame_encoder_init(&enc, &dk);
    CHECK(obfs4_frame_encode(&enc, vec_payload1, sizeof(vec_payload1),
                             wire, sizeof(wire), &out_len) == OBFS4_OK,
          "frame encode #1");
    wire_len += out_len;
    CHECK(obfs4_frame_encode(&enc, vec_payload2, sizeof(vec_payload2),
                             wire + wire_len, sizeof(wire) - wire_len,
                             &out_len) == OBFS4_OK,
          "frame encode #2");
    wire_len += out_len;
    CHECK(wire_len == sizeof(vec_frames_wire) &&
              memcmp(wire, vec_frames_wire, wire_len) == 0,
          "frame wire bytes match Go reference");

    /* Oversized payload is rejected before touching the wire. */
    {
        uint8_t big[OBFS4_MAX_FRAME_PAYLOAD + 1u];
        memset(big, 0x41, sizeof(big));
        CHECK(obfs4_frame_encode(&enc, big, sizeof(big), out,
                                 sizeof(out), &out_len) == OBFS4_ERR,
              "frame encode rejects oversized payload");
        sodium_memzero(big, sizeof(big));
    }
    obfs4_frame_encoder_wipe(&enc);

    /* Decode: feed the wire in 7-byte crumbs (exercises AGAIN), expect
     * the two payloads back in order. */
    obfs4_frame_decoder_init(&dec, &dk);
    {
        uint8_t acc[2u * OBFS4_MAX_SEGMENT_LEN];
        size_t acc_len = 0u;
        size_t fed = 0u;
        unsigned int frames = 0u;
        int ok = 1;

        while (fed < wire_len && ok) {
            size_t step = wire_len - fed < 7u ? wire_len - fed : 7u;
            memcpy(acc + acc_len, wire + fed, step);
            acc_len += step;
            fed += step;
            for (;;) {
                size_t dlen = 0u;
                Obfs4Status st = obfs4_frame_decode(&dec, acc, &acc_len,
                                                    out, &dlen);
                if (st == OBFS4_AGAIN) {
                    break;
                }
                if (st != OBFS4_OK) {
                    ok = 0;
                    break;
                }
                if (frames == 0u &&
                    (dlen != sizeof(vec_payload1) ||
                     memcmp(out, vec_payload1, dlen) != 0)) {
                    ok = 0;
                }
                if (frames == 1u &&
                    (dlen != sizeof(vec_payload2) ||
                     memcmp(out, vec_payload2, dlen) != 0)) {
                    ok = 0;
                }
                frames++;
            }
        }
        CHECK(ok && frames == 2u, "frame decode round-trip (7-byte feeds)");
        sodium_memzero(acc, sizeof(acc));
    }

    /* Negative: one flipped ciphertext bit kills the tag. */
    {
        uint8_t bad[sizeof(vec_frames_wire)];
        uint8_t acc[sizeof(vec_frames_wire)];
        size_t acc_len;
        size_t dlen = 0u;

        memcpy(bad, vec_frames_wire, sizeof(bad));
        bad[2u + 5u] ^= 0x01u; /* inside frame 1's tag */
        obfs4_frame_decoder_wipe(&dec);
        obfs4_frame_decoder_init(&dec, &dk);
        memcpy(acc, bad, sizeof(bad));
        acc_len = sizeof(bad);
        /* First decode returns frame-1 attempt: tag mismatch -> ERR. */
        CHECK(obfs4_frame_decode(&dec, acc, &acc_len, out, &dlen) ==
                  OBFS4_ERR,
              "frame decode: corrupted tag is fatal");
        sodium_memzero(acc, sizeof(acc));
    }

    /* Negative: an out-of-range length arms the Bider path and the
     * frame fails closed afterwards. Setting the obfuscated length
     * equal to the first DRBG mask block forces decoded length 0,
     * which is below the 16-byte minimum — deterministically invalid. */
    {
        uint8_t acc[sizeof(vec_frames_wire)];
        size_t acc_len;
        size_t dlen = 0u;

        memcpy(acc, vec_frames_wire, sizeof(acc));
        acc[0] = vec_drbg_blocks[0];
        acc[1] = vec_drbg_blocks[1];
        acc_len = sizeof(acc);
        obfs4_frame_decoder_wipe(&dec);
        obfs4_frame_decoder_init(&dec, &dk);
        /* The buffer (1474 B) covers any random in-range Bider length
         * (≤ 1446+2), so the armed frame is consumed and MUST fail. */
        CHECK(obfs4_frame_decode(&dec, acc, &acc_len, out, &dlen) ==
                  OBFS4_ERR,
              "frame decode: out-of-range length fails closed (Bider)");
        sodium_memzero(acc, sizeof(acc));
    }

    obfs4_frame_decoder_wipe(&dec);
    sodium_memzero(out, sizeof(out));
    sodium_memzero(wire, sizeof(wire));
    sodium_memzero(&dk, sizeof(dk));
}

static void test_packet(void)
{
    Obfs4DirKeys dk;
    Obfs4FrameEncoder enc;
    Obfs4FrameDecoder dec;
    uint8_t out[OBFS4_MAX_SEGMENT_LEN];
    size_t out_len = 0u;
    static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};

    dir_keys_from_vec(&dk);

    /* Byte-exact: payload packet "hello" with 11 zero padding bytes. */
    obfs4_frame_encoder_init(&enc, &dk);
    CHECK(obfs4_packet_encode(&enc, OBFS4_PACKET_TYPE_PAYLOAD, hello,
                              sizeof(hello), 11u, out, sizeof(out),
                              &out_len) == OBFS4_OK,
          "packet encode");
    CHECK(out_len == sizeof(vec_packet_wire) &&
              memcmp(out, vec_packet_wire, out_len) == 0,
          "packet wire bytes match Go reference");
    obfs4_frame_encoder_wipe(&enc);

    /* Parse: the same frame back through decoder + packet parser. */
    obfs4_frame_decoder_init(&dec, &dk);
    {
        uint8_t acc[OBFS4_MAX_SEGMENT_LEN];
        uint8_t decoded[OBFS4_MAX_FRAME_PAYLOAD];
        size_t acc_len = sizeof(vec_packet_wire);
        size_t dlen = 0u;
        Obfs4PacketKind kind = OBFS4_PKT_IGNORED;
        const uint8_t *payload = NULL;
        size_t payload_len = 0u;

        memcpy(acc, vec_packet_wire, acc_len);
        CHECK(obfs4_frame_decode(&dec, acc, &acc_len, decoded, &dlen) ==
                      OBFS4_OK &&
                  obfs4_packet_parse(decoded, dlen, &kind, &payload,
                                     &payload_len) == OBFS4_OK &&
                  kind == OBFS4_PKT_PAYLOAD &&
                  payload_len == sizeof(hello) &&
                  memcmp(payload, hello, sizeof(hello)) == 0,
              "packet round-trip (hello + padding)");
        sodium_memzero(acc, sizeof(acc));
        sodium_memzero(decoded, sizeof(decoded));
    }
    obfs4_frame_decoder_wipe(&dec);

    /* Malformed/boundary packets. */
    {
        Obfs4PacketKind kind = OBFS4_PKT_IGNORED;
        const uint8_t *payload = NULL;
        size_t payload_len = 0u;
        uint8_t pkt[8];

        /* Header shorter than the packet overhead. */
        CHECK(obfs4_packet_parse(pkt, 2u, &kind, &payload,
                                 &payload_len) == OBFS4_ERR,
              "packet parse: short header rejected");

        /* Payload length overruns the frame. */
        pkt[0] = OBFS4_PACKET_TYPE_PAYLOAD;
        pkt[1] = 0xffu;
        pkt[2] = 0xffu;
        CHECK(obfs4_packet_parse(pkt, sizeof(pkt), &kind, &payload,
                                 &payload_len) == OBFS4_ERR,
              "packet parse: payload overrun rejected");

        /* Unknown types are ignored, not fatal. */
        pkt[0] = 0x77u;
        pkt[1] = 0x00u;
        pkt[2] = 0x00u;
        CHECK(obfs4_packet_parse(pkt, sizeof(pkt), &kind, &payload,
                                 &payload_len) == OBFS4_OK &&
                  kind == OBFS4_PKT_IGNORED,
              "packet parse: unknown type ignored");

        /* A 24-byte PRNG seed packet is accepted and ignored. */
        pkt[0] = OBFS4_PACKET_TYPE_PRNG_SEED;
        pkt[1] = 0x00u;
        pkt[2] = OBFS4_SEED_PAYLOAD_LEN;
        {
            uint8_t seed_pkt[OBFS4_PACKET_OVERHEAD + OBFS4_SEED_PAYLOAD_LEN];
            memcpy(seed_pkt, pkt, OBFS4_PACKET_OVERHEAD);
            memset(seed_pkt + OBFS4_PACKET_OVERHEAD, 0xa5,
                   OBFS4_SEED_PAYLOAD_LEN);
            CHECK(obfs4_packet_parse(seed_pkt, sizeof(seed_pkt), &kind,
                                     &payload, &payload_len) ==
                          OBFS4_OK &&
                      kind == OBFS4_PKT_SEED,
                  "packet parse: seed packet accepted-and-ignored");
            sodium_memzero(seed_pkt, sizeof(seed_pkt));
        }
        sodium_memzero(pkt, sizeof(pkt));
    }

    sodium_memzero(&dk, sizeof(dk));
}

int main(void)
{
    if (sodium_init() < 0) {
        printf("FAIL libsodium init\n");
        return 1;
    }

    test_elligator();
    test_cert();
    test_handshake();
    test_siphash();
    test_framing();
    test_packet();

    if (failures != 0u) {
        printf("%u check(s) FAILED\n", failures);
        return 1;
    }
    printf("all vector checks passed\n");
    return 0;
}
