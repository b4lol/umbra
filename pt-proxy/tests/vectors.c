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

int main(void)
{
    if (sodium_init() < 0) {
        printf("FAIL libsodium init\n");
        return 1;
    }

    test_elligator();
    test_cert();
    test_handshake();

    if (failures != 0u) {
        printf("%u check(s) FAILED\n", failures);
        return 1;
    }
    printf("all vector checks passed\n");
    return 0;
}
