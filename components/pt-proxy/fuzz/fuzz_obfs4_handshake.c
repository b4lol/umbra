/*
 * libFuzzer harness for obfs4_client_finish — the obfs4 handshake
 * RESPONSE parser. This is the highest-value fuzz target in the
 * proxy: every byte it consumes comes straight off the wire from
 * whatever answers the bridge connection, hostile or merely broken,
 * before any cryptographic validation has succeeded.
 *
 * Honest scope note (see fuzz/README.md for the full version): mutation
 * alone cannot forge a valid MAC_S/AUTH, so random/mutated input almost
 * never reaches the post-authentication code (key derivation,
 * direction-key split) — that logic is exhaustively covered instead by
 * `make vectors` / `make relay-test` / `make interop-test` (byte-exact
 * against the Go reference, and a live round trip against the real
 * upstream server). What THIS harness actually exercises, thoroughly,
 * is the fully untrusted pre-authentication surface every response
 * must pass through regardless of validity: the variable-length tail
 * mark/MAC scan across the whole length range, offset arithmetic
 * around it, and OBFS4_AGAIN/OBFS4_ERR classification — exactly the
 * surface a hostile or malfunctioning bridge fully controls.
 */

#include "../src/obfs4.h"
#include "fixtures.h"

#include <sodium.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Fixed, deterministic client handshake template built once; each
 * fuzz iteration works on a fresh stack copy (obfs4_client_finish and
 * its OBFS4_ERR path wipe secrets in place, so the template itself
 * must never be mutated in place). */
static Obfs4ClientHandshake g_template;

/* Bounded retry mirroring the real keygen loop (obfs4_client_init):
 * not every PUBLIC KEY has an Elligator 2 representative (~50% do,
 * independent of the tweak byte, which only disambiguates which valid
 * encoding is returned when one exists) — so, exactly like the
 * production retry loop, each attempt re-derives a fresh candidate
 * private key via SHA-512, not just a new tweak over the same one.
 * Fully deterministic — the "entropy" is a counter, not the CSPRNG. */
static int find_keypair(Obfs4Keypair *kp, const uint8_t seed[OBFS4_PRIVATE_LEN])
{
    unsigned int attempt;

    for (attempt = 0u; attempt < 256u; attempt++) {
        uint8_t material[OBFS4_PRIVATE_LEN + 1u];
        uint8_t digest[crypto_hash_sha512_BYTES];

        memcpy(material, seed, OBFS4_PRIVATE_LEN);
        material[OBFS4_PRIVATE_LEN] = (uint8_t)attempt;
        crypto_hash_sha512(digest, material, sizeof(material));
        if (obfs4_keypair_from_seed(kp, digest, digest[63]) == OBFS4_OK) {
            sodium_memzero(digest, sizeof(digest));
            return 0;
        }
        sodium_memzero(digest, sizeof(digest));
    }
    return -1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    uint8_t pad[FUZZ_PAD_LEN];
    uint8_t throwaway[OBFS4_CLIENT_MIN_HANDSHAKE_LEN + OBFS4_CLIENT_MAX_PAD_LEN];
    size_t throwaway_len = 0u;

    (void)argc;
    (void)argv;

    if (sodium_init() < 0) {
        abort();
    }

    memcpy(g_template.cert.node_id, FUZZ_NODE_ID, sizeof(FUZZ_NODE_ID));
    if (crypto_scalarmult_base(g_template.cert.server_public, FUZZ_SERVER_ID_PRIV) != 0) {
        abort();
    }

    if (find_keypair(&g_template.keypair, FUZZ_CLIENT_PRIV) != 0) {
        abort();
    }

    /* Deterministic fixed padding; only obfs4_client_request_with's
     * side effect of recording hs->epoch matters here — the actual
     * request bytes are discarded. */
    memset(pad, 0x42, sizeof(pad));
    if (obfs4_client_request_with(&g_template, pad, sizeof(pad), FUZZ_EPOCH,
                                  throwaway, sizeof(throwaway),
                                  &throwaway_len) != OBFS4_OK) {
        abort();
    }
    sodium_memzero(pad, sizeof(pad));
    sodium_memzero(throwaway, sizeof(throwaway));

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Obfs4ClientHandshake hs = g_template;
    Obfs4SessionKeys keys;
    uint8_t buf[OBFS4_MAX_HANDSHAKE_LEN];
    size_t len = size < sizeof(buf) ? size : sizeof(buf);
    size_t consumed = 0u;

    memset(&keys, 0, sizeof(keys));
    memcpy(buf, data, len);

    /* Every outcome (OK/AGAIN/ERR) is acceptable; only a crash, an
     * ASan finding or a UBSan finding counts as a bug here. */
    (void)obfs4_client_finish(&hs, buf, len, &keys, &consumed);

    sodium_memzero(buf, sizeof(buf));
    obfs4_client_wipe(&hs);
    obfs4_session_keys_wipe(&keys);
    return 0;
}
