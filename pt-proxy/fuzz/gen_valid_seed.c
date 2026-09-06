/*
 * ONE-SHOT, dev-tooling-only generator for
 * corpus/obfs4_handshake/valid_response. Never built by `make all` or
 * any fuzz/test target; regenerate manually only if fixtures.h changes
 * (see fuzz/README.md).
 *
 * Builds a genuinely valid obfs4 server response for the EXACT
 * deterministic client state fuzz_obfs4_handshake.c constructs from
 * fixtures.h (same cert, same client keypair, same epoch), using the
 * same server_ntor + HMAC-tail construction tests/mockbridge.c already
 * implements for the real end-to-end relay test. This is not new
 * protocol logic — it exists purely so the fuzzer's mutation engine
 * gets one structurally valid, correctly-sized starting point.
 */

#include "../src/obfs4.h"
#include "fixtures.h"

#include <sodium.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void hmac128(const uint8_t key[OBFS4_CERT_LEN], const uint8_t *a,
                    size_t a_len, const uint8_t *b, size_t b_len,
                    uint8_t out[16])
{
    uint8_t full[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;

    crypto_auth_hmacsha256_init(&st, key, OBFS4_CERT_LEN);
    crypto_auth_hmacsha256_update(&st, a, a_len);
    if (b != NULL && b_len > 0u) {
        crypto_auth_hmacsha256_update(&st, b, b_len);
    }
    crypto_auth_hmacsha256_final(&st, full);
    memcpy(out, full, 16u);
    sodium_memzero(full, sizeof(full));
    sodium_memzero(&st, sizeof(st));
}

/* Server-side ntor, identical construction to tests/mockbridge.c. */
static int server_ntor(const Obfs4Keypair *session, const uint8_t id_priv[32],
                       const Obfs4BridgeCert *cert,
                       const uint8_t client_pub[32], uint8_t auth[32])
{
    uint8_t exp_xy[32];
    uint8_t exp_xb[32];
    uint8_t secret_input[2u * 32u + 2u * 32u + 32u + 32u + 24u + 20u];
    uint8_t key_seed[32];
    uint8_t verify[32];
    crypto_auth_hmacsha256_state st;
    uint8_t *p = secret_input;
    static const uint8_t t_mac[] = "ntor-curve25519-sha256-1:mac";
    static const uint8_t t_key[] = "ntor-curve25519-sha256-1:key_extract";
    static const uint8_t t_verify[] = "ntor-curve25519-sha256-1:key_verify";
    static const uint8_t protoid[] = "ntor-curve25519-sha256-1";
    int rc = -1;

    if (crypto_scalarmult(exp_xy, session->priv, client_pub) != 0 ||
        crypto_scalarmult(exp_xb, id_priv, client_pub) != 0) {
        goto out;
    }

    memcpy(p, exp_xy, 32u); p += 32u;
    memcpy(p, exp_xb, 32u); p += 32u;
    memcpy(p, cert->server_public, 32u); p += 32u;
    memcpy(p, cert->server_public, 32u); p += 32u;
    memcpy(p, client_pub, 32u); p += 32u;
    memcpy(p, session->pub, 32u); p += 32u;
    memcpy(p, protoid, 24u); p += 24u;
    memcpy(p, cert->node_id, 20u);

    crypto_auth_hmacsha256_init(&st, t_key, sizeof(t_key) - 1u);
    crypto_auth_hmacsha256_update(&st, secret_input, sizeof(secret_input));
    crypto_auth_hmacsha256_final(&st, key_seed);

    crypto_auth_hmacsha256_init(&st, t_verify, sizeof(t_verify) - 1u);
    crypto_auth_hmacsha256_update(&st, secret_input, sizeof(secret_input));
    crypto_auth_hmacsha256_final(&st, verify);

    crypto_auth_hmacsha256_init(&st, t_mac, sizeof(t_mac) - 1u);
    crypto_auth_hmacsha256_update(&st, verify, sizeof(verify));
    crypto_auth_hmacsha256_update(&st, secret_input + 64u, sizeof(secret_input) - 64u);
    crypto_auth_hmacsha256_update(&st, (const uint8_t *)"Server", 6u);
    crypto_auth_hmacsha256_final(&st, auth);
    rc = 0;

out:
    sodium_memzero(exp_xy, sizeof(exp_xy));
    sodium_memzero(exp_xb, sizeof(exp_xb));
    sodium_memzero(secret_input, sizeof(secret_input));
    sodium_memzero(key_seed, sizeof(key_seed));
    sodium_memzero(verify, sizeof(verify));
    sodium_memzero(&st, sizeof(st));
    return rc;
}

/* Must match fuzz_obfs4_handshake.c's find_keypair exactly: both need
 * to derive the SAME client keypair from FUZZ_CLIENT_PRIV. */
static int find_keypair(Obfs4Keypair *kp, const uint8_t seed[32])
{
    unsigned int attempt;

    for (attempt = 0u; attempt < 256u; attempt++) {
        uint8_t material[33];
        uint8_t digest[crypto_hash_sha512_BYTES];

        memcpy(material, seed, 32u);
        material[32] = (uint8_t)attempt;
        crypto_hash_sha512(digest, material, sizeof(material));
        if (obfs4_keypair_from_seed(kp, digest, digest[63]) == OBFS4_OK) {
            sodium_memzero(digest, sizeof(digest));
            return 0;
        }
        sodium_memzero(digest, sizeof(digest));
    }
    return -1;
}

int main(void)
{
    Obfs4BridgeCert cert;
    Obfs4Keypair client_kp;
    Obfs4Keypair session;
    uint8_t mac_key[OBFS4_CERT_LEN];
    uint8_t auth[32];
    uint8_t resp[OBFS4_REPRESENTATIVE_LEN + 32u + 16u + 16u];
    uint8_t mark[16];
    uint8_t mac[16];
    size_t resp_len = OBFS4_REPRESENTATIVE_LEN + 32u;

    if (sodium_init() < 0) {
        return 1;
    }

    memcpy(cert.node_id, FUZZ_NODE_ID, sizeof(FUZZ_NODE_ID));
    if (crypto_scalarmult_base(cert.server_public, FUZZ_SERVER_ID_PRIV) != 0) {
        return 1;
    }
    if (find_keypair(&client_kp, FUZZ_CLIENT_PRIV) != 0 ||
        find_keypair(&session, FUZZ_SERVER_EPHEMERAL_PRIV) != 0) {
        return 1;
    }
    if (server_ntor(&session, FUZZ_SERVER_ID_PRIV, &cert, client_kp.pub, auth) != 0) {
        return 1;
    }

    memcpy(mac_key, cert.server_public, OBFS4_PUBLIC_LEN);
    memcpy(mac_key + OBFS4_PUBLIC_LEN, cert.node_id, OBFS4_NODE_ID_LEN);

    memcpy(resp, session.repr, OBFS4_REPRESENTATIVE_LEN);
    memcpy(resp + OBFS4_REPRESENTATIVE_LEN, auth, sizeof(auth));
    hmac128(mac_key, session.repr, OBFS4_REPRESENTATIVE_LEN, NULL, 0u, mark);
    memcpy(resp + resp_len, mark, 16u);
    resp_len += 16u;
    hmac128(mac_key, resp, resp_len, (const uint8_t *)FUZZ_EPOCH,
            sizeof(FUZZ_EPOCH) - 1u, mac);
    memcpy(resp + resp_len, mac, 16u);
    resp_len += 16u;

    fwrite(resp, 1u, resp_len, stdout);

    sodium_memzero(&client_kp, sizeof(client_kp));
    sodium_memzero(&session, sizeof(session));
    sodium_memzero(auth, sizeof(auth));
    sodium_memzero(mac_key, sizeof(mac_key));
    sodium_memzero(resp, sizeof(resp));
    return 0;
}
