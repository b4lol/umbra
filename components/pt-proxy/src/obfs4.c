/*
 * umbra-pt-proxy — obfs4 client handshake. See obfs4.h for the wire
 * layout, the ntor KDF derivation and the security invariants.
 *
 * Crypto providers:
 *  - libsodium: X25519 ECDH, HMAC-SHA256, HKDF-SHA256, SHA-512, CSPRNG,
 *    constant-time compare, secure wipe.
 *  - vendored Monocypher: Elligator 2 + the "dirty" X25519 basepoint
 *    multiplication only (Go's x25519ell2 is derived from Monocypher,
 *    so the representative conventions match byte-for-byte).
 */

#include "obfs4.h"

#include <sodium.h>

#include "../vendor/monocypher/monocypher.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* ntor protocol labels (common/ntor/ntor.go). Lengths are derived from
 * the arrays themselves — a hand-counted length here silently corrupts
 * the KDF (an earlier 34-vs-35 off-by-one did exactly that). */
static const uint8_t obfs4_protoid[] = "ntor-curve25519-sha256-1";
#define OBFS4_PROTOID_LEN (sizeof(obfs4_protoid) - 1u)
static const uint8_t obfs4_t_mac[] = "ntor-curve25519-sha256-1:mac";
#define OBFS4_T_MAC_LEN (sizeof(obfs4_t_mac) - 1u)
static const uint8_t obfs4_t_key[] = "ntor-curve25519-sha256-1:key_extract";
#define OBFS4_T_KEY_LEN (sizeof(obfs4_t_key) - 1u)
static const uint8_t obfs4_t_verify[] = "ntor-curve25519-sha256-1:key_verify";
#define OBFS4_T_VERIFY_LEN (sizeof(obfs4_t_verify) - 1u)
static const uint8_t obfs4_m_expand[] = "ntor-curve25519-sha256-1:key_expand";
#define OBFS4_M_EXPAND_LEN (sizeof(obfs4_m_expand) - 1u)
static const uint8_t obfs4_server_str[] = "Server";
#define OBFS4_SERVER_STR_LEN (sizeof(obfs4_server_str) - 1u)

/* Elligator keygen retry bound: each attempt fails with probability
 * ~1/2, so 64 attempts fail overall with probability ~2^-64. The loop
 * MUST stay bounded (invariant 5). */
#define OBFS4_KEYGEN_MAX_ATTEMPTS 64u

/* Offset of M_S inside the server response (Y' | AUTH, then padding). */
#define OBFS4_SERVER_MARK_OFFSET \
    (OBFS4_REPRESENTATIVE_LEN + OBFS4_AUTH_LEN)

static int obfs4_ensure_sodium(void)
{
    return sodium_init() < 0 ? OBFS4_ERR : OBFS4_OK;
}

/* HMAC-SHA256-128 keyed with B | NODEID over the concatenation of the
 * two input slices (b may be NULL when b_len is 0). */
static void obfs4_hmac128(const Obfs4BridgeCert *cert, const uint8_t *a,
                          size_t a_len, const uint8_t *b, size_t b_len,
                          uint8_t out[OBFS4_MARK_LEN])
{
    uint8_t key[OBFS4_CERT_LEN];
    uint8_t full[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;

    memcpy(key, cert->server_public, OBFS4_PUBLIC_LEN);
    memcpy(key + OBFS4_PUBLIC_LEN, cert->node_id, OBFS4_NODE_ID_LEN);

    crypto_auth_hmacsha256_init(&st, key, sizeof(key));
    crypto_auth_hmacsha256_update(&st, a, a_len);
    if (b != NULL && b_len > 0u) {
        crypto_auth_hmacsha256_update(&st, b, b_len);
    }
    crypto_auth_hmacsha256_final(&st, full);

    memcpy(out, full, OBFS4_MARK_LEN);
    sodium_memzero(key, sizeof(key));
    sodium_memzero(full, sizeof(full));
    sodium_memzero(&st, sizeof(st));
}

int obfs4_cert_parse(Obfs4BridgeCert *out, const char *cert_b64)
{
    char padded[OBFS4_CERT_B64_LEN + 2u + 1u];
    uint8_t raw[OBFS4_CERT_LEN];
    size_t len;
    size_t raw_len = 0u;

    if (out == NULL || cert_b64 == NULL) {
        return OBFS4_ERR;
    }
    if (obfs4_ensure_sodium() != OBFS4_OK) {
        return OBFS4_ERR;
    }

    len = strlen(cert_b64);
    if (len == OBFS4_CERT_B64_LEN) {
        /* Unpadded bridge-line form: restore the stripped "==". */
        memcpy(padded, cert_b64, len);
        padded[len] = '=';
        padded[len + 1u] = '=';
        padded[len + 2u] = '\0';
    } else if (len == OBFS4_CERT_B64_LEN + 2u &&
               cert_b64[len - 1u] == '=' && cert_b64[len - 2u] == '=') {
        memcpy(padded, cert_b64, len + 1u);
    } else {
        return OBFS4_ERR;
    }

    if (sodium_base642bin(raw, sizeof(raw), padded, strlen(padded), NULL,
                          &raw_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        sodium_memzero(raw, sizeof(raw));
        return OBFS4_ERR;
    }
    if (raw_len != OBFS4_CERT_LEN) {
        sodium_memzero(raw, sizeof(raw));
        return OBFS4_ERR;
    }

    memcpy(out->node_id, raw, OBFS4_NODE_ID_LEN);
    memcpy(out->server_public, raw + OBFS4_NODE_ID_LEN, OBFS4_PUBLIC_LEN);
    sodium_memzero(raw, sizeof(raw));
    return OBFS4_OK;
}

void obfs4_representative_to_public(uint8_t pub[OBFS4_PUBLIC_LEN],
                                    const uint8_t repr[OBFS4_REPRESENTATIVE_LEN])
{
    crypto_elligator_map(pub, repr);
}

Obfs4Status obfs4_keypair_from_seed(Obfs4Keypair *kp,
                                    const uint8_t priv[OBFS4_PRIVATE_LEN],
                                    uint8_t tweak)
{
    if (kp == NULL || priv == NULL) {
        return OBFS4_ERR;
    }
    /* Dirty basepoint multiplication (cofactor NOT cleared) — required
     * for the representative to match Go's x25519ell2.ScalarBaseMult. */
    crypto_x25519_dirty_fast(kp->pub, priv);
    if (crypto_elligator_rev(kp->repr, kp->pub, tweak) != 0) {
        sodium_memzero(kp, sizeof(*kp));
        return OBFS4_ERR;
    }
    memcpy(kp->priv, priv, OBFS4_PRIVATE_LEN);
    return OBFS4_OK;
}

Obfs4Status obfs4_client_init(Obfs4ClientHandshake *hs,
                              const Obfs4BridgeCert *cert)
{
    uint8_t entropy[OBFS4_PRIVATE_LEN];
    uint8_t digest[crypto_hash_sha512_BYTES];
    unsigned int attempt;
    Obfs4Status st = OBFS4_ERR;

    if (hs == NULL || cert == NULL) {
        return OBFS4_ERR;
    }
    if (obfs4_ensure_sodium() != OBFS4_OK) {
        return OBFS4_ERR;
    }

    memcpy(&hs->cert, cert, sizeof(hs->cert));
    hs->epoch[0] = '\0';

    /* Go keygen parity (common/ntor NewKeypair): hash the CSPRNG output
     * with SHA-512, private = digest[0:32], tweak = digest[63]. */
    for (attempt = 0u; attempt < OBFS4_KEYGEN_MAX_ATTEMPTS; attempt++) {
        randombytes_buf(entropy, sizeof(entropy));
        crypto_hash_sha512(digest, entropy, sizeof(entropy));
        st = obfs4_keypair_from_seed(&hs->keypair, digest, digest[63]);
        sodium_memzero(entropy, sizeof(entropy));
        sodium_memzero(digest, sizeof(digest));
        if (st == OBFS4_OK) {
            return OBFS4_OK;
        }
    }
    sodium_memzero(&hs->keypair, sizeof(hs->keypair));
    return OBFS4_ERR;
}

Obfs4Status obfs4_client_request_with(Obfs4ClientHandshake *hs,
                                      const uint8_t *pad, size_t pad_len,
                                      const char *epoch, uint8_t *out,
                                      size_t out_cap, size_t *out_len)
{
    size_t epoch_len;
    size_t total;

    if (hs == NULL || out == NULL || out_len == NULL || epoch == NULL ||
        (pad == NULL && pad_len > 0u)) {
        return OBFS4_ERR;
    }
    if (pad_len < OBFS4_CLIENT_MIN_PAD_LEN ||
        pad_len > OBFS4_CLIENT_MAX_PAD_LEN) {
        return OBFS4_ERR;
    }
    epoch_len = strlen(epoch);
    if (epoch_len == 0u || epoch_len >= sizeof(hs->epoch)) {
        return OBFS4_ERR;
    }
    total = (size_t)OBFS4_REPRESENTATIVE_LEN + pad_len +
            (size_t)OBFS4_MARK_LEN + (size_t)OBFS4_MAC_LEN;
    if (out_cap < total) {
        return OBFS4_ERR;
    }

    /* Record the epoch: the MAC_S check must use the SENT value. */
    memcpy(hs->epoch, epoch, epoch_len + 1u);

    /* X' | P_C | M_C */
    memcpy(out, hs->keypair.repr, OBFS4_REPRESENTATIVE_LEN);
    if (pad_len > 0u) {
        memcpy(out + OBFS4_REPRESENTATIVE_LEN, pad, pad_len);
    }
    obfs4_hmac128(&hs->cert, hs->keypair.repr, OBFS4_REPRESENTATIVE_LEN,
                  NULL, 0u, out + OBFS4_REPRESENTATIVE_LEN + pad_len);

    /* MAC_C = HMAC(B|NODEID, X' | P_C | M_C | E) */
    obfs4_hmac128(&hs->cert, out,
                  (size_t)OBFS4_REPRESENTATIVE_LEN + pad_len +
                      (size_t)OBFS4_MARK_LEN,
                  (const uint8_t *)epoch, epoch_len,
                  out + OBFS4_REPRESENTATIVE_LEN + pad_len +
                      OBFS4_MARK_LEN);

    *out_len = total;
    return OBFS4_OK;
}

Obfs4Status obfs4_client_request(Obfs4ClientHandshake *hs, uint8_t *out,
                                 size_t out_cap, size_t *out_len)
{
    uint8_t pad[OBFS4_CLIENT_MAX_PAD_LEN];
    char epoch[sizeof(hs->epoch)];
    size_t pad_len;
    Obfs4Status st;

    if (hs == NULL || out == NULL || out_len == NULL) {
        return OBFS4_ERR;
    }
    if (obfs4_ensure_sodium() != OBFS4_OK) {
        return OBFS4_ERR;
    }

    pad_len = (size_t)randombytes_uniform(
                  OBFS4_CLIENT_MAX_PAD_LEN - OBFS4_CLIENT_MIN_PAD_LEN + 1u) +
              (size_t)OBFS4_CLIENT_MIN_PAD_LEN;
    randombytes_buf(pad, pad_len);

    /* E = ASCII decimal hours since the UNIX epoch. */
    if (snprintf(epoch, sizeof(epoch), "%lld",
                 (long long)(time(NULL) / 3600)) <= 0) {
        sodium_memzero(pad, sizeof(pad));
        return OBFS4_ERR;
    }

    st = obfs4_client_request_with(hs, pad, pad_len, epoch, out, out_cap,
                                   out_len);
    sodium_memzero(pad, sizeof(pad));
    return st;
}

/* Constant-time-ish substring scan for the mark, mirroring the Go
 * client's bytes.Index over buf[64:endPos]: first hit wins, and the
 * hit must leave room for the trailing MAC. The mark is public
 * (derived from the received Y'), so data-dependent early exit here
 * leaks nothing secret. */
static long obfs4_find_mark(const uint8_t *resp, size_t resp_len,
                            const uint8_t mark[OBFS4_MARK_LEN])
{
    size_t end = resp_len;
    size_t pos;

    if (end > OBFS4_MAX_HANDSHAKE_LEN) {
        end = OBFS4_MAX_HANDSHAKE_LEN;
    }
    if (end < (size_t)OBFS4_SERVER_MARK_OFFSET +
                  (size_t)OBFS4_MARK_LEN + (size_t)OBFS4_MAC_LEN) {
        return -1;
    }
    for (pos = OBFS4_SERVER_MARK_OFFSET;
         pos + OBFS4_MARK_LEN + OBFS4_MAC_LEN <= end; pos++) {
        if (memcmp(resp + pos, mark, OBFS4_MARK_LEN) == 0) {
            return (long)pos;
        }
    }
    return -1;
}

Obfs4Status obfs4_client_finish(Obfs4ClientHandshake *hs,
                                const uint8_t *resp, size_t resp_len,
                                Obfs4SessionKeys *keys, size_t *consumed)
{
    uint8_t mark[OBFS4_MARK_LEN];
    uint8_t mac[OBFS4_MAC_LEN];
    uint8_t server_pub[OBFS4_PUBLIC_LEN];
    uint8_t exp_yx[OBFS4_PUBLIC_LEN];
    uint8_t exp_bx[OBFS4_PUBLIC_LEN];
    uint8_t secret_input[2u * OBFS4_PUBLIC_LEN + 2u * OBFS4_PUBLIC_LEN +
                         OBFS4_PUBLIC_LEN + OBFS4_PUBLIC_LEN +
                         OBFS4_PROTOID_LEN + OBFS4_NODE_ID_LEN];
    uint8_t verify[crypto_auth_hmacsha256_BYTES];
    uint8_t auth[crypto_auth_hmacsha256_BYTES];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    uint8_t okm[OBFS4_OKM_LEN];
    crypto_auth_hmacsha256_state hst;
    long mark_pos;
    Obfs4Status st = OBFS4_ERR;
    size_t epoch_len;

    if (hs == NULL || resp == NULL || keys == NULL || consumed == NULL) {
        return OBFS4_ERR;
    }
    if (obfs4_ensure_sodium() != OBFS4_OK) {
        return OBFS4_ERR;
    }
    if (resp_len < OBFS4_SERVER_MIN_HANDSHAKE_LEN) {
        return OBFS4_AGAIN;
    }
    epoch_len = strlen(hs->epoch);
    if (epoch_len == 0u) {
        return OBFS4_ERR; /* request was never generated */
    }

    /* M_S = HMAC(B|NODEID, Y') */
    obfs4_hmac128(&hs->cert, resp, OBFS4_REPRESENTATIVE_LEN, NULL, 0u,
                  mark);

    mark_pos = obfs4_find_mark(resp, resp_len, mark);
    if (mark_pos < 0) {
        sodium_memzero(mark, sizeof(mark));
        return resp_len >= OBFS4_MAX_HANDSHAKE_LEN ? OBFS4_ERR
                                                   : OBFS4_AGAIN;
    }

    /* MAC_S = HMAC(B|NODEID, Y' | AUTH | P_S | M_S | E) */
    obfs4_hmac128(&hs->cert, resp, (size_t)mark_pos + OBFS4_MARK_LEN,
                  (const uint8_t *)hs->epoch, epoch_len, mac);
    if (sodium_memcmp(mac, resp + mark_pos + OBFS4_MARK_LEN,
                      OBFS4_MAC_LEN) != 0) {
        goto out;
    }

    /* Y = Elligator2 map of Y'; then the client ntor half. */
    crypto_elligator_map(server_pub, resp);
    if (crypto_scalarmult(exp_yx, hs->keypair.priv, server_pub) != 0) {
        goto out; /* all-zero contributory output */
    }
    if (crypto_scalarmult(exp_bx, hs->keypair.priv,
                          hs->cert.server_public) != 0) {
        goto out;
    }

    /* secret_input = EXP(Y,x) | EXP(B,x) | B | B | X | Y | PROTOID |
     * NODEID — B twice, then the PLAIN public keys (not the
     * representatives), in X|Y order (common/ntor/ntor.go). */
    {
        uint8_t *p = secret_input;
        memcpy(p, exp_yx, OBFS4_PUBLIC_LEN);
        p += OBFS4_PUBLIC_LEN;
        memcpy(p, exp_bx, OBFS4_PUBLIC_LEN);
        p += OBFS4_PUBLIC_LEN;
        memcpy(p, hs->cert.server_public, OBFS4_PUBLIC_LEN);
        p += OBFS4_PUBLIC_LEN;
        memcpy(p, hs->cert.server_public, OBFS4_PUBLIC_LEN);
        p += OBFS4_PUBLIC_LEN;
        memcpy(p, hs->keypair.pub, OBFS4_PUBLIC_LEN);
        p += OBFS4_PUBLIC_LEN;
        memcpy(p, server_pub, OBFS4_PUBLIC_LEN);
        p += OBFS4_PUBLIC_LEN;
        memcpy(p, obfs4_protoid, OBFS4_PROTOID_LEN);
        p += OBFS4_PROTOID_LEN;
        memcpy(p, hs->cert.node_id, OBFS4_NODE_ID_LEN);
    }

    /* KEY_SEED = HMAC-SHA256(t_key, secret_input) */
    crypto_auth_hmacsha256_init(&hst, obfs4_t_key, OBFS4_T_KEY_LEN);
    crypto_auth_hmacsha256_update(&hst, secret_input,
                                  sizeof(secret_input));
    crypto_auth_hmacsha256_final(&hst, keys->key_seed);

    /* verify = HMAC-SHA256(t_verify, secret_input) */
    crypto_auth_hmacsha256_init(&hst, obfs4_t_verify, OBFS4_T_VERIFY_LEN);
    crypto_auth_hmacsha256_update(&hst, secret_input,
                                  sizeof(secret_input));
    crypto_auth_hmacsha256_final(&hst, verify);

    /* AUTH = HMAC-SHA256(t_mac, verify | B | B | X | Y | PROTOID |
     * NODEID | "Server") */
    crypto_auth_hmacsha256_init(&hst, obfs4_t_mac, OBFS4_T_MAC_LEN);
    crypto_auth_hmacsha256_update(&hst, verify, sizeof(verify));
    crypto_auth_hmacsha256_update(&hst,
                                  secret_input + 2u * OBFS4_PUBLIC_LEN,
                                  sizeof(secret_input) -
                                      2u * OBFS4_PUBLIC_LEN);
    crypto_auth_hmacsha256_update(&hst, obfs4_server_str,
                                  OBFS4_SERVER_STR_LEN);
    crypto_auth_hmacsha256_final(&hst, auth);

    if (sodium_memcmp(auth, resp + OBFS4_REPRESENTATIVE_LEN,
                      OBFS4_AUTH_LEN) != 0) {
        goto out;
    }

    /* okm = HKDF-SHA256(KEY_SEED, salt=t_key, info=m_expand, 144). */
    crypto_kdf_hkdf_sha256_extract(prk, obfs4_t_key, OBFS4_T_KEY_LEN,
                                   keys->key_seed, OBFS4_KEY_SEED_LEN);
    if (crypto_kdf_hkdf_sha256_expand(okm, sizeof(okm),
                                      (const char *)obfs4_m_expand,
                                      OBFS4_M_EXPAND_LEN, prk) != 0) {
        goto out;
    }

    /* Client sends with okm[0:72], receives with okm[72:144]. */
    memcpy(keys->send.secretbox_key, okm, OBFS4_SECRETBOX_KEY_LEN);
    memcpy(keys->send.nonce_prefix, okm + OBFS4_SECRETBOX_KEY_LEN,
           OBFS4_NONCE_PREFIX_LEN);
    memcpy(keys->send.siphash_key,
           okm + OBFS4_SECRETBOX_KEY_LEN + OBFS4_NONCE_PREFIX_LEN,
           OBFS4_SIPHASH_KEY_LEN);
    memcpy(keys->send.siphash_iv,
           okm + OBFS4_SECRETBOX_KEY_LEN + OBFS4_NONCE_PREFIX_LEN +
               OBFS4_SIPHASH_KEY_LEN,
           OBFS4_SIPHASH_IV_LEN);
    memcpy(keys->recv.secretbox_key, okm + OBFS4_DIR_KEY_LEN,
           OBFS4_SECRETBOX_KEY_LEN);
    memcpy(keys->recv.nonce_prefix,
           okm + OBFS4_DIR_KEY_LEN + OBFS4_SECRETBOX_KEY_LEN,
           OBFS4_NONCE_PREFIX_LEN);
    memcpy(keys->recv.siphash_key,
           okm + OBFS4_DIR_KEY_LEN + OBFS4_SECRETBOX_KEY_LEN +
               OBFS4_NONCE_PREFIX_LEN,
           OBFS4_SIPHASH_KEY_LEN);
    memcpy(keys->recv.siphash_iv,
           okm + OBFS4_DIR_KEY_LEN + OBFS4_SECRETBOX_KEY_LEN +
               OBFS4_NONCE_PREFIX_LEN + OBFS4_SIPHASH_KEY_LEN,
           OBFS4_SIPHASH_IV_LEN);

    *consumed = (size_t)mark_pos + OBFS4_MARK_LEN + OBFS4_MAC_LEN;
    st = OBFS4_OK;

out:
    sodium_memzero(mark, sizeof(mark));
    sodium_memzero(mac, sizeof(mac));
    sodium_memzero(server_pub, sizeof(server_pub));
    sodium_memzero(exp_yx, sizeof(exp_yx));
    sodium_memzero(exp_bx, sizeof(exp_bx));
    sodium_memzero(secret_input, sizeof(secret_input));
    sodium_memzero(verify, sizeof(verify));
    sodium_memzero(auth, sizeof(auth));
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(okm, sizeof(okm));
    sodium_memzero(&hst, sizeof(hst));
    if (st != OBFS4_OK) {
        sodium_memzero(keys, sizeof(*keys));
    }
    return st;
}

void obfs4_client_wipe(Obfs4ClientHandshake *hs)
{
    if (hs != NULL) {
        sodium_memzero(hs, sizeof(*hs));
    }
}

void obfs4_session_keys_wipe(Obfs4SessionKeys *keys)
{
    if (keys != NULL) {
        sodium_memzero(keys, sizeof(*keys));
    }
}
