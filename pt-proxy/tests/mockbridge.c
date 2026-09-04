/*
 * umbra-pt-proxy — TEST-ONLY mock obfs4 bridge (server side).
 *
 * This binary exists so tests/relay.sh can exercise the full tunnel
 * (SOCKS5 -> obfs4 handshake -> framing -> packet layer -> echo) without
 * a real bridge. It is NEVER installed and never part of the shipped
 * proxy; it implements just enough of the lyrebird server side:
 *
 *   - parses the client request (tail mark scan, MAC_C verified for
 *     epoch-1h/now/+1h),
 *   - answers Y' | AUTH | P_S(0) | M_S | MAC_S,
 *   - sends one 24-byte PRNG seed packet (unpadded, Go parity),
 *   - echoes every payload packet back.
 *
 * It generates a fresh server identity at startup and prints
 * "CERT <base64>" on stdout for the test harness.
 */

#include "../src/obfs4.h"
#include "../src/obfs4_frame.h"
#include "../src/obfs4_packet.h"

#include <sodium.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_HANDSHAKE 8192u
#define EPOCH_BUF 24u

static const uint8_t T_MAC[] = "ntor-curve25519-sha256-1:mac";
static const uint8_t T_KEY[] = "ntor-curve25519-sha256-1:key_extract";
static const uint8_t T_VERIFY[] = "ntor-curve25519-sha256-1:key_verify";
static const uint8_t M_EXPAND[] = "ntor-curve25519-sha256-1:key_expand";
static const uint8_t PROTOID[] = "ntor-curve25519-sha256-1";

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

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n <= 0) {
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

/* Server-side ntor: secret_input = EXP(X,y)|EXP(X,b)|B|B|X|Y|P|NODEID. */
static int server_ntor(const Obfs4Keypair *session,
                       const uint8_t id_priv[OBFS4_PRIVATE_LEN],
                       const Obfs4BridgeCert *cert,
                       const uint8_t client_pub[OBFS4_PUBLIC_LEN],
                       uint8_t key_seed[OBFS4_KEY_SEED_LEN],
                       uint8_t auth[OBFS4_AUTH_LEN])
{
    uint8_t exp_xy[OBFS4_PUBLIC_LEN];
    uint8_t exp_xb[OBFS4_PUBLIC_LEN];
    uint8_t secret_input[2u * 32u + 2u * 32u + 32u + 32u + 24u + 20u];
    uint8_t verify[32];
    crypto_auth_hmacsha256_state st;
    uint8_t *p = secret_input;
    int rc = -1;

    if (crypto_scalarmult(exp_xy, session->priv, client_pub) != 0 ||
        crypto_scalarmult(exp_xb, id_priv, client_pub) != 0) {
        goto out; /* all-zero contributory output */
    }

    memcpy(p, exp_xy, 32u); p += 32u;
    memcpy(p, exp_xb, 32u); p += 32u;
    memcpy(p, cert->server_public, 32u); p += 32u;
    memcpy(p, cert->server_public, 32u); p += 32u;
    memcpy(p, client_pub, 32u); p += 32u;
    memcpy(p, session->pub, 32u); p += 32u;
    memcpy(p, PROTOID, 24u); p += 24u;
    memcpy(p, cert->node_id, 20u);

    crypto_auth_hmacsha256_init(&st, T_KEY, sizeof(T_KEY) - 1u);
    crypto_auth_hmacsha256_update(&st, secret_input, sizeof(secret_input));
    crypto_auth_hmacsha256_final(&st, key_seed);

    crypto_auth_hmacsha256_init(&st, T_VERIFY, sizeof(T_VERIFY) - 1u);
    crypto_auth_hmacsha256_update(&st, secret_input, sizeof(secret_input));
    crypto_auth_hmacsha256_final(&st, verify);

    crypto_auth_hmacsha256_init(&st, T_MAC, sizeof(T_MAC) - 1u);
    crypto_auth_hmacsha256_update(&st, verify, sizeof(verify));
    crypto_auth_hmacsha256_update(&st, secret_input + 64u,
                                  sizeof(secret_input) - 64u);
    crypto_auth_hmacsha256_update(&st, (const uint8_t *)"Server", 6u);
    crypto_auth_hmacsha256_final(&st, auth);
    rc = 0;

out:
    sodium_memzero(exp_xy, sizeof(exp_xy));
    sodium_memzero(exp_xb, sizeof(exp_xb));
    sodium_memzero(secret_input, sizeof(secret_input));
    sodium_memzero(verify, sizeof(verify));
    sodium_memzero(&st, sizeof(st));
    return rc;
}

/* Splits a raw 144-byte okm into the two direction key structs. */
static void split_okm(const uint8_t okm[OBFS4_OKM_LEN], Obfs4DirKeys *a,
                      Obfs4DirKeys *b)
{
    Obfs4DirKeys *both[2];
    int side;

    both[0] = a;
    both[1] = b;
    for (side = 0; side < 2; side++) {
        size_t base = (size_t)side * OBFS4_DIR_KEY_LEN;

        memcpy(both[side]->secretbox_key, okm + base,
               OBFS4_SECRETBOX_KEY_LEN);
        memcpy(both[side]->nonce_prefix,
               okm + base + OBFS4_SECRETBOX_KEY_LEN, OBFS4_NONCE_PREFIX_LEN);
        memcpy(both[side]->siphash_key,
               okm + base + OBFS4_SECRETBOX_KEY_LEN + OBFS4_NONCE_PREFIX_LEN,
               OBFS4_SIPHASH_KEY_LEN);
        memcpy(both[side]->siphash_iv,
               okm + base + OBFS4_SECRETBOX_KEY_LEN +
                   OBFS4_NONCE_PREFIX_LEN + OBFS4_SIPHASH_KEY_LEN,
               OBFS4_SIPHASH_IV_LEN);
    }
}

/* One connection: handshake, then echo payloads until EOF/error. */
static void handle_conn(int fd, const Obfs4BridgeCert *cert,
                        const uint8_t id_priv[OBFS4_PRIVATE_LEN])
{
    uint8_t mac_key[OBFS4_CERT_LEN];
    uint8_t buf[MAX_HANDSHAKE];
    size_t buf_len = 0;
    uint8_t mark[16];
    uint8_t epoch[EPOCH_BUF];
    Obfs4Keypair session;
    Obfs4SessionKeys keys;
    Obfs4FrameEncoder enc;
    Obfs4FrameDecoder dec;
    Obfs4DirKeys server_send;
    Obfs4DirKeys server_recv;
    uint8_t key_seed[OBFS4_KEY_SEED_LEN];
    uint8_t auth[OBFS4_AUTH_LEN];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    uint8_t okm[OBFS4_OKM_LEN];
    int ok = 0;
    size_t epoch_len = 0;

    memcpy(mac_key, cert->server_public, OBFS4_PUBLIC_LEN);
    memcpy(mac_key + OBFS4_PUBLIC_LEN, cert->node_id, OBFS4_NODE_ID_LEN);

    /* Read the client request; the mark/MAC sit at the tail. */
    for (;;) {
        ssize_t n;
        int matched = 0;
        int off;

        if (buf_len >= sizeof(buf)) {
            goto out;
        }
        n = read(fd, buf + buf_len, sizeof(buf) - buf_len);
        if (n <= 0) {
            goto out;
        }
        buf_len += (size_t)n;
        fprintf(stderr, "mock: read %zu bytes\n", buf_len);
        if (buf_len < OBFS4_CLIENT_MIN_HANDSHAKE_LEN) {
            continue;
        }

        /* Tail check: mark at [len-32, len-16), MAC at [len-16, len). */
        hmac128(mac_key, buf, OBFS4_REPRESENTATIVE_LEN, NULL, 0u, mark);
        if (sodium_memcmp(buf + buf_len - 32u, mark, 16u) != 0) {
            fprintf(stderr, "mock: tail mark mismatch at %zu\n", buf_len);
            continue; /* more padding may still be in flight */
        }
        for (off = -1; off <= 1 && !matched; off++) {
            char cand[EPOCH_BUF];
            uint8_t want[16];
            int cn;

            cn = snprintf(cand, sizeof(cand), "%lld",
                          (long long)(time(NULL) / 3600) + (long long)off);
            if (cn <= 0 || (size_t)cn >= sizeof(cand)) {
                continue;
            }
            hmac128(mac_key, buf, buf_len - 16u, (const uint8_t *)cand,
                    (size_t)cn, want);
            if (sodium_memcmp(want, buf + buf_len - 16u, 16u) == 0) {
                memcpy(epoch, cand, (size_t)cn + 1u);
                epoch_len = (size_t)cn;
                matched = 1;
            }
        }
        if (!matched) { fprintf(stderr, "mock: MAC_C mismatch\n");
            goto out;
        }
        break;
    }

    /* Session keypair with an Elligator representative. */
    {
        uint8_t entropy[OBFS4_PRIVATE_LEN];
        unsigned int attempt;
        int made = 0;

        for (attempt = 0u; attempt < 64u && !made; attempt++) {
            randombytes_buf(entropy, sizeof(entropy));
            made = obfs4_keypair_from_seed(&session, entropy,
                                           (uint8_t)attempt) == OBFS4_OK;
            sodium_memzero(entropy, sizeof(entropy));
        }
        if (!made) {
            goto out;
        }
    }

    /* ntor + response. */
    {
        uint8_t client_pub[OBFS4_PUBLIC_LEN];
        uint8_t resp[OBFS4_REPRESENTATIVE_LEN + OBFS4_AUTH_LEN + 16u +
                     16u];
        uint8_t resp_mark[16];
        uint8_t resp_mac[16];
        size_t resp_len = OBFS4_REPRESENTATIVE_LEN + OBFS4_AUTH_LEN;

        obfs4_representative_to_public(client_pub, buf);
        if (server_ntor(&session, id_priv, cert, client_pub, key_seed,
                        auth) != 0) {
            sodium_memzero(client_pub, sizeof(client_pub));
            goto out;
        }
        sodium_memzero(client_pub, sizeof(client_pub));

        memcpy(resp, session.repr, OBFS4_REPRESENTATIVE_LEN);
        memcpy(resp + OBFS4_REPRESENTATIVE_LEN, auth, OBFS4_AUTH_LEN);
        hmac128(mac_key, session.repr, OBFS4_REPRESENTATIVE_LEN, NULL, 0u,
                resp_mark);
        memcpy(resp + resp_len, resp_mark, 16u);
        resp_len += 16u;
        hmac128(mac_key, resp, resp_len, epoch, epoch_len, resp_mac);
        memcpy(resp + resp_len, resp_mac, 16u);
        resp_len += 16u;
        if (write_full(fd, resp, resp_len) != 0) {
            sodium_memzero(resp, sizeof(resp));
            goto out;
        }
        sodium_memzero(resp, sizeof(resp));
    }

    /* Key schedule: server sends with okm[72:144], reads okm[0:72]. */
    crypto_kdf_hkdf_sha256_extract(prk, T_KEY, sizeof(T_KEY) - 1u,
                                   key_seed, OBFS4_KEY_SEED_LEN);
    if (crypto_kdf_hkdf_sha256_expand(okm, sizeof(okm),
                                      (const char *)M_EXPAND,
                                      sizeof(M_EXPAND) - 1u, prk) != 0) {
        goto out;
    }
    split_okm(okm, &server_recv, &server_send);
    /* Copy the client-facing halves into the session keys layout so the
     * shared framing initializers can be reused. */
    obfs4_frame_decoder_init(&dec, &server_recv);
    obfs4_frame_encoder_init(&enc, &server_send);
    (void)keys;

    /* First packet: the 24-byte PRNG seed, unpadded (Go parity). */
    {
        uint8_t seed[OBFS4_SEED_PAYLOAD_LEN];
        uint8_t frame[OBFS4_MAX_SEGMENT_LEN];
        size_t frame_len = 0;

        randombytes_buf(seed, sizeof(seed));
        if (obfs4_packet_encode(&enc, OBFS4_PACKET_TYPE_PRNG_SEED, seed,
                                sizeof(seed), 0u, frame, sizeof(frame),
                                &frame_len) != OBFS4_OK ||
            write_full(fd, frame, frame_len) != 0) {
            sodium_memzero(seed, sizeof(seed));
            goto out;
        }
        sodium_memzero(seed, sizeof(seed));
    }

    /* Echo loop. */
    {
        uint8_t acc[16u * OBFS4_MAX_SEGMENT_LEN];
        size_t acc_len = 0;
        uint8_t decoded[OBFS4_MAX_FRAME_PAYLOAD];

        for (;;) {
            ssize_t n;
            Obfs4Status st;
            Obfs4PacketKind kind;
            const uint8_t *payload = NULL;
            size_t payload_len = 0;
            size_t dlen = 0;

            if (acc_len >= sizeof(acc)) {
                break;
            }
            n = read(fd, acc + acc_len, sizeof(acc) - acc_len);
            if (n <= 0) {
                break;
            }
            acc_len += (size_t)n;
            for (;;) {
                st = obfs4_frame_decode(&dec, acc, &acc_len, decoded,
                                        &dlen);
                if (st == OBFS4_AGAIN) {
                    break;
                }
                if (st != OBFS4_OK ||
                    obfs4_packet_parse(decoded, dlen, &kind, &payload,
                                       &payload_len) != OBFS4_OK) {
                    goto echo_out;
                }
                if (kind == OBFS4_PKT_PAYLOAD && payload_len > 0u) {
                    uint8_t frame[OBFS4_MAX_SEGMENT_LEN];
                    size_t frame_len = 0;

                    if (obfs4_packet_encode(&enc, OBFS4_PACKET_TYPE_PAYLOAD,
                                            payload, payload_len, 0u, frame,
                                            sizeof(frame),
                                            &frame_len) != OBFS4_OK ||
                        write_full(fd, frame, frame_len) != 0) {
                        goto echo_out;
                    }
                }
            }
        }
    echo_out:
        sodium_memzero(acc, sizeof(acc));
        sodium_memzero(decoded, sizeof(decoded));
    }

    ok = 1;

out:
    if (ok == 0) {
        fprintf(stderr, "mockbridge: connection failed\n");
    }
    sodium_memzero(mac_key, sizeof(mac_key));
    sodium_memzero(buf, sizeof(buf));
    sodium_memzero(epoch, sizeof(epoch));
    sodium_memzero(&session, sizeof(session));
    sodium_memzero(key_seed, sizeof(key_seed));
    sodium_memzero(auth, sizeof(auth));
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(okm, sizeof(okm));
    sodium_memzero(&server_send, sizeof(server_send));
    sodium_memzero(&server_recv, sizeof(server_recv));
    obfs4_frame_encoder_wipe(&enc);
    obfs4_frame_decoder_wipe(&dec);
    (void)epoch_len;
}

int main(int argc, char **argv)
{
    uint8_t id_priv[OBFS4_PRIVATE_LEN];
    Obfs4BridgeCert cert;
    uint8_t cert_raw[OBFS4_CERT_LEN];
    char cert_b64[128];
    int listener;
    struct sockaddr_in addr;
    int one = 1;
    long port;

    if (argc != 2) {
        fprintf(stderr, "usage: %s PORT\n", argv[0]);
        return 2;
    }
    port = strtol(argv[1], NULL, 10);
    if (port <= 0 || port > 65535) {
        return 2;
    }
    if (sodium_init() < 0) {
        return 1;
    }

    /* Fresh server identity per run; the cert line goes to stdout. */
    randombytes_buf(id_priv, sizeof(id_priv));
    if (crypto_scalarmult_base(cert.server_public, id_priv) != 0) {
        return 1;
    }
    randombytes_buf(cert.node_id, sizeof(cert.node_id));
    memcpy(cert_raw, cert.node_id, OBFS4_NODE_ID_LEN);
    memcpy(cert_raw + OBFS4_NODE_ID_LEN, cert.server_public,
           OBFS4_PUBLIC_LEN);
    sodium_bin2base64(cert_b64, sizeof(cert_b64), cert_raw,
                      sizeof(cert_raw),
                      sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    printf("CERT %s\n", cert_b64);
    fflush(stdout);
    sodium_memzero(cert_raw, sizeof(cert_raw));

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return 1;
    }
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one,
                     (socklen_t)sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 4) != 0) {
        return 1;
    }

    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) {
            continue;
        }
        handle_conn(fd, &cert, id_priv);
        close(fd);
    }
}
