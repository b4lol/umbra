/*
 * umbra-pt-proxy — obfs4 client handshake (ntor variant + Elligator 2).
 *
 * Wire-format reference: the Go implementation (lyrebird, formerly
 * obfs4proxy), which is the deployed definition of the protocol:
 *   - transports/obfs4/handshake_ntor.go  (mark/MAC framing, padding)
 *   - common/ntor/ntor.go                 (ntor KDF labels, byte order)
 *   - common/drbg/hash_drbg.go            (SipHash-2-4 OFB length DRBG)
 *   - internal/x25519ell2                 (Elligator 2, derived from
 *     Monocypher — which is why our vendored Monocypher matches it
 *     byte-for-byte)
 *
 * Byte layouts (client side):
 *   request : X' | P_C | M_C | MAC_C
 *     X'    = 32-byte Elligator 2 representative of the ephemeral key
 *     P_C   = random padding, [77, 8128] bytes
 *     M_C   = HMAC-SHA256-128(B | NODEID, X')
 *     MAC_C = HMAC-SHA256-128(B | NODEID, X' | P_C | M_C | E)
 *     E     = ASCII decimal hours since the UNIX epoch
 *   response: Y' | AUTH | P_S | M_S | MAC_S  (M_S found by substring
 *     scan from offset 64; MAC_S verified with the SENT epoch string)
 *
 * ntor (per the Go labels, NOT proposal 216 verbatim):
 *   secret_input = EXP(Y,x) | EXP(B,x) | B | B | X | Y | PROTOID | NODEID
 *   KEY_SEED     = HMAC-SHA256(t_key,    secret_input)
 *   verify       = HMAC-SHA256(t_verify, secret_input)
 *   AUTH         = HMAC-SHA256(t_mac,    verify | B | B | X | Y |
 *                                PROTOID | NODEID | "Server")
 *   okm          = HKDF-SHA256(KEY_SEED, salt=t_key, info=m_expand, 144)
 *                  -> send direction okm[0:72], receive okm[72:144]
 *   direction block: 32 secretbox key | 16 nonce prefix |
 *                    16 SipHash-2-4 key | 8 SipHash OFB IV
 *
 * Security invariants:
 *  1. No dynamic allocation; every buffer is bounded by
 *     OBFS4_MAX_HANDSHAKE_LEN.
 *  2. Secrets (private keys, KEY_SEED, session keys) are wiped with
 *     sodium_memzero on every exit path, including errors.
 *  3. All comparisons of received MAC/AUTH values are constant-time
 *     (sodium_memcmp).
 *  4. Contributory behaviour: a failed X25519 (all-zero output) aborts
 *     the handshake (libsodium returns -1).
 *  5. The Elligator retry loop is BOUNDED (64 attempts); failure is a
 *     hard error, never an infinite loop.
 */

#ifndef UMBRA_PT_OBFS4_H
#define UMBRA_PT_OBFS4_H

#include <stddef.h>
#include <stdint.h>

#define OBFS4_PUBLIC_LEN 32
#define OBFS4_PRIVATE_LEN 32
#define OBFS4_REPRESENTATIVE_LEN 32
#define OBFS4_NODE_ID_LEN 20
#define OBFS4_CERT_LEN (OBFS4_NODE_ID_LEN + OBFS4_PUBLIC_LEN)
#define OBFS4_CERT_B64_LEN 70 /* unpadded base64 of the 52-byte cert */

#define OBFS4_MARK_LEN 16
#define OBFS4_MAC_LEN 16
#define OBFS4_AUTH_LEN 32
#define OBFS4_KEY_SEED_LEN 32

#define OBFS4_MAX_HANDSHAKE_LEN 8192
#define OBFS4_CLIENT_MIN_PAD_LEN 77
#define OBFS4_CLIENT_MAX_PAD_LEN 8128
#define OBFS4_CLIENT_MIN_HANDSHAKE_LEN \
    (OBFS4_REPRESENTATIVE_LEN + OBFS4_MARK_LEN + OBFS4_MAC_LEN)
#define OBFS4_SERVER_MIN_HANDSHAKE_LEN \
    (OBFS4_REPRESENTATIVE_LEN + OBFS4_AUTH_LEN + OBFS4_MARK_LEN + \
     OBFS4_MAC_LEN)

/* Per-direction key block carved out of the 144-byte HKDF output:
 * secretbox key | nonce prefix | SipHash-2-4 key | SipHash OFB IV. */
#define OBFS4_SECRETBOX_KEY_LEN 32
#define OBFS4_NONCE_PREFIX_LEN 16
#define OBFS4_SIPHASH_KEY_LEN 16
#define OBFS4_SIPHASH_IV_LEN 8
#define OBFS4_DIR_KEY_LEN                              \
    (OBFS4_SECRETBOX_KEY_LEN + OBFS4_NONCE_PREFIX_LEN + \
     OBFS4_SIPHASH_KEY_LEN + OBFS4_SIPHASH_IV_LEN)
#define OBFS4_OKM_LEN (2 * OBFS4_DIR_KEY_LEN)

typedef enum {
    OBFS4_OK = 0,
    OBFS4_AGAIN = 1, /* response incomplete; read more bytes */
    OBFS4_ERR = -1   /* fatal handshake failure; drop the connection */
} Obfs4Status;

/* Parsed `cert=` argument of an obfs4 bridge line: NODEID | B. */
typedef struct {
    uint8_t node_id[OBFS4_NODE_ID_LEN];
    uint8_t server_public[OBFS4_PUBLIC_LEN];
} Obfs4BridgeCert;

/* Ephemeral session keypair with its Elligator 2 representative. */
typedef struct {
    uint8_t priv[OBFS4_PRIVATE_LEN];
    uint8_t pub[OBFS4_PUBLIC_LEN];
    uint8_t repr[OBFS4_REPRESENTATIVE_LEN];
} Obfs4Keypair;

/* Per-direction link keys, ready for the framing layer (roadmap 4). */
typedef struct {
    uint8_t secretbox_key[OBFS4_SECRETBOX_KEY_LEN];
    uint8_t nonce_prefix[OBFS4_NONCE_PREFIX_LEN];
    uint8_t siphash_key[OBFS4_SIPHASH_KEY_LEN];
    uint8_t siphash_iv[OBFS4_SIPHASH_IV_LEN];
} Obfs4DirKeys;

typedef struct {
    uint8_t key_seed[OBFS4_KEY_SEED_LEN];
    Obfs4DirKeys send;
    Obfs4DirKeys recv;
} Obfs4SessionKeys;

/* Client handshake state. Holds the session secret until wiped. */
typedef struct {
    Obfs4Keypair keypair;
    Obfs4BridgeCert cert;
    char epoch[24]; /* ASCII decimal epoch hour, NUL-terminated */
} Obfs4ClientHandshake;

/* Parses a bridge-line `cert=` value (unpadded base64, 70 chars;
 * padded 72-char form is also accepted) into NODEID | B. */
int obfs4_cert_parse(Obfs4BridgeCert *out, const char *cert_b64);

/* Maps an Elligator 2 representative to its Curve25519 public key
 * (Monocypher crypto_elligator_map). Exposed for the vector tests. */
void obfs4_representative_to_public(uint8_t pub[OBFS4_PUBLIC_LEN],
                                    const uint8_t repr[OBFS4_REPRESENTATIVE_LEN]);

/* Deterministic keypair derivation for the vector tests: `priv` is the
 * raw 32-byte private key, `tweak` the Elligator tweak byte. Returns
 * OBFS4_ERR when no representative exists for this key (~50%). */
Obfs4Status obfs4_keypair_from_seed(Obfs4Keypair *kp,
                                    const uint8_t priv[OBFS4_PRIVATE_LEN],
                                    uint8_t tweak);

/* Initializes a client handshake: parses nothing, generates a fresh
 * Elligator keypair (bounded retry, Go keygen parity: SHA-512 of the
 * CSPRNG output, private = digest[0:32], tweak = digest[63]). */
Obfs4Status obfs4_client_init(Obfs4ClientHandshake *hs,
                              const Obfs4BridgeCert *cert);

/* Builds the client request X' | P_C | M_C | MAC_C with random padding
 * and the current epoch hour (recorded in the state for the MAC_S
 * check). `out` must hold OBFS4_CLIENT_MIN_HANDSHAKE_LEN +
 * OBFS4_CLIENT_MAX_PAD_LEN bytes. */
Obfs4Status obfs4_client_request(Obfs4ClientHandshake *hs, uint8_t *out,
                                 size_t out_cap, size_t *out_len);

/* Deterministic variant for the vector tests: caller supplies the
 * padding bytes and the epoch string. */
Obfs4Status obfs4_client_request_with(Obfs4ClientHandshake *hs,
                                      const uint8_t *pad, size_t pad_len,
                                      const char *epoch, uint8_t *out,
                                      size_t out_cap, size_t *out_len);

/* Consumes the server response. OBFS4_AGAIN: buffer holds a prefix of
 * a plausible response, keep reading. OBFS4_OK: handshake complete;
 * `keys` receives the session keys and `consumed` the number of
 * response bytes belonging to the handshake (trailing bytes are the
 * first frames). OBFS4_ERR: fatal, drop the connection. Wipes all
 * intermediate secrets before returning. */
Obfs4Status obfs4_client_finish(Obfs4ClientHandshake *hs,
                                const uint8_t *resp, size_t resp_len,
                                Obfs4SessionKeys *keys, size_t *consumed);

/* Wipes the handshake state (session secret included). */
void obfs4_client_wipe(Obfs4ClientHandshake *hs);

/* Wipes the derived session keys. */
void obfs4_session_keys_wipe(Obfs4SessionKeys *keys);

#endif /* UMBRA_PT_OBFS4_H */
