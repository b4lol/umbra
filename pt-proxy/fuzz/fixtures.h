/*
 * umbra-pt-proxy fuzz fixtures — fixed, public (non-secret) constants
 * shared between fuzz_obfs4_handshake.c and gen_valid_seed.c so the
 * two stay trivially in sync: the harness builds its deterministic
 * client handshake state from these, and the (offline, one-shot)
 * generator uses the SAME server identity key to produce a genuinely
 * valid response for that exact client state, checked into
 * corpus/obfs4_handshake/ as a seed.
 *
 * None of this is a real bridge identity — it exists only so the fuzz
 * harness's handshake state is reproducible across runs.
 */

#ifndef UMBRA_PT_FUZZ_FIXTURES_H
#define UMBRA_PT_FUZZ_FIXTURES_H

#include <stdint.h>

/* Fixed "bridge" identity private key; obfs4_cert_parse never sees
 * this — only its derived public key (computed at init time via
 * crypto_scalarmult_base, both here and in the harness) goes into the
 * Obfs4BridgeCert. */
static const uint8_t FUZZ_SERVER_ID_PRIV[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x20,
};

static const uint8_t FUZZ_NODE_ID[20] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
    0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
};

/* Fixed client ephemeral seed; obfs4_keypair_from_seed is tried with
 * increasing tweak bytes (like the real keygen retry loop) until one
 * yields a representative — deterministic, no CSPRNG involved. */
static const uint8_t FUZZ_CLIENT_PRIV[32] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
    0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
    0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
    0xde, 0xdf,
};

/* Fixed server ephemeral seed for the offline generator only — the
 * fuzz harness never needs this, it only consumes the resulting
 * response bytes as a corpus seed. */
static const uint8_t FUZZ_SERVER_EPHEMERAL_PRIV[32] = {
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
    0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3,
    0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
    0xfe, 0x21,
};

/* Minimal legal padding length (OBFS4_CLIENT_MIN_PAD_LEN) and a fixed
 * epoch string — obfs4_client_finish checks the response's MAC_S
 * against the SENT epoch (see obfs4.h), never wall-clock time, so a
 * fixed string keeps the harness fully deterministic. */
#define FUZZ_PAD_LEN 77u
#define FUZZ_EPOCH "1000000"

#endif /* UMBRA_PT_FUZZ_FIXTURES_H */
