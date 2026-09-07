/*
 * libFuzzer harness for obfs4_cert_parse — the bridge-line `cert=`
 * argument parser (base64 decode + length validation). Untrusted in
 * the sense that a corrupted/hand-edited bridge line, or a bridge
 * descriptor scraped from an untrusted source, feeds this function
 * directly, before any network I/O.
 *
 * Unlike the handshake response parser (fuzz_obfs4_handshake.c), there
 * is no MAC gating a single byte of this input: every branch is
 * reachable by mutation alone, so this target gets full, unrestricted
 * coverage of obfs4_cert_parse from a random/mutated corpus.
 *
 * See README.md for build/run instructions and corpus provenance.
 */

#include "../src/obfs4.h"

#include <sodium.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* obfs4_cert_parse takes a NUL-terminated C string; a real bridge line
 * argument is never anywhere close to this long, so bound the copy
 * generously rather than reject-and-return on oversized input (which
 * would just skip exercising the parser on truncated/binary-garbage
 * strings — exactly the kind of input worth fuzzing). */
#define FUZZ_CERT_MAX_LEN 512u

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    if (sodium_init() < 0) {
        abort();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char buf[FUZZ_CERT_MAX_LEN + 1u];
    Obfs4BridgeCert cert;
    size_t len = size < FUZZ_CERT_MAX_LEN ? size : FUZZ_CERT_MAX_LEN;

    memcpy(buf, data, len);
    buf[len] = '\0';

    /* Fuzzer-supplied bytes may legitimately contain embedded NULs;
     * obfs4_cert_parse takes a C string, so only the prefix up to the
     * first NUL is what it actually sees — matching real call sites
     * (CLI argv, a bridge-line config value). */
    (void)obfs4_cert_parse(&cert, buf);
    sodium_memzero(&cert, sizeof(cert));
    return 0;
}
