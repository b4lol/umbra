# fuzz — libFuzzer harnesses for the handshake parser (roadmap step 6)

**Dev tooling only. Not built by `make all`, `test`, `vectors`,
`relay-test` or `interop-test` — those stay on `$(CC)` (GCC-compatible)
exactly as before.** `clang` is a fuzzing-only dependency
(`-fsanitize=fuzzer` is clang/LLVM-only; GCC 16 supports neither
`trace-pc-guard` nor libFuzzer's runtime).

## Targets

- **`fuzz_obfs4_cert`** → `obfs4_cert_parse` (`src/obfs4.c`): the
  bridge-line `cert=` argument parser (base64 decode + length
  validation). No MAC or other cryptographic gate sits in front of any
  branch here, so mutation gets full, unrestricted coverage.

- **`fuzz_obfs4_handshake`** → `obfs4_client_finish` (`src/obfs4.c`):
  the handshake RESPONSE parser — the highest-value target, since every
  byte it consumes comes straight off the wire from whatever answers
  the bridge connection, before any cryptographic validation succeeds.
  `LLVMFuzzerInitialize` builds one fixed, fully deterministic client
  handshake state from `fixtures.h` (same construction style
  `tests/vectors.c` already uses: `obfs4_keypair_from_seed` over a
  fixed seed, a fixed cert, a fixed epoch string set via
  `obfs4_client_request_with` — `obfs4_client_finish` checks the
  response's MAC against the SENT epoch, never wall-clock time, so this
  is reproducible run to run). Each input restores a fresh copy of that
  state and calls `obfs4_client_finish` on the fuzzer's bytes, capped
  at `OBFS4_MAX_HANDSHAKE_LEN`. Every return value (`OK`/`AGAIN`/`ERR`)
  is an acceptable outcome — only a crash, an ASan finding or a UBSan
  finding counts as a bug.

  **Honest scope note:** mutation alone cannot forge a valid
  `MAC_S`/`AUTH` — those are full HMAC-SHA256 outputs over
  attacker-influenced content, not fixed constants a coverage-guided
  mutator can converge on. So random/mutated input almost never reaches
  the post-authentication code (key derivation, direction-key split);
  that logic is exhaustively covered instead by `make vectors` (static,
  byte-exact against the Go reference), `make relay-test` (against our
  own mock bridge) and `make interop-test` (a live round trip against
  the actual upstream lyrebird server). What this harness actually
  exercises, thoroughly, is the fully untrusted, pre-authentication
  surface every response must pass through regardless of validity: the
  variable-length tail mark/MAC scan across the whole
  `[OBFS4_SERVER_MIN_HANDSHAKE_LEN, OBFS4_MAX_HANDSHAKE_LEN]` range, the
  offset arithmetic around it, and `OBFS4_AGAIN`/`OBFS4_ERR`
  classification — exactly the surface a hostile or malfunctioning
  bridge fully controls. A committed valid-response seed (see below)
  exists only to bias the mutator toward structurally plausible
  lengths/field boundaries, not to reach past the MAC.

## Corpus

`corpus/obfs4_cert/`: `empty`, `garbage` (not valid base64), and
`plausible_len` (right ballpark length, wrong content).

`corpus/obfs4_handshake/`: `empty`, `short_zero` (below the minimum
handshake length), and `valid_response` — a genuinely valid response
for the exact deterministic client state `fuzz_obfs4_handshake.c`
builds, generated once by `gen_valid_seed.c` (a standalone, one-shot
program reusing the same `server_ntor` + HMAC-tail construction
`tests/mockbridge.c` already implements — not new protocol logic).

libFuzzer grows these directories in place with hash-named files it
discovers during a run; those are gitignored (`.gitignore`) and not
meant to be committed — only the named seeds above are tracked.

### Regenerating `valid_response`

Only needed if `fixtures.h` changes:

```sh
cc -std=c11 -O2 $(pkg-config --cflags libsodium) \
   fuzz/gen_valid_seed.c src/obfs4.c src/obfs4_frame.c src/obfs4_packet.c \
   src/siphash24.c src/gorand.c src/probdist.c build/monocypher.o \
   -o /tmp/gen_valid_seed $(pkg-config --libs libsodium)
/tmp/gen_valid_seed > fuzz/corpus/obfs4_handshake/valid_response
```

## Running

```sh
make fuzz-build          # compile both targets with clang
make fuzz-smoke          # bounded run (FUZZ_SMOKE_SECONDS, default 30s each) — CI-suitable
make fuzz                # unbounded — manual/nightly deep runs
```

`LSAN_OPTIONS=detect_leaks=0` is set for both (same reason as `make
test`/`vectors`/`relay-test`: LeakSanitizer needs `ptrace_scope=0` on
hardened kernels; ASan/UBSan still run either way).

Verified locally: `fuzz_obfs4_cert` ran ~11.4M executions in 30s
(cov 17/ft 19) and `fuzz_obfs4_handshake` ran ~6.9M executions in 46s
(cov 639/ft 659), both with zero crashes and zero ASan/UBSan findings.
