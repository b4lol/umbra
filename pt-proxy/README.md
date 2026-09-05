# umbra-pt-proxy — Standalone Pluggable Transport Proxy

> **Status: FUNCTIONAL (iat-mode 0/1/2).** SOCKS5 front-end, obfs4
> ntor/Elligator handshake, framing, packet and traffic-shaping layers
> are implemented and verified byte-exact against the Go reference
> (lyrebird); the end-to-end relay is integration-tested against a
> reference-faithful mock bridge in all three iat modes
> (`make relay-test`, also under ASan/UBSan). NOT yet done: live interop
> against a real bridge and the fuzz harness (step 6).

A standalone, OS-managed pluggable-transport client proxy for Umbra's
censorship-circumvention path (TODO B.1, **ADR-030**). It runs as a
separate process and exposes a **loopback-only SOCKS5 endpoint**; Umbra
(`umbra serve` / `send --onion` / `tui` with `--pt-socks`) connects to
that endpoint through arti's unmanaged-transport support. Umbra never
spawns, links, or loads this binary.

## Why C here? (the ADR-030 scoped exception)

Umbra's language policy (ADR-011) bans C/C++ from the project. ADR-030
records a scoped, owner-granted exception for THIS component only,
because no maintained pure-Rust PT client library exists (the Rust
`obfs4` crate is unaudited 0.1.x; reference PT implementations are Go,
also banned in-process). The exception buys nothing for free — it moves
the risk into a component that is:

1. **Process-isolated**: a memory fault here can never corrupt an Umbra
   process; the only shared surface is a loopback SOCKS5 socket.
2. **Loopback-bound**: the listener refuses to bind anything but
   `127.0.0.1`/`::1`, enforced in code before any socket call.
3. **Separately gated**: builds with `-Wall -Wextra -Werror` plus the
   full hardening flag set, and MUST pass ASan/UBSan test runs before
   any "functional" claim is made (see Roadmap).

## Build

Dependencies: a C11 compiler, `make`, and the system **libsodium**
development package (`libsodium-devel` / `libsodium-dev`; X25519,
HMAC-SHA256, HKDF-SHA256, CSPRNG). **Monocypher 4.0.3** (Elligator 2
only) is vendored under `vendor/monocypher/` — tarball SHA-256
`8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`,
upstream SHA-512 verified at import time. Vendored files are built
with a relaxed warning set (documented in the Makefile); the hardening
mitigations still apply.

```sh
make            # hardened release build into build/umbra-pt-proxy
make sanitize   # ASan+UBSan builds (proxy + all test binaries)
make test       # SOCKS5 integration tests
make vectors    # obfs4 handshake/framing vector tests (normal + ASan)
make relay-test # end-to-end tunnel tests via the test-only mock bridge
make clean
```

Runtime: `umbra-pt-proxy --socks 127.0.0.1:PORT --obfs4-cert CERT
--iat-mode 0|1|2` where CERT and the iat-mode are taken from the bridge
line. A missing/malformed cert or a missing/invalid iat-mode fails the
process at startup, before any accept (fail-closed).

## Roadmap (each step gated on the previous one)

1. [x] Skeleton: loopback-only SOCKS5 listener, hardening flags,
       hygiene rules (explicit_bzero on teardown paths).
2. [x] SOCKS5 CONNECT handshake (RFC 1928, no-auth only, loopback
       peers) with exact reply codes, bounded parsing, I/O deadlines,
       and a deadline-guarded non-blocking upstream dial — integration
       tested (`make test`, also under ASan/UBSan). (The data relay was
       kept disabled here until step 4 enabled it.)
3. [x] obfs4 handshake: X25519 + Elligator 2 representative, ntor
       variant — implemented per the Go reference (lyrebird), which is
       the deployed wire definition, and verified BYTE-EXACT against
       fixtures dumped from it (`make vectors`, also under ASan/UBSan;
       see `tests/govectors/`). Constant-time properties come from
       libsodium + Monocypher (audited upstreams); the glue code here
       performs no secret-dependent branching beyond the reference
       implementation's own mark scan.
4. [x] obfs4 framing + packet layer + relay: XSalsa20-Poly1305 frames
       (libsodium secretbox) with SipHash-2-4-DRBG-obfuscated lengths
       (in-house streaming SipHash, cross-checked against libsodium's
       one-shot SipHash AND the Go DRBG block sequence), nonce
       prefix|counter-BE from 1, the Bider length-countermeasure, the
       packet layer (payload/PRNG-seed/unknown-types), and the
       poll-driven bidirectional relay wired into the SOCKS5 path.
       Verified byte-exact against Go framing vectors AND end-to-end
       against `tests/mockbridge.c` (a reference-faithful test-only
       server) with 1 KB / 5 KB / 100 KB echo round-trips and a
       fail-closed mid-handshake cut (`make relay-test`, normal +
       ASan/UBSan builds).
5. [x] iat-mode traffic shaping (0/1/2): Go `math/rand.Rand` helper
       semantics replicated over the obfs4 SipHash-2-4-OFB DRBG
       (`src/gorand.c`), the uniform weighted-distribution tables via
       Vose's alias method (`src/probdist.c`) — both pinned BIT-EXACT
       against `common/probdist` fixtures dumped from lyrebird
       (`make vectors`); per-connection distributions reset from the
       bridge's PRNG-seed packet (iat seed = SHA-256(len seed), Go
       parity); scheduled (never slept) inter-chunk delays with a
       bounded backpressure queue; paranoid mode chops/pads per sample
       with Go padBurst semantics. Verified end-to-end in all three
       modes (`make relay-test`, normal + ASan/UBSan). Honest notes:
       the distribution TABLES are byte-exact, individual SAMPLES are
       CSPRNG-drawn (Go's csrand does the same), and delays quantize UP
       to whole milliseconds (poll granularity, shape-preserving).
6. [ ] Interop tests against the reference (Go) lyrebird, ASan/UBSan
       clean, fuzz harness for the handshake parser.

## Non-goals

- No Snowflake (no viable C/Rust client stack; documented in ADR-030).
- No server/bridge side — client proxy only.
- Never linked into or spawned by an Umbra binary; distribution and
  lifecycle are the operator's responsibility.
